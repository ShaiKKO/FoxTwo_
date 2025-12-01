/*
 * IoRing Operation Interception & Policy Engine – Implementation
 *
 * Author: Colin MacRitchie | ziX Labs
 * Organization: ziX Labs — Security Research Division
 * File: ioring_intercept.c
 * Version: 1.1
 * Date: 2025-11-30
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and confidential.
 *   Redistribution or disclosure without prior written consent is prohibited.
 *
 * Summary
 * -------
 * Implements the kernel-mode policy engine for IoRing operation validation.
 * User-mode hooks call IOCTL_MONITOR_INTERCEPT_VALIDATE with serialized SQEs,
 * and this module validates against configured policy.
 *
 * SECURITY PROPERTIES:
 * - Input: All request buffers treated as hostile; ProbeForRead before access
 * - Output: Response contains only safe values; no kernel addresses disclosed
 * - Memory Safety: SEH guards all user buffer dereferences
 * - IRQL: PASSIVE_LEVEL for validation; DISPATCH_LEVEL for queries
 *
 * References:
 * - ziX-labs-c-style.md: 60-line function limit, SEH patterns, bounded accessors
 * - PLAN_phase6_ioring_interception.md: Architecture specification
 */

#include <ntifs.h>
#include <ntstrsafe.h>
#include "ioring_intercept.h"
#include "monitor_internal.h"
#include "regbuf_integrity.h"
#include "ioring_enum.h"
#include "telemetry_ringbuf.h"

#pragma warning(push)
#pragma warning(disable: 4201 4214)

/*--------------------------------------------------------------------------
 * Internal State
 *-------------------------------------------------------------------------*/

typedef struct _MON_INTERCEPT_STATE {
    /* Initialization flag */
    volatile LONG       Initialized;

    /* Policy (volatile for lock-free reads) */
    volatile LONG       PolicyVersion;
    MON_INTERCEPT_POLICY Policy;

    /* Synchronization for policy updates */
    KSPIN_LOCK          PolicyLock;

    /* Statistics */
    MON_INTERCEPT_STATS Stats;

    /* Process blacklist */
    MON_BLACKLIST_ENTRY Blacklist[MON_INTERCEPT_MAX_BLACKLIST];
    volatile LONG       BlacklistCount;
    KSPIN_LOCK          BlacklistLock;

} MON_INTERCEPT_STATE, *PMON_INTERCEPT_STATE;

static MON_INTERCEPT_STATE g_InterceptState = {0};

/*--------------------------------------------------------------------------
 * MITRE ATT&CK Technique Mapping
 *-------------------------------------------------------------------------*/

/**
 * @function   MonInterceptGetMitreTechnique
 * @purpose    Map violation reason to MITRE ATT&CK technique ID
 * @param[in]  Reason - Violation reason code
 * @returns    Static string with technique ID (empty if no mapping)
 */
static const CHAR*
MonInterceptGetMitreTechnique(
    _In_ MON_INTERCEPT_REASON Reason
)
{
    switch (Reason) {
        case MonReason_RegBuffersCorrupted:
        case MonReason_KernelAddressInBuffer:
            return "T1068";  /* Exploitation for Privilege Escalation */
        case MonReason_ExcessiveOperations:
        case MonReason_RateLimitExceeded:
            return "T1499";  /* Endpoint Denial of Service */
        case MonReason_SuspiciousOpCode:
            return "T1203";  /* Exploitation for Client Execution */
        case MonReason_ProcessBlacklisted:
            return "T1055";  /* Process Injection (often precursor) */
        default:
            return "";
    }
}

/*--------------------------------------------------------------------------
 * Internal Helper: Response Initialization
 *-------------------------------------------------------------------------*/

/**
 * @function   MonInterceptInitResponse
 * @purpose    Initialize response structure with safe defaults
 */
static VOID
MonInterceptInitResponse(
    _Out_ PMON_INTERCEPT_RESPONSE Response
)
{
    RtlZeroMemory(Response, sizeof(MON_INTERCEPT_RESPONSE));
    Response->Size = sizeof(MON_INTERCEPT_RESPONSE);
    Response->Action = MonIntercept_Allow;
    Response->Reason = MonReason_None;
    Response->ViolatingOpIndex = (ULONG)-1;
    Response->ViolationFlags = 0;
}

/*--------------------------------------------------------------------------
 * Internal Helper: Policy Snapshot
 *-------------------------------------------------------------------------*/

/**
 * @function   MonInterceptCapturePolicy
 * @purpose    Capture current policy for lock-free read
 */
static VOID
MonInterceptCapturePolicy(
    _Out_ PMON_INTERCEPT_POLICY Policy
)
{
    /* Lock-free snapshot - policy updates are atomic via spinlock */
    RtlCopyMemory(Policy, &g_InterceptState.Policy, sizeof(MON_INTERCEPT_POLICY));
}

/*--------------------------------------------------------------------------
 * Internal Helper: Blacklist Check (Lock-Free)
 *-------------------------------------------------------------------------*/

/**
 * @function   MonInterceptCheckBlacklist
 * @purpose    Check if process is blacklisted (lock-free linear scan)
 * @param[in]  ProcessId - PID to check
 * @returns    TRUE if blacklisted
 */
static BOOLEAN
MonInterceptCheckBlacklist(
    _In_ ULONG ProcessId
)
{
    for (ULONG i = 0; i < MON_INTERCEPT_MAX_BLACKLIST; i++) {
        /* Volatile read of ProcessId field */
        ULONG entryPid = *(volatile ULONG*)&g_InterceptState.Blacklist[i].ProcessId;
        if (entryPid == ProcessId) {
            return TRUE;
        }
    }
    return FALSE;
}

/*--------------------------------------------------------------------------
 * Internal Helper: Single SQE Validation
 *-------------------------------------------------------------------------*/

/**
 * @function   MonInterceptValidateSingleSqe
 * @purpose    Validate a single captured SQE against policy
 * @param[in]  Sqe - Locally captured SQE (already in kernel memory)
 * @param[in]  Policy - Policy snapshot
 * @returns    MonReason_None if valid, specific reason if violation
 */
static MON_INTERCEPT_REASON
MonInterceptValidateSingleSqe(
    _In_ const MON_SERIALIZED_SQE* Sqe,
    _In_ const MON_INTERCEPT_POLICY* Policy
)
{
    /* Check opcode against whitelist if configured */
    if (Policy->ValidateOpCodes && Policy->AllowedOpCodeMask != 0) {
        if (Sqe->OpCode > 31 ||
            !(Policy->AllowedOpCodeMask & (1UL << Sqe->OpCode))) {
            return MonReason_SuspiciousOpCode;
        }
    }

    /* Check for kernel addresses in buffer pointer */
    if (Policy->BlockKernelAddresses && Sqe->BufferAddress != 0) {
        /* Only check if not using pre-registered buffer index */
        if (!(Sqe->Flags & MON_SQE_FLAG_PREREGISTERED_BUFFER)) {
            if (MON_IS_KERNEL_ADDRESS((PVOID)Sqe->BufferAddress)) {
                return MonReason_KernelAddressInBuffer;
            }
        }
    }

    /* Check individual buffer size limit */
    if (Policy->MaxBufferSizeBytes != 0 &&
        Sqe->BufferSize > Policy->MaxBufferSizeBytes) {
        return MonReason_BufferSizeTooLarge;
    }

    return MonReason_None;
}

/*--------------------------------------------------------------------------
 * Internal Helper: Bounded SQE Array Accessor
 *-------------------------------------------------------------------------*/

/**
 * @function   MonInterceptCaptureSqe
 * @purpose    Safely capture single SQE from user buffer with bounds check
 * @precondition Caller has validated UserBuffer is probed for RequestSize
 * @param[in]  UserBuffer - Validated user request buffer
 * @param[in]  RequestSize - Total buffer size
 * @param[in]  Index - SQE index to capture (0-based)
 * @param[out] CapturedSqe - Output buffer for captured SQE
 * @returns    TRUE if captured successfully, FALSE if out of bounds
 *
 * SECURITY: This function is SEH-guarded by caller
 */
static BOOLEAN
MonInterceptCaptureSqe(
    _In_reads_bytes_(RequestSize) const VOID* UserBuffer,
    _In_ ULONG RequestSize,
    _In_ ULONG Index,
    _Out_ PMON_SERIALIZED_SQE CapturedSqe
)
{
    /* Calculate offset with overflow protection */
    ULONG sqeOffset;
    ULONG sqeArrayStart = MON_INTERCEPT_REQUEST_HEADER_SIZE;

    /* Check for multiplication overflow */
    if (Index > (MAXULONG / sizeof(MON_SERIALIZED_SQE))) {
        return FALSE;
    }
    sqeOffset = sqeArrayStart + (Index * sizeof(MON_SERIALIZED_SQE));

    /* Validate bounds */
    if (sqeOffset > RequestSize ||
        (RequestSize - sqeOffset) < sizeof(MON_SERIALIZED_SQE)) {
        return FALSE;
    }

    /* Safe copy - caller has SEH protection */
    RtlCopyMemory(CapturedSqe,
                  (const UCHAR*)UserBuffer + sqeOffset,
                  sizeof(MON_SERIALIZED_SQE));
    return TRUE;
}

/*--------------------------------------------------------------------------
 * Internal Helper: Request Header Validation
 *-------------------------------------------------------------------------*/

/**
 * @function   MonInterceptValidateRequestHeader
 * @purpose    Validate and capture request header from user buffer
 * @param[in]  UserBuffer - User-mode buffer (already probed)
 * @param[in]  UserBufferSize - Size provided by caller
 * @param[out] CapturedHeader - Output for captured header
 * @param[out] Response - Receives error details on failure
 * @returns    STATUS_SUCCESS if header valid, error status otherwise
 */
static NTSTATUS
MonInterceptValidateRequestHeader(
    _In_reads_bytes_(UserBufferSize) const VOID* UserBuffer,
    _In_ ULONG UserBufferSize,
    _Out_ PMON_INTERCEPT_REQUEST CapturedHeader,
    _Inout_ PMON_INTERCEPT_RESPONSE Response
)
{
    /* Size check for header */
    if (UserBufferSize < MON_INTERCEPT_REQUEST_HEADER_SIZE) {
        Response->Action = MonIntercept_Block;
        Response->Reason = MonReason_MalformedRequest;
        InterlockedIncrement64(&g_InterceptState.Stats.BlockedMalformed);
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Capture header (caller has SEH) */
    RtlCopyMemory(CapturedHeader, UserBuffer, sizeof(MON_INTERCEPT_REQUEST));

    /* Validate version */
    if (CapturedHeader->Version != MON_INTERCEPT_REQUEST_VERSION) {
        Response->Action = MonIntercept_Block;
        Response->Reason = MonReason_MalformedRequest;
        InterlockedIncrement64(&g_InterceptState.Stats.BlockedMalformed);
        return STATUS_INVALID_PARAMETER;
    }

    /* Validate Size field matches reality */
    if (CapturedHeader->Size < MON_INTERCEPT_REQUEST_HEADER_SIZE ||
        CapturedHeader->Size > UserBufferSize) {
        Response->Action = MonIntercept_Block;
        Response->Reason = MonReason_MalformedRequest;
        InterlockedIncrement64(&g_InterceptState.Stats.BlockedMalformed);
        return STATUS_INVALID_PARAMETER;
    }

    /* Validate OperationCount doesn't overflow */
    if (CapturedHeader->OperationCount > MON_INTERCEPT_MAX_OPS_PER_SUBMIT) {
        Response->Action = MonIntercept_Block;
        Response->Reason = MonReason_ExcessiveOperations;
        Response->ViolatingOpIndex = MON_INTERCEPT_MAX_OPS_PER_SUBMIT;
        InterlockedIncrement64(&g_InterceptState.Stats.BlockedExcessiveOps);
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
 * Internal Helper: Validate Request Size vs Op Count
 *-------------------------------------------------------------------------*/

/**
 * @function   MonInterceptValidateRequestSize
 * @purpose    Verify buffer size matches claimed operation count
 */
static NTSTATUS
MonInterceptValidateRequestSize(
    _In_ ULONG UserBufferSize,
    _In_ ULONG OperationCount,
    _Inout_ PMON_INTERCEPT_RESPONSE Response
)
{
    ULONG requiredSize;
    ULONG sqeArraySize;

    /* Check for multiplication overflow */
    if (OperationCount > (MAXULONG / sizeof(MON_SERIALIZED_SQE))) {
        Response->Action = MonIntercept_Block;
        Response->Reason = MonReason_MalformedRequest;
        return STATUS_INTEGER_OVERFLOW;
    }

    sqeArraySize = OperationCount * sizeof(MON_SERIALIZED_SQE);

    /* Check for addition overflow */
    if (sqeArraySize > (MAXULONG - MON_INTERCEPT_REQUEST_HEADER_SIZE)) {
        Response->Action = MonIntercept_Block;
        Response->Reason = MonReason_MalformedRequest;
        return STATUS_INTEGER_OVERFLOW;
    }

    requiredSize = MON_INTERCEPT_REQUEST_HEADER_SIZE + sqeArraySize;

    if (UserBufferSize < requiredSize) {
        Response->Action = MonIntercept_Block;
        Response->Reason = MonReason_MalformedRequest;
        InterlockedIncrement64(&g_InterceptState.Stats.BlockedMalformed);
        return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
 * Internal Helper: Policy Enforcement Checks
 *-------------------------------------------------------------------------*/

/**
 * @function   MonInterceptCheckPolicyLimits
 * @purpose    Check policy-level limits (op count, blacklist)
 */
static NTSTATUS
MonInterceptCheckPolicyLimits(
    _In_ const MON_INTERCEPT_REQUEST* Request,
    _In_ const MON_INTERCEPT_POLICY* Policy,
    _Inout_ PMON_INTERCEPT_RESPONSE Response
)
{
    /* Check operation count limit */
    if (Policy->EnforceOperationLimit) {
        ULONG maxOps = Policy->MaxOperationsPerSubmit;
        if (maxOps == 0) {
            maxOps = MON_INTERCEPT_DEFAULT_MAX_OPS;
        }
        if (Request->OperationCount > maxOps) {
            Response->Action = Policy->AuditMode ? MonIntercept_LogOnly : MonIntercept_Block;
            Response->Reason = MonReason_ExcessiveOperations;
            Response->ViolatingOpIndex = maxOps;
            RtlStringCchCopyA(Response->MitreTechnique,
                              sizeof(Response->MitreTechnique),
                              MonInterceptGetMitreTechnique(MonReason_ExcessiveOperations));
            InterlockedIncrement64(&g_InterceptState.Stats.BlockedExcessiveOps);
            return Policy->AuditMode ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
        }
    }

    /* Check blacklist */
    if (MonInterceptCheckBlacklist(Request->ProcessId)) {
        Response->Action = Policy->AuditMode ? MonIntercept_LogOnly : MonIntercept_Block;
        Response->Reason = MonReason_ProcessBlacklisted;
        RtlStringCchCopyA(Response->MitreTechnique,
                          sizeof(Response->MitreTechnique),
                          MonInterceptGetMitreTechnique(MonReason_ProcessBlacklisted));
        InterlockedIncrement64(&g_InterceptState.Stats.BlockedBlacklist);
        return Policy->AuditMode ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
    }

    return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
 * Internal Helper: SQE Array Validation Loop
 *-------------------------------------------------------------------------*/

/**
 * @function   MonInterceptValidateSqeArray
 * @purpose    Validate all SQEs in the request buffer
 * @precondition Called within SEH block
 */
static NTSTATUS
MonInterceptValidateSqeArray(
    _In_reads_bytes_(RequestSize) const VOID* UserBuffer,
    _In_ ULONG RequestSize,
    _In_ ULONG OperationCount,
    _In_ const MON_INTERCEPT_POLICY* Policy,
    _Inout_ PMON_INTERCEPT_RESPONSE Response
)
{
    MON_SERIALIZED_SQE capturedSqe;

    for (ULONG i = 0; i < OperationCount; i++) {
        /* Bounded capture */
        if (!MonInterceptCaptureSqe(UserBuffer, RequestSize, i, &capturedSqe)) {
            Response->Action = MonIntercept_Block;
            Response->Reason = MonReason_ValidationError;
            Response->ViolatingOpIndex = i;
            InterlockedIncrement64(&g_InterceptState.Stats.ValidationErrors);
            return STATUS_INVALID_PARAMETER;
        }

        /* Validate captured SQE */
        MON_INTERCEPT_REASON reason = MonInterceptValidateSingleSqe(&capturedSqe, Policy);

        if (reason != MonReason_None) {
            Response->Action = Policy->AuditMode ? MonIntercept_LogOnly : MonIntercept_Block;
            Response->Reason = reason;
            Response->ViolatingOpIndex = i;
            RtlStringCchCopyA(Response->MitreTechnique,
                              sizeof(Response->MitreTechnique),
                              MonInterceptGetMitreTechnique(reason));

            /* Update specific counter */
            switch (reason) {
                case MonReason_KernelAddressInBuffer:
                    InterlockedIncrement64(&g_InterceptState.Stats.BlockedKernelAddress);
                    break;
                case MonReason_SuspiciousOpCode:
                    InterlockedIncrement64(&g_InterceptState.Stats.BlockedSuspiciousOpCode);
                    break;
                case MonReason_BufferSizeTooLarge:
                    InterlockedIncrement64(&g_InterceptState.Stats.BlockedBufferSize);
                    break;
                default:
                    break;
            }

            if (!Policy->AuditMode) {
                return STATUS_ACCESS_DENIED;
            }
        }

        /* Count validated operation */
        InterlockedIncrement64(&g_InterceptState.Stats.TotalOperationsValidated);
    }

    return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
 * Internal Helper: Event Logging
 *-------------------------------------------------------------------------*/

/**
 * @function   MonInterceptLogEvent
 * @purpose    Log interception event to telemetry ring buffer
 */
static VOID
MonInterceptLogEvent(
    _In_ const MON_INTERCEPT_REQUEST* Request,
    _In_ const MON_INTERCEPT_RESPONSE* Response
)
{
    /* Only log blocks or audit violations */
    if (Response->Action == MonIntercept_Allow) {
        return;
    }

    /* Build compact event payload */
    struct {
        ULONG   ProcessId;
        ULONG64 IoRingHandle;
        ULONG   OperationCount;
        ULONG   Action;
        ULONG   Reason;
        ULONG   ViolatingIndex;
        CHAR    Technique[16];
    } payload;

    payload.ProcessId = Request->ProcessId;
    payload.IoRingHandle = Request->IoRingHandle;
    payload.OperationCount = Request->OperationCount;
    payload.Action = (ULONG)Response->Action;
    payload.Reason = (ULONG)Response->Reason;
    payload.ViolatingIndex = Response->ViolatingOpIndex;
    RtlCopyMemory(payload.Technique, Response->MitreTechnique,
                  sizeof(payload.Technique));

    /* Write to telemetry ring buffer if available */
    if (MonRingBufferIsInitialized()) {
        MonRingBufferWrite(
            MonEvent_PolicyViolation,
            &payload,
            sizeof(payload)
        );
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
        "[WIN11MON][INTERCEPT] %s PID=%lu Handle=0x%llX Reason=%u Tech=%s\n",
        Response->Action == MonIntercept_Block ? "Blocked" : "AuditLog",
        Request->ProcessId,
        Request->IoRingHandle,
        Response->Reason,
        Response->MitreTechnique);
}

/*--------------------------------------------------------------------------
 * Internal Helper: Update Timing Statistics
 *-------------------------------------------------------------------------*/

/**
 * @function   MonInterceptUpdateTimingStats
 * @purpose    Update validation timing statistics
 */
static VOID
MonInterceptUpdateTimingStats(
    _In_ ULONG64 ValidationTimeNs
)
{
    InterlockedAdd64(&g_InterceptState.Stats.TotalValidationTimeNs,
                     (LONG64)ValidationTimeNs);

    ULONG validationUs = (ULONG)(ValidationTimeNs / 1000);
    ULONG currentPeak = g_InterceptState.Stats.PeakValidationTimeUs;

    if (validationUs > currentPeak) {
        InterlockedCompareExchange(
            (volatile LONG*)&g_InterceptState.Stats.PeakValidationTimeUs,
            (LONG)validationUs,
            (LONG)currentPeak
        );
    }
}

/*==========================================================================
 * Public API Implementation
 *=========================================================================*/

_Use_decl_annotations_
NTSTATUS MonInterceptInitialize(VOID)
{
    if (InterlockedCompareExchange(&g_InterceptState.Initialized, 0, 0) != 0) {
        return STATUS_SUCCESS;
    }

    /* Initialize spinlocks */
    KeInitializeSpinLock(&g_InterceptState.PolicyLock);
    KeInitializeSpinLock(&g_InterceptState.BlacklistLock);

    /* Set secure default policy */
    RtlZeroMemory(&g_InterceptState.Policy, sizeof(MON_INTERCEPT_POLICY));
    g_InterceptState.Policy.Size = sizeof(MON_INTERCEPT_POLICY);
    g_InterceptState.Policy.Enabled = FALSE;  /* Disabled until explicit enable */
    g_InterceptState.Policy.AuditMode = FALSE;
    g_InterceptState.Policy.BlockKernelAddresses = TRUE;
    g_InterceptState.Policy.BlockCorruptedRegBuffers = TRUE;
    g_InterceptState.Policy.EnforceOperationLimit = TRUE;
    g_InterceptState.Policy.EnforceRateLimit = FALSE;
    g_InterceptState.Policy.ValidateOpCodes = TRUE;
    g_InterceptState.Policy.MaxOperationsPerSubmit = MON_INTERCEPT_DEFAULT_MAX_OPS;
    g_InterceptState.Policy.MaxBufferSizeBytes = MON_INTERCEPT_MAX_BUFFER_SIZE;
    g_InterceptState.Policy.MaxSubmitsPerSecond = MON_INTERCEPT_DEFAULT_RATE_LIMIT;
    g_InterceptState.Policy.AllowedOpCodeMask = MON_INTERCEPT_DEFAULT_OPCODE_MASK;

    g_InterceptState.PolicyVersion = 1;

    /* Zero statistics */
    RtlZeroMemory(&g_InterceptState.Stats, sizeof(MON_INTERCEPT_STATS));
    g_InterceptState.Stats.Size = sizeof(MON_INTERCEPT_STATS);

    /* Zero blacklist */
    RtlZeroMemory(g_InterceptState.Blacklist, sizeof(g_InterceptState.Blacklist));
    g_InterceptState.BlacklistCount = 0;

    /* Mark initialized */
    InterlockedExchange(&g_InterceptState.Initialized, 1);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][INTERCEPT] Initialized (disabled by default)\n");

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID MonInterceptShutdown(VOID)
{
    if (InterlockedCompareExchange(&g_InterceptState.Initialized, 0, 0) == 0) {
        return;
    }

    /* Disable first to prevent new validations */
    g_InterceptState.Policy.Enabled = FALSE;

    /* Mark shutdown */
    InterlockedExchange(&g_InterceptState.Initialized, 0);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][INTERCEPT] Shutdown (validated %lld, blocked %lld)\n",
        g_InterceptState.Stats.TotalValidationRequests,
        g_InterceptState.Stats.TotalBlocked);
}

_Use_decl_annotations_
BOOLEAN MonInterceptIsInitialized(VOID)
{
    return InterlockedCompareExchange(&g_InterceptState.Initialized, 0, 0) != 0;
}

/*--------------------------------------------------------------------------
 * Internal Helper: Update stats based on validation result
 *-------------------------------------------------------------------------*/

/**
 * @function   MonInterceptUpdateResultStats
 * @purpose    Update stats based on action and audit mode
 */
static VOID
MonInterceptUpdateResultStats(
    _In_ MON_INTERCEPT_ACTION Action,
    _In_ BOOLEAN AuditMode
)
{
    if (Action != MonIntercept_Allow) {
        if (!AuditMode) {
            InterlockedIncrement64(&g_InterceptState.Stats.TotalBlocked);
        } else {
            InterlockedIncrement64(&g_InterceptState.Stats.TotalLogOnly);
        }
    } else {
        InterlockedIncrement64(&g_InterceptState.Stats.TotalAllowed);
    }
}

/*--------------------------------------------------------------------------
 * Internal Helper: Core validation logic (called within SEH)
 *-------------------------------------------------------------------------*/

/**
 * @function   MonInterceptValidateCore
 * @purpose    Core validation logic for submission (SEH wrapper calls this)
 * @precondition Called within SEH block after ProbeForRead
 */
static NTSTATUS
MonInterceptValidateCore(
    _In_reads_bytes_(RequestSize) const VOID* Request,
    _In_ ULONG RequestSize,
    _In_ const MON_INTERCEPT_POLICY* Policy,
    _Inout_ PMON_INTERCEPT_RESPONSE Response
)
{
    MON_INTERCEPT_REQUEST capturedHeader;
    NTSTATUS status;

    /* Validate and capture header */
    status = MonInterceptValidateRequestHeader(
        (PMON_INTERCEPT_REQUEST)Request, RequestSize, &capturedHeader, Response);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Empty submission - allow */
    if (capturedHeader.OperationCount == 0) {
        InterlockedIncrement64(&g_InterceptState.Stats.TotalAllowed);
        return STATUS_SUCCESS;
    }

    /* Validate size matches operation count */
    status = MonInterceptValidateRequestSize(
        RequestSize, capturedHeader.OperationCount, Response);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Check policy-level limits */
    status = MonInterceptCheckPolicyLimits(&capturedHeader, Policy, Response);
    if (!NT_SUCCESS(status) || Response->Action != MonIntercept_Allow) {
        if (Response->Action != MonIntercept_Allow) {
            MonInterceptLogEvent(&capturedHeader, Response);
            MonInterceptUpdateResultStats(Response->Action, Policy->AuditMode);
        }
        return status;
    }

    /* Validate each SQE */
    status = MonInterceptValidateSqeArray(
        Request, RequestSize, capturedHeader.OperationCount, Policy, Response);

    if (Response->Action != MonIntercept_Allow) {
        MonInterceptLogEvent(&capturedHeader, Response);
    }
    MonInterceptUpdateResultStats(Response->Action, Policy->AuditMode);

    return status;
}

/*--------------------------------------------------------------------------
 * Public API: Main Validation Entry Point
 *-------------------------------------------------------------------------*/

_Use_decl_annotations_
NTSTATUS
MonInterceptValidateSubmission(
    PMON_INTERCEPT_REQUEST Request,
    ULONG RequestSize,
    PMON_INTERCEPT_RESPONSE Response
)
{
    LARGE_INTEGER startTime, endTime;
    MON_INTERCEPT_POLICY policy;
    NTSTATUS status = STATUS_SUCCESS;

    /* Initialize response with safe defaults */
    MonInterceptInitResponse(Response);

    /* Quick exit if not initialized */
    if (!MonInterceptIsInitialized()) {
        Response->Reason = MonReason_PolicyDisabled;
        return STATUS_SUCCESS;
    }

    /* Capture timing */
    KeQuerySystemTime(&startTime);
    InterlockedIncrement64(&g_InterceptState.Stats.TotalValidationRequests);

    /* Capture policy snapshot */
    MonInterceptCapturePolicy(&policy);

    /* Check if enabled */
    if (!policy.Enabled) {
        Response->Reason = MonReason_PolicyDisabled;
        InterlockedIncrement64(&g_InterceptState.Stats.TotalAllowed);
        goto Exit;
    }

    /*
     * SECURITY: All user buffer access within SEH block
     */
    __try {
        ProbeForRead(Request, RequestSize, sizeof(ULONG));
        status = MonInterceptValidateCore(Request, RequestSize, &policy, Response);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Response->Action = MonIntercept_Block;
        Response->Reason = MonReason_ValidationError;
        InterlockedIncrement64(&g_InterceptState.Stats.SehExceptions);
        InterlockedIncrement64(&g_InterceptState.Stats.ValidationErrors);
        status = GetExceptionCode();

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WIN11MON][INTERCEPT] SEH exception: 0x%08X\n", status);
    }

Exit:
    KeQuerySystemTime(&endTime);
    Response->ValidationTimeNs = (ULONG64)((endTime.QuadPart - startTime.QuadPart) * 100);
    MonInterceptUpdateTimingStats(Response->ValidationTimeNs);

    return status;
}

_Use_decl_annotations_
NTSTATUS
MonInterceptSetPolicy(
    PMON_INTERCEPT_POLICY Policy
)
{
    KIRQL oldIrql;

    if (!MonInterceptIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    if (Policy == NULL || Policy->Size != sizeof(MON_INTERCEPT_POLICY)) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&g_InterceptState.PolicyLock, &oldIrql);

    RtlCopyMemory(&g_InterceptState.Policy, Policy, sizeof(MON_INTERCEPT_POLICY));
    InterlockedIncrement(&g_InterceptState.PolicyVersion);

    KeReleaseSpinLock(&g_InterceptState.PolicyLock, oldIrql);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][INTERCEPT] Policy updated (enabled=%d, audit=%d)\n",
        Policy->Enabled, Policy->AuditMode);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
MonInterceptGetPolicy(
    PMON_INTERCEPT_POLICY Policy
)
{
    if (Policy == NULL) {
        return;
    }

    if (!MonInterceptIsInitialized()) {
        RtlZeroMemory(Policy, sizeof(MON_INTERCEPT_POLICY));
        Policy->Size = sizeof(MON_INTERCEPT_POLICY);
        return;
    }

    MonInterceptCapturePolicy(Policy);
}

_Use_decl_annotations_
VOID
MonInterceptGetStats(
    PMON_INTERCEPT_STATS Stats
)
{
    if (Stats == NULL) {
        return;
    }

    if (!MonInterceptIsInitialized()) {
        RtlZeroMemory(Stats, sizeof(MON_INTERCEPT_STATS));
        Stats->Size = sizeof(MON_INTERCEPT_STATS);
        return;
    }

    /* Snapshot volatile statistics */
    RtlCopyMemory(Stats, &g_InterceptState.Stats, sizeof(MON_INTERCEPT_STATS));

    /* Calculate average validation time */
    if (Stats->TotalValidationRequests > 0) {
        Stats->AverageValidationTimeUs = (ULONG)(
            (Stats->TotalValidationTimeNs / 1000) / Stats->TotalValidationRequests
        );
    }
}

_Use_decl_annotations_
VOID MonInterceptResetStats(VOID)
{
    if (!MonInterceptIsInitialized()) {
        return;
    }

    /* Reset all counters atomically */
    InterlockedExchange64(&g_InterceptState.Stats.TotalValidationRequests, 0);
    InterlockedExchange64(&g_InterceptState.Stats.TotalOperationsValidated, 0);
    InterlockedExchange64(&g_InterceptState.Stats.TotalAllowed, 0);
    InterlockedExchange64(&g_InterceptState.Stats.TotalBlocked, 0);
    InterlockedExchange64(&g_InterceptState.Stats.TotalLogOnly, 0);
    InterlockedExchange64(&g_InterceptState.Stats.BlockedRegBuffers, 0);
    InterlockedExchange64(&g_InterceptState.Stats.BlockedKernelAddress, 0);
    InterlockedExchange64(&g_InterceptState.Stats.BlockedExcessiveOps, 0);
    InterlockedExchange64(&g_InterceptState.Stats.BlockedSuspiciousOpCode, 0);
    InterlockedExchange64(&g_InterceptState.Stats.BlockedBlacklist, 0);
    InterlockedExchange64(&g_InterceptState.Stats.BlockedRateLimit, 0);
    InterlockedExchange64(&g_InterceptState.Stats.BlockedInvalidHandle, 0);
    InterlockedExchange64(&g_InterceptState.Stats.BlockedBufferSize, 0);
    InterlockedExchange64(&g_InterceptState.Stats.BlockedMalformed, 0);
    InterlockedExchange64(&g_InterceptState.Stats.TotalValidationTimeNs, 0);
    InterlockedExchange((volatile LONG*)&g_InterceptState.Stats.PeakValidationTimeUs, 0);
    InterlockedExchange64(&g_InterceptState.Stats.ValidationErrors, 0);
    InterlockedExchange64(&g_InterceptState.Stats.SehExceptions, 0);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][INTERCEPT] Statistics reset\n");
}

_Use_decl_annotations_
NTSTATUS
MonInterceptAddToBlacklist(
    ULONG ProcessId,
    PCWSTR ProcessName,
    PCSTR Reason
)
{
    KIRQL oldIrql;
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    LARGE_INTEGER currentTime;

    if (!MonInterceptIsInitialized() || ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    KeQuerySystemTime(&currentTime);
    KeAcquireSpinLock(&g_InterceptState.BlacklistLock, &oldIrql);

    /* Check if already blacklisted */
    for (ULONG i = 0; i < MON_INTERCEPT_MAX_BLACKLIST; i++) {
        if (g_InterceptState.Blacklist[i].ProcessId == ProcessId) {
            status = STATUS_SUCCESS;
            goto Exit;
        }
    }

    /* Find empty slot */
    for (ULONG i = 0; i < MON_INTERCEPT_MAX_BLACKLIST; i++) {
        if (g_InterceptState.Blacklist[i].ProcessId == 0) {
            g_InterceptState.Blacklist[i].ProcessId = ProcessId;
            g_InterceptState.Blacklist[i].AddedTime = currentTime.QuadPart;

            if (ProcessName != NULL) {
                RtlStringCchCopyW(g_InterceptState.Blacklist[i].ProcessName,
                                  RTL_NUMBER_OF(g_InterceptState.Blacklist[i].ProcessName),
                                  ProcessName);
            }

            if (Reason != NULL) {
                RtlStringCchCopyA(g_InterceptState.Blacklist[i].Reason,
                                  RTL_NUMBER_OF(g_InterceptState.Blacklist[i].Reason),
                                  Reason);
            }

            InterlockedIncrement(&g_InterceptState.BlacklistCount);
            status = STATUS_SUCCESS;

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[WIN11MON][INTERCEPT] Blacklisted PID=%lu\n", ProcessId);
            goto Exit;
        }
    }

Exit:
    KeReleaseSpinLock(&g_InterceptState.BlacklistLock, oldIrql);
    return status;
}

_Use_decl_annotations_
BOOLEAN
MonInterceptRemoveFromBlacklist(
    ULONG ProcessId
)
{
    KIRQL oldIrql;
    BOOLEAN found = FALSE;

    if (!MonInterceptIsInitialized() || ProcessId == 0) {
        return FALSE;
    }

    KeAcquireSpinLock(&g_InterceptState.BlacklistLock, &oldIrql);

    for (ULONG i = 0; i < MON_INTERCEPT_MAX_BLACKLIST; i++) {
        if (g_InterceptState.Blacklist[i].ProcessId == ProcessId) {
            RtlZeroMemory(&g_InterceptState.Blacklist[i],
                          sizeof(MON_BLACKLIST_ENTRY));
            InterlockedDecrement(&g_InterceptState.BlacklistCount);
            found = TRUE;

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[WIN11MON][INTERCEPT] Removed PID=%lu from blacklist\n", ProcessId);
            break;
        }
    }

    KeReleaseSpinLock(&g_InterceptState.BlacklistLock, oldIrql);
    return found;
}

_Use_decl_annotations_
BOOLEAN
MonInterceptIsBlacklisted(
    ULONG ProcessId
)
{
    if (!MonInterceptIsInitialized()) {
        return FALSE;
    }

    return MonInterceptCheckBlacklist(ProcessId);
}

_Use_decl_annotations_
NTSTATUS
MonInterceptEnumerateBlacklist(
    PMON_BLACKLIST_ENTRY Buffer,
    ULONG MaxEntries,
    ULONG* EntryCount
)
{
    KIRQL oldIrql;
    ULONG count = 0;

    if (Buffer == NULL || EntryCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *EntryCount = 0;

    if (!MonInterceptIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    if (MaxEntries == 0) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    KeAcquireSpinLock(&g_InterceptState.BlacklistLock, &oldIrql);

    /* Copy active entries to output buffer */
    for (ULONG i = 0; i < MON_INTERCEPT_MAX_BLACKLIST && count < MaxEntries; i++) {
        if (g_InterceptState.Blacklist[i].ProcessId != 0) {
            RtlCopyMemory(&Buffer[count],
                          &g_InterceptState.Blacklist[i],
                          sizeof(MON_BLACKLIST_ENTRY));
            count++;
        }
    }

    KeReleaseSpinLock(&g_InterceptState.BlacklistLock, oldIrql);

    *EntryCount = count;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
BOOLEAN MonInterceptIsEnabled(VOID)
{
    if (!MonInterceptIsInitialized()) {
        return FALSE;
    }

    return g_InterceptState.Policy.Enabled;
}

_Use_decl_annotations_
VOID MonInterceptEnable(BOOLEAN Enable)
{
    KIRQL oldIrql;

    if (!MonInterceptIsInitialized()) {
        return;
    }

    KeAcquireSpinLock(&g_InterceptState.PolicyLock, &oldIrql);
    g_InterceptState.Policy.Enabled = Enable;
    InterlockedIncrement(&g_InterceptState.PolicyVersion);
    KeReleaseSpinLock(&g_InterceptState.PolicyLock, oldIrql);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][INTERCEPT] %s\n", Enable ? "Enabled" : "Disabled");
}

#pragma warning(pop)
