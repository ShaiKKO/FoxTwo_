/*
 * IoRing Operation Interception & Policy Engine – Header
 *
 * Author: Colin MacRitchie | ziX Labs
 * Organization: ziX Labs — Security Research Division
 * File: ioring_intercept.h
 * Version: 1.0
 * Date: 2025-11-30
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and confidential.
 *   Redistribution or disclosure without prior written consent is prohibited.
 *
 * Summary
 * -------
 * Kernel-mode policy engine for validating IoRing submission queue operations.
 * User-mode interception hooks serialize SQEs and call kernel via IOCTL for
 * pre-execution policy enforcement.
 *
 * SECURITY PROPERTIES:
 * - Input: All validation requests treated as hostile until validated
 * - Output: Action decisions only; addresses masked before user-mode return
 * - Memory Safety: SEH guards all buffer access; ProbeForRead on user buffers
 * - IRQL: PASSIVE_LEVEL for validation; DISPATCH_LEVEL for policy queries
 *
 * Architecture:
 * - Layer 1: User-mode IAT/inline hook on ntdll!NtSubmitIoRing
 * - Layer 2: Kernel policy engine validates serialized SQE array
 * - Layer 3: Integration with RegBuffers integrity (A2) and rate limiting (B3)
 * - Layer 4: Telemetry via ring buffer (Phase 5A)
 *
 * References:
 * - PLAN_phase6_ioring_interception.md
 * - "One I/O Ring to Rule Them All" – Yarden Shafir
 * - NT_IORING_SQE layout from yardenshafir/IoRing_Demos/ioringnt.h
 * - Vergilius Project: IORING_OBJECT structure
 */

#ifndef _ZIX_LABS_IORING_INTERCEPT_H_
#define _ZIX_LABS_IORING_INTERCEPT_H_

#ifndef _KERNEL_MODE
# error "This header is for kernel-mode only."
#endif

#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------
 * Pool Tags
 *-------------------------------------------------------------------------*/
#define MON_INTERCEPT_TAG       'tInM'  /* 'MInt' – Monitor Intercept */
#define MON_INTERCEPT_SQE_TAG   'qSnM'  /* 'MnSq' – SQE validation buffer */

/*--------------------------------------------------------------------------
 * Configuration Constants
 *-------------------------------------------------------------------------*/
#define MON_INTERCEPT_MAX_OPS_PER_SUBMIT    4096    /* Absolute max SQEs per submit */
#define MON_INTERCEPT_DEFAULT_MAX_OPS       1024    /* Default policy limit */
#define MON_INTERCEPT_DEFAULT_RATE_LIMIT    1000    /* Submits per second */
#define MON_INTERCEPT_MAX_BLACKLIST         64      /* Max blacklisted PIDs */
#define MON_INTERCEPT_MAX_BUFFER_SIZE       (256 * 1024 * 1024)  /* 256MB max buffer */

/*--------------------------------------------------------------------------
 * Interception Action Codes
 *
 * Returned by validation to indicate policy decision.
 *-------------------------------------------------------------------------*/
typedef enum _MON_INTERCEPT_ACTION {
    MonIntercept_Allow = 0,         /* Operation permitted to proceed */
    MonIntercept_Block = 1,         /* Operation blocked; return error to caller */
    MonIntercept_LogOnly = 2        /* Audit mode: log violation but permit */
} MON_INTERCEPT_ACTION;

/*--------------------------------------------------------------------------
 * Violation Reason Codes
 *
 * Indicates specific reason for block/log decision.
 * Maps to MITRE ATT&CK techniques where applicable.
 *-------------------------------------------------------------------------*/
typedef enum _MON_INTERCEPT_REASON {
    MonReason_None = 0,                     /* No violation */
    MonReason_RegBuffersCorrupted = 1,      /* A2 validation failed (T1068) */
    MonReason_KernelAddressInBuffer = 2,    /* Buffer VA in kernel space (T1068) */
    MonReason_ExcessiveOperations = 3,      /* Too many SQEs in submission (T1499) */
    MonReason_SuspiciousOpCode = 4,         /* Unknown/blocked opcode (T1203) */
    MonReason_ProcessBlacklisted = 5,       /* PID on block list (T1055) */
    MonReason_RateLimitExceeded = 6,        /* Submit rate exceeded (T1499) */
    MonReason_InvalidHandle = 7,            /* IoRing handle invalid/not found */
    MonReason_PolicyDisabled = 8,           /* Interception subsystem disabled */
    MonReason_ValidationError = 9,          /* Internal error during validation */
    MonReason_BufferSizeTooLarge = 10,      /* Single buffer exceeds limit */
    MonReason_MalformedRequest = 11         /* Request structure invalid */
} MON_INTERCEPT_REASON;

/*--------------------------------------------------------------------------
 * IoRing Operation Codes (NT_IORING_OP_CODE)
 *
 * Mirror of Windows internal IORING_OP_CODE enum.
 * Source: ntioring_x.h, yardenshafir/IoRing_Demos
 *-------------------------------------------------------------------------*/
typedef enum _MON_IORING_OP_CODE {
    MonIoRingOp_Nop = 0,                /* No operation */
    MonIoRingOp_Read = 1,               /* Read from file to buffer */
    MonIoRingOp_RegisterFiles = 2,      /* Register file handle array */
    MonIoRingOp_RegisterBuffers = 3,    /* Register buffer array */
    MonIoRingOp_Cancel = 4,             /* Cancel pending operation */
    MonIoRingOp_Write = 5,              /* Write from buffer to file */
    MonIoRingOp_Flush = 6,              /* Flush file buffers */
    MonIoRingOp_ReadScatter = 7,        /* Scatter read (Win11 22H2+) */
    MonIoRingOp_WriteGather = 8,        /* Gather write (Win11 22H2+) */
    MonIoRingOp_MaxKnown = 8,           /* Highest known opcode */
    MonIoRingOp_ReservedMax = 255       /* Reserved upper bound */
} MON_IORING_OP_CODE;

/*--------------------------------------------------------------------------
 * SQE Flags (NT_IORING_SQE_FLAGS)
 *
 * Flags for individual submission queue entries.
 *-------------------------------------------------------------------------*/
#define MON_SQE_FLAG_NONE                   0x00
#define MON_SQE_FLAG_DRAIN_PRECEDING_OPS    0x01    /* Wait for prior ops */
#define MON_SQE_FLAG_PREREGISTERED_FILE     0x01    /* FileRef is index, not handle */
#define MON_SQE_FLAG_PREREGISTERED_BUFFER   0x02    /* Buffer is index, not pointer */

/*--------------------------------------------------------------------------
 * Serialized Submission Queue Entry
 *
 * Captured from user-mode NT_IORING_SQE for kernel validation.
 * Layout matches NT_IORING_SQE from Windows internals (80 bytes).
 *
 * SECURITY NOTE:
 * - This structure is populated from user-mode via IOCTL
 * - All fields must be validated before use
 * - BufferAddress must be checked against kernel boundary
 *-------------------------------------------------------------------------*/
typedef struct _MON_SERIALIZED_SQE {
    ULONG       OpCode;             /* 0x00: Operation type (MON_IORING_OP_CODE) */
    ULONG       Flags;              /* 0x04: SQE flags */
    union {
        ULONG64 FileRef;            /* 0x08: File handle or pre-registered index */
        ULONG64 FilePaddingForx86;
    };
    LARGE_INTEGER FileOffset;       /* 0x10: File offset for I/O operations */
    union {
        ULONG64 BufferAddress;      /* 0x18: Buffer VA or pre-registered index */
        ULONG64 BufferPaddingForx86;
    };
    ULONG       BufferSize;         /* 0x20: Buffer size in bytes */
    ULONG       BufferOffset;       /* 0x24: Offset within buffer */
    ULONG       Key;                /* 0x28: Cancellation key */
    ULONG       Reserved1;          /* 0x2C: Padding */
    ULONG64     UserData;           /* 0x30: User-defined context */
    ULONG64     Padding[4];         /* 0x38-0x50: Reserved/alignment */
} MON_SERIALIZED_SQE, *PMON_SERIALIZED_SQE;

C_ASSERT(sizeof(MON_SERIALIZED_SQE) == 0x58);  /* 88 bytes */
C_ASSERT(FIELD_OFFSET(MON_SERIALIZED_SQE, OpCode) == 0x00);
C_ASSERT(FIELD_OFFSET(MON_SERIALIZED_SQE, FileRef) == 0x08);
C_ASSERT(FIELD_OFFSET(MON_SERIALIZED_SQE, BufferAddress) == 0x18);
C_ASSERT(FIELD_OFFSET(MON_SERIALIZED_SQE, UserData) == 0x30);

/*--------------------------------------------------------------------------
 * Policy Configuration Structure
 *
 * Runtime-configurable policy settings for interception behavior.
 * Atomic updates via spinlock; lock-free reads after version check.
 *-------------------------------------------------------------------------*/
typedef struct _MON_INTERCEPT_POLICY {
    ULONG       Size;                       /* Must be sizeof(MON_INTERCEPT_POLICY) */

    /* Master controls */
    BOOLEAN     Enabled;                    /* Global enable/disable */
    BOOLEAN     AuditMode;                  /* TRUE: log but don't block */

    /* Validation toggles */
    BOOLEAN     BlockKernelAddresses;       /* Block if buffer VA >= MmUserProbeAddress */
    BOOLEAN     BlockCorruptedRegBuffers;   /* Integrate with A2 RegBuffers check */
    BOOLEAN     EnforceOperationLimit;      /* Enforce MaxOperationsPerSubmit */
    BOOLEAN     EnforceRateLimit;           /* Per-process submit rate limiting */
    BOOLEAN     ValidateOpCodes;            /* Check against AllowedOpCodeMask */
    BOOLEAN     Reserved1;                  /* Alignment padding */

    /* Thresholds */
    ULONG       MaxOperationsPerSubmit;     /* 0 = use default (1024) */
    ULONG       MaxBufferSizeBytes;         /* 0 = no limit; else max per-buffer */
    ULONG       MaxSubmitsPerSecond;        /* 0 = use default (1000) */

    /* Operation whitelist */
    ULONG       AllowedOpCodeMask;          /* Bitmask: bit N = opcode N allowed */
                                            /* 0 = all opcodes permitted */
                                            /* Default 0x1FF = ops 0-8 allowed */
} MON_INTERCEPT_POLICY, *PMON_INTERCEPT_POLICY;

C_ASSERT(sizeof(MON_INTERCEPT_POLICY) == 28);
#define MON_INTERCEPT_DEFAULT_OPCODE_MASK   0x000001FF  /* Ops 0-8 (all known) */

/*--------------------------------------------------------------------------
 * Validation Request Structure
 *
 * Sent from user-mode hook via IOCTL_MONITOR_INTERCEPT_VALIDATE.
 * Variable-length: header followed by SQE array.
 *
 * SECURITY REQUIREMENTS:
 * 1. Validate Size field matches expected: header + (OperationCount * sizeof(SQE))
 * 2. Bound OperationCount to MON_INTERCEPT_MAX_OPS_PER_SUBMIT
 * 3. Probe entire buffer before accessing SQE array
 *-------------------------------------------------------------------------*/
typedef struct _MON_INTERCEPT_REQUEST {
    ULONG       Size;               /* Total structure size including SQEs */
    ULONG       Version;            /* Protocol version (must be 1) */
    ULONG       ProcessId;          /* Calling process ID */
    ULONG       ThreadId;           /* Calling thread ID */
    ULONG64     IoRingHandle;       /* Handle value being submitted */
    ULONG       OperationCount;     /* Number of SQEs following header */
    ULONG       Flags;              /* Reserved, must be 0 */
    /* MON_SERIALIZED_SQE array[OperationCount] follows immediately */
} MON_INTERCEPT_REQUEST, *PMON_INTERCEPT_REQUEST;

C_ASSERT(sizeof(MON_INTERCEPT_REQUEST) == 32);
#define MON_INTERCEPT_REQUEST_HEADER_SIZE   sizeof(MON_INTERCEPT_REQUEST)
#define MON_INTERCEPT_REQUEST_VERSION       1

/*--------------------------------------------------------------------------
 * Validation Response Structure
 *
 * Returned to user-mode with validation decision.
 *-------------------------------------------------------------------------*/
typedef struct _MON_INTERCEPT_RESPONSE {
    ULONG                   Size;               /* sizeof(MON_INTERCEPT_RESPONSE) */
    MON_INTERCEPT_ACTION    Action;             /* Allow/Block/LogOnly */
    MON_INTERCEPT_REASON    Reason;             /* Why this decision */
    ULONG                   ViolatingOpIndex;   /* Index of first bad SQE, or (ULONG)-1 */
    ULONG                   ViolationFlags;     /* Additional MON_REGBUF_VF_* flags */
    ULONG                   Reserved;           /* Alignment */
    ULONG64                 ValidationTimeNs;   /* Time spent validating (nanoseconds) */
    CHAR                    MitreTechnique[16]; /* ATT&CK technique ID (e.g., "T1068") */
} MON_INTERCEPT_RESPONSE, *PMON_INTERCEPT_RESPONSE;

C_ASSERT(sizeof(MON_INTERCEPT_RESPONSE) == 48);

/*--------------------------------------------------------------------------
 * Interception Statistics
 *
 * Volatile counters for operational metrics.
 *-------------------------------------------------------------------------*/
typedef struct _MON_INTERCEPT_STATS {
    ULONG       Size;                       /* sizeof(MON_INTERCEPT_STATS) */
    ULONG       Reserved;                   /* Alignment */

    /* Request metrics */
    volatile LONG64 TotalValidationRequests;
    volatile LONG64 TotalOperationsValidated;

    /* Decision metrics */
    volatile LONG64 TotalAllowed;
    volatile LONG64 TotalBlocked;
    volatile LONG64 TotalLogOnly;

    /* Block reason breakdown */
    volatile LONG64 BlockedRegBuffers;
    volatile LONG64 BlockedKernelAddress;
    volatile LONG64 BlockedExcessiveOps;
    volatile LONG64 BlockedSuspiciousOpCode;
    volatile LONG64 BlockedBlacklist;
    volatile LONG64 BlockedRateLimit;
    volatile LONG64 BlockedInvalidHandle;
    volatile LONG64 BlockedBufferSize;
    volatile LONG64 BlockedMalformed;

    /* Performance metrics */
    volatile LONG64 TotalValidationTimeNs;
    volatile ULONG  PeakValidationTimeUs;
    volatile ULONG  AverageValidationTimeUs;

    /* Error metrics */
    volatile LONG64 ValidationErrors;
    volatile LONG64 SehExceptions;

} MON_INTERCEPT_STATS, *PMON_INTERCEPT_STATS;

C_ASSERT(sizeof(MON_INTERCEPT_STATS) == 152);

/*--------------------------------------------------------------------------
 * Process Blacklist Entry
 *
 * Entries for processes blocked from IoRing operations.
 *-------------------------------------------------------------------------*/
typedef struct _MON_BLACKLIST_ENTRY {
    ULONG       ProcessId;          /* 0 = slot empty */
    ULONG       Reserved;           /* Alignment */
    ULONG64     AddedTime;          /* KeQuerySystemTime when added */
    WCHAR       ProcessName[64];    /* Image name for logging */
    CHAR        Reason[64];         /* Human-readable reason */
} MON_BLACKLIST_ENTRY, *PMON_BLACKLIST_ENTRY;

C_ASSERT(sizeof(MON_BLACKLIST_ENTRY) == 208);

/*--------------------------------------------------------------------------
 * Public Function Prototypes
 *-------------------------------------------------------------------------*/

/**
 * @function   MonInterceptInitialize
 * @purpose    Initialize the IoRing interception subsystem
 * @precondition IRQL == PASSIVE_LEVEL; Called from DriverEntry
 * @postcondition Subsystem ready; policy set to secure defaults
 * @returns    STATUS_SUCCESS on success
 *             STATUS_INSUFFICIENT_RESOURCES if allocation fails
 * @thread-safety Single-threaded; called once during init
 * @side-effects Allocates blacklist storage; initializes spinlocks
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS MonInterceptInitialize(VOID);

/**
 * @function   MonInterceptShutdown
 * @purpose    Shutdown interception and free all resources
 * @precondition IRQL == PASSIVE_LEVEL; Called from DriverUnload
 * @postcondition All resources freed; subsystem unavailable
 * @thread-safety Single-threaded; no concurrent operations
 * @side-effects Frees all allocated memory
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID MonInterceptShutdown(VOID);

/**
 * @function   MonInterceptValidateSubmission
 * @purpose    Validate IoRing submission request from user-mode hook
 * @precondition IRQL == PASSIVE_LEVEL; called from IOCTL dispatch
 * @postcondition Response populated with decision and reason
 *
 * SECURITY REQUIREMENTS:
 * 1. Request buffer comes from user-mode; treat as hostile
 * 2. Probe and capture all data before validation
 * 3. Bound all array accesses
 * 4. SEH guard all dereferences
 *
 * @param[in]  Request - User-mode request buffer (untrusted)
 * @param[in]  RequestSize - Size claimed by caller
 * @param[out] Response - Validation result
 * @returns    STATUS_SUCCESS if validation completed (check Response->Action)
 *             STATUS_INVALID_PARAMETER if request malformed
 *             STATUS_BUFFER_TOO_SMALL if RequestSize insufficient
 *
 * @thread-safety Re-entrant; concurrent validation supported
 * @side-effects Updates statistics; may log to ring buffer
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MonInterceptValidateSubmission(
    _In_reads_bytes_(RequestSize) PMON_INTERCEPT_REQUEST Request,
    _In_ ULONG RequestSize,
    _Out_ PMON_INTERCEPT_RESPONSE Response
);

/**
 * @function   MonInterceptSetPolicy
 * @purpose    Update interception policy atomically
 * @precondition IRQL <= DISPATCH_LEVEL
 * @postcondition New policy in effect for subsequent validations
 *
 * @param[in]  Policy - New policy settings; Size field must match
 * @returns    STATUS_SUCCESS on success
 *             STATUS_INVALID_PARAMETER if Policy->Size incorrect
 *
 * @thread-safety Spinlock-synchronized update
 * @side-effects Increments policy version counter
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
MonInterceptSetPolicy(
    _In_ PMON_INTERCEPT_POLICY Policy
);

/**
 * @function   MonInterceptGetPolicy
 * @purpose    Query current interception policy
 * @precondition IRQL <= DISPATCH_LEVEL
 * @postcondition Policy buffer populated with current settings
 *
 * @param[out] Policy - Buffer to receive current policy
 *
 * @thread-safety Lock-free snapshot
 * @side-effects None
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
MonInterceptGetPolicy(
    _Out_ PMON_INTERCEPT_POLICY Policy
);

/**
 * @function   MonInterceptGetStats
 * @purpose    Query interception statistics
 * @precondition IRQL <= DISPATCH_LEVEL
 * @postcondition Stats buffer populated
 *
 * @param[out] Stats - Buffer to receive statistics
 *
 * @thread-safety Lock-free snapshot of volatile counters
 * @side-effects None
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
MonInterceptGetStats(
    _Out_ PMON_INTERCEPT_STATS Stats
);

/**
 * @function   MonInterceptResetStats
 * @purpose    Reset all statistics counters to zero
 * @precondition IRQL <= DISPATCH_LEVEL
 * @postcondition All counters zeroed
 *
 * @thread-safety Interlocked operations on each counter
 * @side-effects Clears all metrics
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID MonInterceptResetStats(VOID);

/**
 * @function   MonInterceptAddToBlacklist
 * @purpose    Add a process to the IoRing blacklist
 * @precondition IRQL <= DISPATCH_LEVEL
 * @postcondition Process will be blocked from IoRing submissions
 *
 * @param[in]  ProcessId - PID to blacklist (must be > 0)
 * @param[in]  ProcessName - Optional image name for logging
 * @param[in]  Reason - Optional human-readable reason
 * @returns    STATUS_SUCCESS if added
 *             STATUS_INSUFFICIENT_RESOURCES if blacklist full
 *             STATUS_INVALID_PARAMETER if ProcessId == 0
 *
 * @thread-safety Spinlock-synchronized
 * @side-effects May overwrite existing entry for same PID
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
MonInterceptAddToBlacklist(
    _In_ ULONG ProcessId,
    _In_opt_ PCWSTR ProcessName,
    _In_opt_ PCSTR Reason
);

/**
 * @function   MonInterceptRemoveFromBlacklist
 * @purpose    Remove a process from the IoRing blacklist
 * @precondition IRQL <= DISPATCH_LEVEL
 *
 * @param[in]  ProcessId - PID to remove
 * @returns    TRUE if removed, FALSE if not found
 *
 * @thread-safety Spinlock-synchronized
 * @side-effects Clears blacklist entry
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
MonInterceptRemoveFromBlacklist(
    _In_ ULONG ProcessId
);

/**
 * @function   MonInterceptIsBlacklisted
 * @purpose    Check if a process is on the blacklist
 * @precondition IRQL <= DISPATCH_LEVEL
 *
 * @param[in]  ProcessId - PID to check
 * @returns    TRUE if blacklisted, FALSE otherwise
 *
 * @thread-safety Lock-free linear scan
 * @side-effects None
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
MonInterceptIsBlacklisted(
    _In_ ULONG ProcessId
);

/**
 * @function   MonInterceptEnumerateBlacklist
 * @purpose    Enumerate all blacklisted processes
 * @precondition IRQL == PASSIVE_LEVEL
 *
 * @param[out]    Buffer - Caller-supplied buffer for entries
 * @param[in]     MaxEntries - Maximum entries buffer can hold
 * @param[out]    EntryCount - Actual number of entries returned
 * @returns       STATUS_SUCCESS on success
 *                STATUS_BUFFER_TOO_SMALL if buffer insufficient
 *                STATUS_NOT_SUPPORTED if not initialized
 *
 * @thread-safety Spinlock-protected snapshot
 * @side-effects None
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MonInterceptEnumerateBlacklist(
    _Out_writes_to_(MaxEntries, *EntryCount) PMON_BLACKLIST_ENTRY Buffer,
    _In_ ULONG MaxEntries,
    _Out_ ULONG* EntryCount
);

/**
 * @function   MonInterceptIsEnabled
 * @purpose    Quick check if interception is enabled
 * @precondition IRQL <= DISPATCH_LEVEL
 * @returns    TRUE if enabled and initialized
 *
 * @thread-safety Lock-free read
 * @side-effects None
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN MonInterceptIsEnabled(VOID);

/**
 * @function   MonInterceptEnable
 * @purpose    Enable or disable interception globally
 * @precondition IRQL <= DISPATCH_LEVEL
 *
 * @param[in]  Enable - TRUE to enable, FALSE to disable
 *
 * @thread-safety Spinlock-synchronized
 * @side-effects Updates policy Enabled flag
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID MonInterceptEnable(
    _In_ BOOLEAN Enable
);

/**
 * @function   MonInterceptIsInitialized
 * @purpose    Check if interception subsystem is initialized
 * @precondition IRQL <= DISPATCH_LEVEL
 * @returns    TRUE if MonInterceptInitialize succeeded
 *
 * @thread-safety Lock-free read
 * @side-effects None
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN MonInterceptIsInitialized(VOID);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _ZIX_LABS_IORING_INTERCEPT_H_ */
