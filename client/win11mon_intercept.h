/*
 * Windows 11 Monitor Manager - IoRing Interception Client Library Header
 *
 * Author: Colin MacRitchie | ziX Labs
 * Organization: ziX Performance Labs
 * File: client/win11mon_intercept.h
 * Version: 1.1
 * Date: 2025-11-30
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and
 * confidential. Redistribution or disclosure without prior written consent is
 * prohibited.
 *
 * Summary
 * -------
 * User-mode API for IoRing operation interception. Provides:
 *   - Hook installation on NtSubmitIoRing/NtCreateIoRing
 *   - Pre-submission validation via kernel driver
 *   - Policy configuration and statistics
 *   - Process blacklist management
 *
 * Architecture
 * ------------
 * - Layer 1: IAT/inline hooks capture NtSubmitIoRing calls
 * - Layer 2: Serialize SQE array into MON_INTERCEPT_REQUEST
 * - Layer 3: Send to kernel via IOCTL_MONITOR_INTERCEPT_VALIDATE
 * - Layer 4: Apply kernel response (block/allow/log)
 *
 * Usage
 * -----
 *   #include "win11mon_intercept.h"
 *
 *   // Initialize (requires valid driver handle from win11mon_client.h)
 *   HRESULT hr = Win11MonInterceptInit(hMon);
 *   if (SUCCEEDED(hr)) {
 *       // Enable interception with default policy
 *       Win11MonInterceptEnable(hMon, TRUE);
 *
 *       // ... application runs with IoRing validation ...
 *
 *       Win11MonInterceptShutdown(hMon);
 *   }
 *
 * Build
 * -----
 * Link with: win11mon_client.lib
 * Requires: Windows SDK, win11mon_client.h
 *
 * References
 * ----------
 * - Kernel header: ioring_intercept.h (structures must match)
 * - NT_IORING_SQE: yardenshafir/IoRing_Demos/ioringnt.h
 */

#ifndef WIN11MON_INTERCEPT_H
#define WIN11MON_INTERCEPT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>

#include "win11mon_client.h"

/*--------------------------------------------------------------------------
 * Compile-Time Assertions (User-Mode)
 *-------------------------------------------------------------------------*/
#ifndef C_ASSERT
#define C_ASSERT(e) typedef char __C_ASSERT__[(e) ? 1 : -1]
#endif

/*--------------------------------------------------------------------------
 * Configuration Constants (Mirrors Kernel)
 *-------------------------------------------------------------------------*/
#define WIN11MON_INTERCEPT_MAX_OPS_PER_SUBMIT 4096
#define WIN11MON_INTERCEPT_DEFAULT_MAX_OPS    1024
#define WIN11MON_INTERCEPT_DEFAULT_RATE_LIMIT 1000
#define WIN11MON_INTERCEPT_MAX_BLACKLIST      64
#define WIN11MON_INTERCEPT_MAX_BUFFER_SIZE    (256 * 1024 * 1024)

/*--------------------------------------------------------------------------
 * Interception Action Results (mirrors kernel MON_INTERCEPT_ACTION)
 *-------------------------------------------------------------------------*/
typedef enum _WIN11MON_INTERCEPT_ACTION {
  Win11MonIntercept_Allow = 0,  /* Operation permitted */
  Win11MonIntercept_Block = 1,  /* Operation blocked */
  Win11MonIntercept_LogOnly = 2 /* Audit mode: log but permit */
} WIN11MON_INTERCEPT_ACTION;

/*--------------------------------------------------------------------------
 * Violation Reason Codes (mirrors kernel MON_INTERCEPT_REASON)
 *-------------------------------------------------------------------------*/
typedef enum _WIN11MON_INTERCEPT_REASON {
  Win11MonReason_None = 0,                  /* No violation */
  Win11MonReason_RegBuffersCorrupted = 1,   /* A2 validation failed (T1068) */
  Win11MonReason_KernelAddressInBuffer = 2, /* Buffer VA in kernel space (T1068) */
  Win11MonReason_ExcessiveOperations = 3,   /* Too many SQEs (T1499) */
  Win11MonReason_SuspiciousOpCode = 4,      /* Unknown/blocked opcode (T1203) */
  Win11MonReason_ProcessBlacklisted = 5,    /* PID on block list (T1055) */
  Win11MonReason_RateLimitExceeded = 6,     /* Submit rate exceeded (T1499) */
  Win11MonReason_InvalidHandle = 7,         /* IoRing handle invalid */
  Win11MonReason_PolicyDisabled = 8,        /* Interception disabled */
  Win11MonReason_ValidationError = 9,       /* Internal error */
  Win11MonReason_BufferSizeTooLarge = 10,   /* Single buffer exceeds limit */
  Win11MonReason_MalformedRequest = 11      /* Request structure invalid */
} WIN11MON_INTERCEPT_REASON;

/*--------------------------------------------------------------------------
 * IoRing Operation Codes (mirrors kernel MON_IORING_OP_CODE)
 *-------------------------------------------------------------------------*/
typedef enum _WIN11MON_IORING_OP_CODE {
  Win11MonIoRingOp_Nop = 0,             /* No operation */
  Win11MonIoRingOp_Read = 1,            /* Read from file */
  Win11MonIoRingOp_RegisterFiles = 2,   /* Register file handles */
  Win11MonIoRingOp_RegisterBuffers = 3, /* Register buffers */
  Win11MonIoRingOp_Cancel = 4,          /* Cancel operation */
  Win11MonIoRingOp_Write = 5,           /* Write to file */
  Win11MonIoRingOp_Flush = 6,           /* Flush buffers */
  Win11MonIoRingOp_ReadScatter = 7,     /* Scatter read */
  Win11MonIoRingOp_WriteGather = 8,     /* Gather write */
  Win11MonIoRingOp_MaxKnown = 8
} WIN11MON_IORING_OP_CODE;

/*--------------------------------------------------------------------------
 * SQE Flags
 *-------------------------------------------------------------------------*/
#define WIN11MON_SQE_FLAG_NONE                 0x00
#define WIN11MON_SQE_FLAG_DRAIN_PRECEDING_OPS  0x01
#define WIN11MON_SQE_FLAG_PREREGISTERED_FILE   0x01
#define WIN11MON_SQE_FLAG_PREREGISTERED_BUFFER 0x02

/*--------------------------------------------------------------------------
 * Default Opcode Mask (all known opcodes 0-8)
 *-------------------------------------------------------------------------*/
#define WIN11MON_INTERCEPT_DEFAULT_OPCODE_MASK 0x000001FF

/*--------------------------------------------------------------------------
 * Serialized Submission Queue Entry
 *
 * Mirrors kernel MON_SERIALIZED_SQE for IOCTL transmission.
 * Must match kernel structure exactly for wire protocol.
 *-------------------------------------------------------------------------*/
#pragma pack(push, 8)
typedef struct _WIN11MON_SERIALIZED_SQE {
  DWORD OpCode; /* 0x00: Operation type */
  DWORD Flags;  /* 0x04: SQE flags */
  union {
    DWORD64 FileRef; /* 0x08: File handle or index */
    DWORD64 FilePaddingForx86;
  };
  LARGE_INTEGER FileOffset; /* 0x10: File offset */
  union {
    DWORD64 BufferAddress; /* 0x18: Buffer VA or index */
    DWORD64 BufferPaddingForx86;
  };
  DWORD BufferSize;   /* 0x20: Buffer size */
  DWORD BufferOffset; /* 0x24: Offset within buffer */
  DWORD Key;          /* 0x28: Cancellation key */
  DWORD Reserved1;    /* 0x2C: Padding */
  DWORD64 UserData;   /* 0x30: User context */
  DWORD64 Padding[4]; /* 0x38-0x50: Reserved */
} WIN11MON_SERIALIZED_SQE, *PWIN11MON_SERIALIZED_SQE;
#pragma pack(pop)

C_ASSERT(sizeof(WIN11MON_SERIALIZED_SQE) == 0x58); /* 88 bytes */

/*--------------------------------------------------------------------------
 * Policy Configuration
 *
 * Mirrors kernel MON_INTERCEPT_POLICY for driver communication.
 * Uses BYTE for boolean fields to match kernel BOOLEAN type (1 byte).
 *-------------------------------------------------------------------------*/
#pragma pack(push, 1)
typedef struct _WIN11MON_INTERCEPT_POLICY {
  DWORD Size; /* 0x00: Must be sizeof(WIN11MON_INTERCEPT_POLICY) */

  /* Master controls (BYTE to match kernel BOOLEAN) */
  BYTE Enabled;   /* 0x04: Global enable/disable */
  BYTE AuditMode; /* 0x05: Log but don't block */

  /* Validation toggles */
  BYTE BlockKernelAddresses;     /* 0x06: Block if buffer VA >= MmUserProbeAddress */
  BYTE BlockCorruptedRegBuffers; /* 0x07: Integrate with RegBuffers check */
  BYTE EnforceOperationLimit;    /* 0x08: Enforce MaxOperationsPerSubmit */
  BYTE EnforceRateLimit;         /* 0x09: Per-process rate limiting */
  BYTE ValidateOpCodes;          /* 0x0A: Check against AllowedOpCodeMask */
  BYTE Reserved1;                /* 0x0B: Alignment padding */

  /* Thresholds */
  DWORD MaxOperationsPerSubmit; /* 0x0C: 0 = use default (1024) */
  DWORD MaxBufferSizeBytes;     /* 0x10: 0 = no limit */
  DWORD MaxSubmitsPerSecond;    /* 0x14: 0 = use default (1000) */

  /* Operation whitelist */
  DWORD AllowedOpCodeMask; /* 0x18: Bitmask of allowed opcodes */
                           /* 0 = all permitted */
                           /* Default 0x1FF = ops 0-8 */
} WIN11MON_INTERCEPT_POLICY, *PWIN11MON_INTERCEPT_POLICY;
#pragma pack(pop)

C_ASSERT(sizeof(WIN11MON_INTERCEPT_POLICY) == 28);

/*--------------------------------------------------------------------------
 * Validation Request (for manual validation API)
 *
 * Variable-length structure sent to kernel.
 *-------------------------------------------------------------------------*/
#pragma pack(push, 4)
typedef struct _WIN11MON_INTERCEPT_REQUEST {
  DWORD Size;           /* Total structure size including SQEs */
  DWORD Version;        /* Protocol version (must be 1) */
  DWORD ProcessId;      /* Calling process ID */
  DWORD ThreadId;       /* Calling thread ID */
  DWORD64 IoRingHandle; /* Handle value being submitted */
  DWORD OperationCount; /* Number of SQEs following header */
  DWORD Flags;          /* Reserved, must be 0 */
  /* WIN11MON_SERIALIZED_SQE array[OperationCount] follows */
} WIN11MON_INTERCEPT_REQUEST, *PWIN11MON_INTERCEPT_REQUEST;
#pragma pack(pop)

C_ASSERT(sizeof(WIN11MON_INTERCEPT_REQUEST) == 32);
#define WIN11MON_INTERCEPT_REQUEST_HEADER_SIZE sizeof(WIN11MON_INTERCEPT_REQUEST)
#define WIN11MON_INTERCEPT_REQUEST_VERSION     1

/*--------------------------------------------------------------------------
 * Validation Response
 *
 * Mirrors kernel MON_INTERCEPT_RESPONSE.
 *-------------------------------------------------------------------------*/
#pragma pack(push, 8)
typedef struct _WIN11MON_INTERCEPT_RESPONSE {
  DWORD Size;                       /* sizeof(WIN11MON_INTERCEPT_RESPONSE) */
  WIN11MON_INTERCEPT_ACTION Action; /* Allow/Block/LogOnly */
  WIN11MON_INTERCEPT_REASON Reason; /* Violation reason */
  DWORD ViolatingOpIndex;           /* First bad SQE index, or -1 */
  DWORD ViolationFlags;             /* Additional flags */
  DWORD Reserved;                   /* Alignment */
  DWORD64 ValidationTimeNs;         /* Time spent validating */
  CHAR MitreTechnique[16];          /* ATT&CK technique ID */
} WIN11MON_INTERCEPT_RESPONSE, *PWIN11MON_INTERCEPT_RESPONSE;
#pragma pack(pop)

C_ASSERT(sizeof(WIN11MON_INTERCEPT_RESPONSE) == 48);

/*--------------------------------------------------------------------------
 * Interception Statistics
 *
 * Mirrors kernel MON_INTERCEPT_STATS.
 *-------------------------------------------------------------------------*/
#pragma pack(push, 8)
typedef struct _WIN11MON_INTERCEPT_STATS {
  DWORD Size;     /* sizeof(WIN11MON_INTERCEPT_STATS) */
  DWORD Reserved; /* Alignment */

  /* Request metrics */
  DWORD64 TotalValidationRequests;
  DWORD64 TotalOperationsValidated;

  /* Decision metrics */
  DWORD64 TotalAllowed;
  DWORD64 TotalBlocked;
  DWORD64 TotalLogOnly;

  /* Block reason breakdown */
  DWORD64 BlockedRegBuffers;
  DWORD64 BlockedKernelAddress;
  DWORD64 BlockedExcessiveOps;
  DWORD64 BlockedSuspiciousOpCode;
  DWORD64 BlockedBlacklist;
  DWORD64 BlockedRateLimit;
  DWORD64 BlockedInvalidHandle;
  DWORD64 BlockedBufferSize;
  DWORD64 BlockedMalformed;

  /* Performance metrics */
  DWORD64 TotalValidationTimeNs;
  DWORD PeakValidationTimeUs;
  DWORD AverageValidationTimeUs;

  /* Error metrics */
  DWORD64 ValidationErrors;
  DWORD64 SehExceptions;

} WIN11MON_INTERCEPT_STATS, *PWIN11MON_INTERCEPT_STATS;
#pragma pack(pop)

C_ASSERT(sizeof(WIN11MON_INTERCEPT_STATS) == 152);

/*--------------------------------------------------------------------------
 * Blacklist Entry
 *-------------------------------------------------------------------------*/
#pragma pack(push, 8)
typedef struct _WIN11MON_BLACKLIST_ENTRY {
  DWORD ProcessId;       /* 0 = slot empty */
  DWORD Reserved;        /* Alignment */
  DWORD64 AddedTime;     /* Timestamp when added */
  WCHAR ProcessName[64]; /* Image name for logging */
  CHAR Reason[64];       /* Human-readable reason */
} WIN11MON_BLACKLIST_ENTRY, *PWIN11MON_BLACKLIST_ENTRY;
#pragma pack(pop)

C_ASSERT(sizeof(WIN11MON_BLACKLIST_ENTRY) == 208);

/*--------------------------------------------------------------------------
 * Pre-Validation Callback
 *
 * Optional user callback invoked before sending validation to kernel.
 * Return FALSE to skip kernel validation and allow the operation.
 *-------------------------------------------------------------------------*/
typedef BOOL(CALLBACK *WIN11MON_PRE_VALIDATE_CALLBACK)(_In_ PVOID Context, _In_ HANDLE IoRingHandle,
                                                       _In_ DWORD OperationCount,
                                                       _In_reads_bytes_(BufferSize)
                                                           const VOID *SubmissionBuffer,
                                                       _In_ DWORD BufferSize);

/*--------------------------------------------------------------------------
 * Post-Validation Callback
 *
 * Optional user callback invoked after kernel validation completes.
 * Receives the validation result for logging/metrics.
 *-------------------------------------------------------------------------*/
typedef VOID(CALLBACK *WIN11MON_POST_VALIDATE_CALLBACK)(
    _In_ PVOID Context, _In_ HANDLE IoRingHandle, _In_ const WIN11MON_INTERCEPT_RESPONSE *Response);

/*==========================================================================
 * Public API - Initialization
 *=========================================================================*/

/**
 * @function   Win11MonInterceptInit
 * @purpose    Initialize the interception subsystem
 * @param[in]  Handle - Valid driver handle from Win11MonOpen
 * @returns    S_OK on success
 *             WIN11MON_E_NOT_SUPPORTED if capability not available
 * @note       Must be called before any other interception functions
 * @thread-safety Safe to call from any thread
 */
WIN11MON_API HRESULT Win11MonInterceptInit(_In_ HWIN11MON Handle);

/**
 * @function   Win11MonInterceptShutdown
 * @purpose    Shutdown interception and remove all hooks
 * @param[in]  Handle - Valid driver handle
 * @note       Waits for in-flight validations to complete
 * @thread-safety Safe; blocks until hooks removed
 */
WIN11MON_API VOID Win11MonInterceptShutdown(_In_ HWIN11MON Handle);

/**
 * @function   Win11MonInterceptIsAvailable
 * @purpose    Check if interception capability is available
 * @param[in]  Handle - Valid driver handle
 * @returns    TRUE if interception supported by driver
 * @thread-safety Lock-free; safe to call frequently
 */
WIN11MON_API BOOL Win11MonInterceptIsAvailable(_In_ HWIN11MON Handle);

/**
 * @function   Win11MonInterceptIsInitialized
 * @purpose    Check if interception subsystem is initialized
 * @param[in]  Handle - Valid driver handle
 * @returns    TRUE if Win11MonInterceptInit succeeded
 * @thread-safety Lock-free
 */
WIN11MON_API BOOL Win11MonInterceptIsInitialized(_In_ HWIN11MON Handle);

/*==========================================================================
 * Public API - Enable/Disable
 *=========================================================================*/

/**
 * @function   Win11MonInterceptEnable
 * @purpose    Enable or disable interception globally
 * @param[in]  Handle - Valid driver handle
 * @param[in]  Enable - TRUE to enable, FALSE to disable
 * @returns    S_OK on success
 * @thread-safety Safe; synchronized with driver
 */
WIN11MON_API HRESULT Win11MonInterceptEnable(_In_ HWIN11MON Handle, _In_ BOOL Enable);

/**
 * @function   Win11MonInterceptIsEnabled
 * @purpose    Check if interception is currently enabled
 * @param[in]  Handle - Valid driver handle
 * @returns    TRUE if enabled
 * @thread-safety Lock-free
 */
WIN11MON_API BOOL Win11MonInterceptIsEnabled(_In_ HWIN11MON Handle);

/*==========================================================================
 * Public API - Policy Configuration
 *=========================================================================*/

/**
 * @function   Win11MonInterceptSetPolicy
 * @purpose    Set interception policy
 * @param[in]  Handle - Valid driver handle
 * @param[in]  Policy - Policy configuration (Size must be set)
 * @returns    S_OK on success
 *             E_INVALIDARG if Policy->Size incorrect
 * @thread-safety Synchronized via driver spinlock
 */
WIN11MON_API HRESULT Win11MonInterceptSetPolicy(_In_ HWIN11MON Handle,
                                                _In_ const WIN11MON_INTERCEPT_POLICY *Policy);

/**
 * @function   Win11MonInterceptGetPolicy
 * @purpose    Get current interception policy
 * @param[in]  Handle - Valid driver handle
 * @param[out] Policy - Receives current policy
 * @returns    S_OK on success
 * @thread-safety Lock-free snapshot
 */
WIN11MON_API HRESULT Win11MonInterceptGetPolicy(_In_ HWIN11MON Handle,
                                                _Out_ PWIN11MON_INTERCEPT_POLICY Policy);

/**
 * @function   Win11MonInterceptSetDefaultPolicy
 * @purpose    Reset policy to secure defaults
 * @param[in]  Handle - Valid driver handle
 * @returns    S_OK on success
 */
WIN11MON_API HRESULT Win11MonInterceptSetDefaultPolicy(_In_ HWIN11MON Handle);

/*==========================================================================
 * Public API - Statistics
 *=========================================================================*/

/**
 * @function   Win11MonInterceptGetStats
 * @purpose    Get interception statistics
 * @param[in]  Handle - Valid driver handle
 * @param[out] Stats - Receives statistics (Size field set on return)
 * @returns    S_OK on success
 * @thread-safety Lock-free snapshot
 */
WIN11MON_API HRESULT Win11MonInterceptGetStats(_In_ HWIN11MON Handle,
                                               _Out_ PWIN11MON_INTERCEPT_STATS Stats);

/**
 * @function   Win11MonInterceptResetStats
 * @purpose    Reset all interception statistics to zero
 * @param[in]  Handle - Valid driver handle
 * @returns    S_OK on success
 * @thread-safety Interlocked operations
 */
WIN11MON_API HRESULT Win11MonInterceptResetStats(_In_ HWIN11MON Handle);

/*==========================================================================
 * Public API - Blacklist Management
 *=========================================================================*/

/**
 * @function   Win11MonInterceptAddBlacklist
 * @purpose    Add a process to the IoRing blacklist
 * @param[in]  Handle - Valid driver handle
 * @param[in]  ProcessId - Process ID to blacklist (must be > 0)
 * @param[in]  Reason - Optional reason string (max 63 chars)
 * @returns    S_OK on success
 *             E_OUTOFMEMORY if blacklist full (64 max)
 *             E_INVALIDARG if ProcessId == 0
 * @thread-safety Spinlock-synchronized
 */
WIN11MON_API HRESULT Win11MonInterceptAddBlacklist(_In_ HWIN11MON Handle, _In_ DWORD ProcessId,
                                                   _In_opt_ PCSTR Reason);

/**
 * @function   Win11MonInterceptRemoveBlacklist
 * @purpose    Remove a process from the blacklist
 * @param[in]  Handle - Valid driver handle
 * @param[in]  ProcessId - Process ID to remove
 * @returns    S_OK if removed
 *             S_FALSE if not found
 * @thread-safety Spinlock-synchronized
 */
WIN11MON_API HRESULT Win11MonInterceptRemoveBlacklist(_In_ HWIN11MON Handle, _In_ DWORD ProcessId);

/**
 * @function   Win11MonInterceptClearBlacklist
 * @purpose    Remove all processes from blacklist
 * @param[in]  Handle - Valid driver handle
 * @returns    S_OK on success
 * @thread-safety Spinlock-synchronized
 */
WIN11MON_API HRESULT Win11MonInterceptClearBlacklist(_In_ HWIN11MON Handle);

/**
 * @function   Win11MonInterceptIsBlacklisted
 * @purpose    Check if a process is blacklisted
 * @param[in]  Handle - Valid driver handle
 * @param[in]  ProcessId - Process ID to check
 * @returns    TRUE if blacklisted
 * @thread-safety Lock-free linear scan
 */
WIN11MON_API BOOL Win11MonInterceptIsBlacklisted(_In_ HWIN11MON Handle, _In_ DWORD ProcessId);

/**
 * @function   Win11MonInterceptGetBlacklist
 * @purpose    Enumerate all blacklisted processes
 * @param[in]  Handle - Valid driver handle
 * @param[out] Buffer - Buffer to receive entries
 * @param[in]  MaxEntries - Maximum entries buffer can hold
 * @param[out] EntryCount - Actual entries returned
 * @returns    S_OK on success
 */
WIN11MON_API HRESULT Win11MonInterceptGetBlacklist(_In_ HWIN11MON Handle,
                                                   _Out_writes_to_(MaxEntries, *EntryCount)
                                                       PWIN11MON_BLACKLIST_ENTRY Buffer,
                                                   _In_ DWORD MaxEntries, _Out_ DWORD *EntryCount);

/*==========================================================================
 * Public API - Callbacks
 *=========================================================================*/

/**
 * @function   Win11MonInterceptSetPreCallback
 * @purpose    Set pre-validation callback
 * @param[in]  Handle - Valid driver handle
 * @param[in]  Callback - Callback function (NULL to clear)
 * @param[in]  Context - User context passed to callback
 * @returns    S_OK on success
 * @note       Callback runs synchronously in NtSubmitIoRing context
 */
WIN11MON_API HRESULT Win11MonInterceptSetPreCallback(
    _In_ HWIN11MON Handle, _In_opt_ WIN11MON_PRE_VALIDATE_CALLBACK Callback,
    _In_opt_ PVOID Context);

/**
 * @function   Win11MonInterceptSetPostCallback
 * @purpose    Set post-validation callback
 * @param[in]  Handle - Valid driver handle
 * @param[in]  Callback - Callback function (NULL to clear)
 * @param[in]  Context - User context passed to callback
 * @returns    S_OK on success
 * @note       Callback runs synchronously after kernel validation
 */
WIN11MON_API HRESULT Win11MonInterceptSetPostCallback(
    _In_ HWIN11MON Handle, _In_opt_ WIN11MON_POST_VALIDATE_CALLBACK Callback,
    _In_opt_ PVOID Context);

/*==========================================================================
 * Public API - Hook Management
 *=========================================================================*/

/**
 * @function   Win11MonInterceptInstallHooks
 * @purpose    Install hooks on NtSubmitIoRing/NtCreateIoRing
 * @param[in]  Handle - Valid driver handle
 * @returns    S_OK on success
 *             E_FAIL if hooks already installed or hook failed
 * @note       Requires SeDebugPrivilege for cross-process hooking
 * @thread-safety Not thread-safe; call once during init
 */
WIN11MON_API HRESULT Win11MonInterceptInstallHooks(_In_ HWIN11MON Handle);

/**
 * @function   Win11MonInterceptRemoveHooks
 * @purpose    Remove all installed hooks
 * @param[in]  Handle - Valid driver handle
 * @returns    S_OK on success
 * @note       Blocks until all in-flight hook calls complete
 */
WIN11MON_API HRESULT Win11MonInterceptRemoveHooks(_In_ HWIN11MON Handle);

/**
 * @function   Win11MonInterceptAreHooksInstalled
 * @purpose    Check if hooks are currently installed
 * @param[in]  Handle - Valid driver handle
 * @returns    TRUE if hooks installed
 */
WIN11MON_API BOOL Win11MonInterceptAreHooksInstalled(_In_ HWIN11MON Handle);

/*==========================================================================
 * Public API - Manual Validation (for testing/custom hooks)
 *=========================================================================*/

/**
 * @function   Win11MonInterceptValidate
 * @purpose    Manually validate IoRing operations via kernel
 * @param[in]  Handle - Valid driver handle
 * @param[in]  IoRingHandle - IoRing handle being submitted
 * @param[in]  OperationCount - Number of SQEs
 * @param[in]  SubmissionBuffer - Serialized SQE array
 * @param[in]  BufferSize - Size of submission buffer
 * @param[out] Response - Receives validation result
 * @returns    S_OK on success (check Response->Action)
 *             E_INVALIDARG if parameters invalid
 * @note       Normally called internally by installed hooks
 */
WIN11MON_API HRESULT Win11MonInterceptValidate(_In_ HWIN11MON Handle, _In_ HANDLE IoRingHandle,
                                               _In_ DWORD OperationCount,
                                               _In_reads_bytes_(BufferSize)
                                                   const VOID *SubmissionBuffer,
                                               _In_ DWORD BufferSize,
                                               _Out_ PWIN11MON_INTERCEPT_RESPONSE Response);

/**
 * @function   Win11MonInterceptBuildRequest
 * @purpose    Helper to build validation request from raw SQE data
 * @param[in]  IoRingHandle - IoRing handle value
 * @param[in]  SqeArray - Array of serialized SQEs
 * @param[in]  SqeCount - Number of SQEs
 * @param[out] Request - Receives built request
 * @param[in]  RequestBufferSize - Size of Request buffer
 * @param[out] RequestSize - Actual request size needed/written
 * @returns    S_OK on success
 *             E_INSUFFICIENT_BUFFER if RequestBufferSize too small
 */
WIN11MON_API HRESULT Win11MonInterceptBuildRequest(
    _In_ HANDLE IoRingHandle, _In_reads_(SqeCount) const WIN11MON_SERIALIZED_SQE *SqeArray,
    _In_ DWORD SqeCount,
    _Out_writes_bytes_to_(RequestBufferSize, *RequestSize) PWIN11MON_INTERCEPT_REQUEST Request,
    _In_ DWORD RequestBufferSize, _Out_ DWORD *RequestSize);

#ifdef __cplusplus
}
#endif

#endif /* WIN11MON_INTERCEPT_H */
