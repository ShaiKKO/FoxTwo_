/*
 * ETW TraceLogging Provider – Public Header
 *
 * Author: Colin MacRitchie | ziX Labs
 * Organization: ziX Labs — Security Research Division
 * File: telemetry_etw.h
 * Version: 1.0
 * Date: 2025-11-30
 *
 * Summary
 * -------
 * Provides ETW TraceLogging infrastructure for the Windows 11 Monitor
 * Manager. TraceLogging is preferred over manifest-based ETW for kernel
 * drivers per Microsoft guidance.
 *
 * Provider GUID: {7E8B92A1-5C3D-4F2E-B8A9-1D2E3F4A5B6C}
 * Provider Name: ziXLabs-Win11MonitorMgr
 *
 * References:
 * - https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/tracelogging-for-kernel-mode-drivers-and-components
 */

#ifndef _ZIX_LABS_TELEMETRY_ETW_H_
#define _ZIX_LABS_TELEMETRY_ETW_H_

#ifndef _KERNEL_MODE
# error "This header is for kernel-mode only."
#endif

#include <ntddk.h>
#include <evntrace.h>

/*
 * TraceLogging includes require specific WDK version.
 * Fall back to stub if unavailable.
 */
#if defined(TRACELOGGING_SUPPORTED) || (NTDDI_VERSION >= NTDDI_WIN10)
#include <TraceLoggingProvider.h>
#define MON_ETW_TRACELOGGING_AVAILABLE 1
#else
#define MON_ETW_TRACELOGGING_AVAILABLE 0
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------
 * Provider Configuration
 *-------------------------------------------------------------------------*/

/* Provider name visible in ETW tools */
#define MON_ETW_PROVIDER_NAME       "ziXLabs-Win11MonitorMgr"

/*
 * Provider GUID: {7E8B92A1-5C3D-4F2E-B8A9-1D2E3F4A5B6C}
 *
 * Generated for ziX Labs Win11 Monitor Manager.
 * Use with: logman, wevtutil, tracelog, etc.
 */
DEFINE_GUID(MON_ETW_PROVIDER_GUID,
    0x7e8b92a1, 0x5c3d, 0x4f2e,
    0xb8, 0xa9, 0x1d, 0x2e, 0x3f, 0x4a, 0x5b, 0x6c);

/*--------------------------------------------------------------------------
 * Event Levels (matching TRACE_LEVEL_*)
 *-------------------------------------------------------------------------*/
#define MON_ETW_LEVEL_CRITICAL      1   /* TRACE_LEVEL_CRITICAL */
#define MON_ETW_LEVEL_ERROR         2   /* TRACE_LEVEL_ERROR */
#define MON_ETW_LEVEL_WARNING       3   /* TRACE_LEVEL_WARNING */
#define MON_ETW_LEVEL_INFO          4   /* TRACE_LEVEL_INFORMATION */
#define MON_ETW_LEVEL_VERBOSE       5   /* TRACE_LEVEL_VERBOSE */

/*--------------------------------------------------------------------------
 * Event Keywords for Filtering
 *
 * Consumers can filter by keyword to receive only relevant events.
 *-------------------------------------------------------------------------*/
#define MON_ETW_KEYWORD_DETECTION   0x0001  /* Security detections */
#define MON_ETW_KEYWORD_POOL        0x0002  /* Pool allocation events */
#define MON_ETW_KEYWORD_IORING      0x0004  /* IoRing-specific events */
#define MON_ETW_KEYWORD_TELEMETRY   0x0008  /* General telemetry */
#define MON_ETW_KEYWORD_DIAGNOSTIC  0x0010  /* Debug/diagnostic events */
#define MON_ETW_KEYWORD_HANDLE      0x0020  /* Handle operations */

/*--------------------------------------------------------------------------
 * Event IDs
 *-------------------------------------------------------------------------*/
typedef enum _MON_ETW_EVENT_ID {
    MonEtwEvent_None = 0,

    /* Detection events (100-199) */
    MonEtwEvent_CrossVmDetected = 100,
    MonEtwEvent_RegBuffersViolation = 101,
    MonEtwEvent_PolicyViolation = 102,
    MonEtwEvent_Anomaly = 103,

    /* IoRing events (200-299) */
    MonEtwEvent_IoRingHandleCreated = 200,
    MonEtwEvent_IoRingHandleSpray = 201,
    MonEtwEvent_IoRingHandleDuplicated = 202,
    MonEtwEvent_IoRingEnumerated = 203,

    /* Pool events (300-399) */
    MonEtwEvent_PoolAllocation = 300,
    MonEtwEvent_PoolTagFound = 301,
    MonEtwEvent_PoolSprayDetected = 302,

    /* Operational events (400-499) */
    MonEtwEvent_DriverLoaded = 400,
    MonEtwEvent_DriverUnloaded = 401,
    MonEtwEvent_MonitoringEnabled = 402,
    MonEtwEvent_MonitoringDisabled = 403,
    MonEtwEvent_OffsetResolutionFailed = 404,

    MonEtwEvent_Max
} MON_ETW_EVENT_ID;

/*--------------------------------------------------------------------------
 * MITRE ATT&CK Technique Identifiers
 *-------------------------------------------------------------------------*/
#define MON_ATTACK_TECHNIQUE_T1068   "T1068"  /* Exploitation for Privilege Escalation */
#define MON_ATTACK_TECHNIQUE_T1106   "T1106"  /* Native API */
#define MON_ATTACK_TACTIC_TA0004     "TA0004" /* Privilege Escalation */
#define MON_ATTACK_TACTIC_TA0002     "TA0002" /* Execution */

/*--------------------------------------------------------------------------
 * Public Function Prototypes
 *-------------------------------------------------------------------------*/

/**
 * @function   MonEtwInitialize
 * @purpose    Register ETW TraceLogging provider
 * @precondition IRQL == PASSIVE_LEVEL; Called from DriverEntry
 * @postcondition Provider registered and ready for event emission
 * @thread-safety Single-threaded init
 * @side-effects Registers ETW provider with kernel
 * @returns    STATUS_SUCCESS if registration succeeded
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS MonEtwInitialize(VOID);

/**
 * @function   MonEtwShutdown
 * @purpose    Unregister ETW provider
 * @precondition IRQL == PASSIVE_LEVEL; Called from DriverUnload
 * @postcondition Provider unregistered
 * @thread-safety Single-threaded shutdown
 * @side-effects Unregisters ETW provider
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID MonEtwShutdown(VOID);

/**
 * @function   MonEtwIsEnabled
 * @purpose    Check if ETW provider is enabled and accepting events
 * @precondition IRQL <= DISPATCH_LEVEL
 * @postcondition Returns TRUE if events should be logged
 * @thread-safety Thread-safe
 * @side-effects None
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN MonEtwIsEnabled(VOID);

/*--------------------------------------------------------------------------
 * Event Logging Functions
 *-------------------------------------------------------------------------*/

/**
 * @function   MonEtwLogCrossVmDetection
 * @purpose    Log cross-VM (user VA in kernel) detection event
 * @precondition IRQL <= DISPATCH_LEVEL
 * @side-effects Emits ETW event if provider enabled
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
MonEtwLogCrossVmDetection(
    _In_ ULONG ProcessId,
    _In_ ULONG ThreadId,
    _In_ ULONG64 SuspectAddress,
    _In_ UCHAR Severity
);

/**
 * @function   MonEtwLogRegBuffersViolation
 * @purpose    Log RegBuffers integrity violation event
 * @precondition IRQL <= DISPATCH_LEVEL
 * @side-effects Emits ETW event if provider enabled
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
MonEtwLogRegBuffersViolation(
    _In_ ULONG ProcessId,
    _In_ ULONG64 IoRingAddress,
    _In_ ULONG64 RegBuffersAddress,
    _In_ ULONG ViolationFlags
);

/**
 * @function   MonEtwLogIoRingHandle
 * @purpose    Log IoRing handle event (creation, duplication, spray)
 * @precondition IRQL <= DISPATCH_LEVEL
 * @side-effects Emits ETW event if provider enabled
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
MonEtwLogIoRingHandle(
    _In_ ULONG ProcessId,
    _In_ ULONG64 HandleValue,
    _In_ ULONG64 ObjectAddress,
    _In_ ULONG AccessMask,
    _In_ MON_ETW_EVENT_ID EventType
);

/**
 * @function   MonEtwLogPoolAllocation
 * @purpose    Log pool allocation of interest
 * @precondition IRQL <= DISPATCH_LEVEL
 * @side-effects Emits ETW event if provider enabled
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
MonEtwLogPoolAllocation(
    _In_ ULONG PoolTag,
    _In_ ULONG64 AllocationSize,
    _In_ ULONG64 Address,
    _In_ BOOLEAN IsNew
);

/**
 * @function   MonEtwLogDriverEvent
 * @purpose    Log driver lifecycle event
 * @precondition IRQL == PASSIVE_LEVEL
 * @side-effects Emits ETW event if provider enabled
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
MonEtwLogDriverEvent(
    _In_ MON_ETW_EVENT_ID EventId,
    _In_ ULONG Capabilities,
    _In_ ULONG WindowsBuild
);

/**
 * @function   MonEtwLogPoolSpray
 * @purpose    Log pool spray detection event
 * @precondition IRQL <= DISPATCH_LEVEL
 * @side-effects Emits ETW event if provider enabled
 *
 * @param[in] PoolTag - Pool tag that triggered detection (little-endian)
 * @param[in] TagName - Human-readable tag name (4 chars)
 * @param[in] AllocationCount - Number of allocations detected
 * @param[in] Threshold - Configured threshold that was exceeded
 * @param[in] Severity - 1-5 severity level
 * @param[in] MitreTechnique - ATT&CK technique ID (e.g., "T1068")
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
MonEtwLogPoolSpray(
    _In_ ULONG PoolTag,
    _In_ const char* TagName,
    _In_ ULONG AllocationCount,
    _In_ ULONG Threshold,
    _In_ UCHAR Severity,
    _In_ const char* MitreTechnique
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _ZIX_LABS_TELEMETRY_ETW_H_ */
