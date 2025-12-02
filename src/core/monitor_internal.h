/*
 * Windows 11 Monitor Manager – Internal Structures & Private APIs
 *
 * Author: Colin MacRitchie | ziX Labs
 * Organization: ziX Labs — Security Research Division
 * File: monitor_internal.h
 * Version: 1.0
 * Date: 2025-11-18
 *
 * Summary
 * -------
 * Internal-only header. Encapsulates private data structures, globals, and
 * function prototypes shared across the implementation units:
 *   - win11_monitor_mgr.c  (core driver)
 *   - pool_tracker.c       (pool scanning & tag tracking)
 *   - telemetry.c          (ETW/logging subsystem; encryption stub)
 *
 * Not for public consumption or stable API exposure.
 */

#ifndef _WIN11_MONITOR_INTERNAL_H_
#define _WIN11_MONITOR_INTERNAL_H_

#ifndef _KERNEL_MODE
#error "Internal kernel header included in non-kernel build."
#endif

#include <ntddk.h>
#include <ntstrsafe.h>

#include "addr_mask.h"        /* Address masking (B2). */
#include "iop_mc.h"           /* Parser utilities for IOP_MC structures (kernel-mode only). */
#include "ioring_enum.h"      /* IoRing handle enumeration (A1). */
#include "offset_resolver.h"  /* Dynamic offset resolution (E2). */
#include "rate_limit.h"       /* Per-process rate limiting (B3). */
#include "regbuf_integrity.h" /* RegBuffers validation (A2). */
#include "telemetry_etw.h"    /* ETW TraceLogging provider (B1). */
#include "win11_monitor_mgr.h"

#ifndef _In_
#define _In_
#endif

#ifndef _In_opt_
#define _In_opt_
#endif

#ifndef _Out_
#define _Out_
#endif

#ifndef _Out_opt_
#define _Out_opt_
#endif

#ifndef _Inout_
#define _Inout_
#endif

#ifndef _In_reads_bytes_opt_
#define _In_reads_bytes_opt_(n)
#endif

#ifndef _In_range_
#define _In_range_(l, u)
#endif

#ifndef _IRQL_requires_max_
#define _IRQL_requires_max_(level)
#endif

/*---------------------------------------------------------------------------
 * Build Guards & Target
 *-------------------------------------------------------------------------*/
#if !defined(_WIN64)
#error "This driver targets x64 Windows 11 only."
#endif

/*---------------------------------------------------------------------------
 * Pool Allocation Wrappers
 *
 * ExAllocatePoolWithTag is deprecated since Windows 10 2004.
 * Use ExAllocatePool2 on modern systems, with fallback for down-level.
 * See:
 * https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/updating-deprecated-exallocatepool-calls
 *-------------------------------------------------------------------------*/
#if (NTDDI_VERSION >= NTDDI_WIN10_VB) /* Win10 2004+ */

#define MonAllocatePoolPaged(Size, Tag) ExAllocatePool2(POOL_FLAG_PAGED, (Size), (Tag))

#define MonAllocatePoolNonPaged(Size, Tag) ExAllocatePool2(POOL_FLAG_NON_PAGED, (Size), (Tag))

#define MonAllocatePoolNonPagedExecute(Size, Tag) \
  ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, (Size), (Tag))

#else /* Down-level compatibility */

/*
 * For older WDK, use the deprecated API with explicit zero-init.
 * Note: NonPagedPoolNx is the non-executable variant (security best practice).
 */
#define MonAllocatePoolPaged(Size, Tag) ExAllocatePoolWithTag(PagedPool, (Size), (Tag))

#define MonAllocatePoolNonPaged(Size, Tag) ExAllocatePoolWithTag(NonPagedPoolNx, (Size), (Tag))

#define MonAllocatePoolNonPagedExecute(Size, Tag) ExAllocatePoolWithTag(NonPagedPool, (Size), (Tag))

#endif /* NTDDI_VERSION */

/*---------------------------------------------------------------------------
 * Address Validation Macros
 *
 * MmUserProbeAddress is the boundary between user and kernel space.
 * Addresses below this value are user-mode; at or above are kernel-mode.
 *-------------------------------------------------------------------------*/
#define MON_IS_KERNEL_ADDRESS(addr) ((addr) != NULL && (ULONG_PTR)(addr) >= MmUserProbeAddress)

#define MON_IS_USER_ADDRESS(addr) ((addr) != NULL && (ULONG_PTR)(addr) < MmUserProbeAddress)

/*---------------------------------------------------------------------------
 * Memory Barrier Helpers
 *-------------------------------------------------------------------------*/
FORCEINLINE BOOLEAN MonReadBooleanAcquire(_In_ volatile BOOLEAN *Value) {
  BOOLEAN result = *Value;
  KeMemoryBarrierWithoutFence(); /* Acquire semantics - prevent reordering */
  return result;
}

FORCEINLINE VOID MonWriteBooleanRelease(_Inout_ volatile BOOLEAN *Target, _In_ BOOLEAN Value) {
  KeMemoryBarrier(); /* Release semantics - ensure prior writes visible */
  *Target = Value;
}

/*---------------------------------------------------------------------------
 * Integer Overflow Protection
 *-------------------------------------------------------------------------*/
#define MON_SAFE_ADD_ULONG(a, b, result) \
  (((a) > (ULONG_MAX - (b))) ? FALSE : (*(result) = (a) + (b), TRUE))

/*---------------------------------------------------------------------------
 * Pool Tags
 *-------------------------------------------------------------------------*/
#define MON_POOL_TAG  'nMoW' /* 'Womn' – Win11 Monitor generic */
#define MON_EVENT_TAG 'EvMW' /* Event allocation tag */
#define MON_TEL_TAG   'TeMW' /* Telemetry buffer tag */

/* Notation: IoRing Registered Buffer array tag 'IrRB' shows as 'BRrI' in dumps
 */
#define TAG_IORING_REGBUF 'BrRI' /* PoolTag 'IrRB' (endianness considerations) */

/*---------------------------------------------------------------------------
 * Policy & Limits
 *-------------------------------------------------------------------------*/
#define MON_DEFAULT_RATE_LIMIT_PER_SEC 1000u
#define MON_MAX_EVENT_BLOB_BYTES       (64u * 1024u)
#define MON_TELEMETRY_RING_MB          1u

/*---------------------------------------------------------------------------
 * Internal Event Node (queued for fetch/telemetry)
 *-------------------------------------------------------------------------*/
typedef struct _MON_EVENT_NODE {
  SLIST_ENTRY SListEntry;
  ULONG NodeSize;   /* sizeof(MON_EVENT_NODE) + PayloadBytes */
  EVENT_BLOB Event; /* Header + flexible payload */
                    /* UCHAR trailing payload ... */
} MON_EVENT_NODE, *PMON_EVENT_NODE;

/*---------------------------------------------------------------------------
 * Core Driver Context (singleton)
 *-------------------------------------------------------------------------*/
typedef struct _MONITOR_CONTEXT {
  /* Device & naming */
  PDEVICE_OBJECT DeviceObject;
  UNICODE_STRING DeviceName;
  UNICODE_STRING SymLink;

  /* State */
  volatile LONG MonitoringEnabled;
  volatile LONG TelemetryEnabled;
  volatile LONG EncryptionEnabled; /* stub */

  /* Counters (atomics) */
  volatile LONG64 TotalAllocations;
  volatile LONG64 IopMcDetections;
  volatile LONG64 CrossVmDetections;
  volatile LONG64 PolicyViolations;
  volatile LONG64 DroppedEvents;

  /* Pools & Queues */
  NPAGED_LOOKASIDE_LIST EventLookaside; /* fixed-size fast allocations */
  SLIST_HEADER EventQueue;              /* lock-free consumer queue */
  volatile LONG EventCount;

  /* Rate Limiting (simple global; per-PID optional) */
  ULONG RateLimitPerSec;
  LARGE_INTEGER RateWindowStart; /* system time (100ns) */
  volatile LONG EventsThisWindow;

  /* Telemetry ring buffer (optional, stub initially) */
  PVOID TelemetryBuffer;
  SIZE_T TelemetryBytes;

  /* Worker scheduling */
  PIO_WORKITEM ScanWorkItem;
  KTIMER ScanTimer;
  KDPC ScanDpc;
  volatile LONG ScanWorkQueued;

} MONITOR_CONTEXT, *PMONITOR_CONTEXT;

/* Global (defined in win11_monitor_mgr.c) */
extern MONITOR_CONTEXT g_Mon;

/*---------------------------------------------------------------------------
 * Private Prototypes (cross-unit)
 *-------------------------------------------------------------------------*/

/* telemetry.c */
/**
 * @function   MonTelemetryInitialize
 * @purpose    Initializes telemetry subsystem (ETW stub); pairs with Shutdown
 * @precondition IRQL <= PASSIVE_LEVEL; Ctx non-NULL
 * @postcondition STATUS_SUCCESS on init; no persistent allocations in stub
 * @thread-safety Called during init; not concurrent
 * @side-effects None (stub)
 */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS MonTelemetryInitialize(_Inout_ PMONITOR_CONTEXT Ctx);

/**
 * @function   MonTelemetryShutdown
 * @purpose    Disables telemetry and drains queued events
 * @precondition IRQL <= PASSIVE_LEVEL; Ctx non-NULL
 * @postcondition Telemetry queue drained; lookaside nodes freed
 * @thread-safety Teardown path; not concurrent with logging
 * @side-effects Updates TelemetryEnabled to 0
 */
_IRQL_requires_max_(PASSIVE_LEVEL) VOID MonTelemetryShutdown(_Inout_ PMONITOR_CONTEXT Ctx);

/**
 * @function   MonTelemetryLogBlob
 * @purpose    Rate-limited enqueue of an event blob
 * @precondition IRQL <= DISPATCH_LEVEL; PayloadLen within configured bounds
 * @postcondition Event queued or dropped; counters updated
 * @thread-safety Interlocked-only; no locks
 * @side-effects Increments EventCount or DroppedEvents
 */
_IRQL_requires_max_(DISPATCH_LEVEL) VOID
    MonTelemetryLogBlob(_In_ MONITOR_EVENT_TYPE Type,
                        _In_reads_bytes_opt_(PayloadLen) const VOID *Payload,
                        _In_range_(0, MON_MAX_EVENT_BLOB_BYTES) ULONG PayloadLen);

/* pool_tracker.c */
typedef NTSTATUS (*PFN_MON_ANALYZE_REGARRAY)(_In_ PVOID ArrayVirtualAddress,
                                             _In_ SIZE_T ArrayByteLength);

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    MonPoolTrackerInitialize(_Inout_ PMONITOR_CONTEXT Ctx, _In_ PFN_MON_ANALYZE_REGARRAY AnalyzeCb);

/**
 * @function   MonPoolTrackerShutdown
 * @purpose    Removes analysis callback and resets tracker state
 * @precondition IRQL <= PASSIVE_LEVEL; Ctx non-NULL
 * @postcondition Callback cleared
 * @thread-safety Teardown path; not concurrent with scans
 * @side-effects None
 */
_IRQL_requires_max_(PASSIVE_LEVEL) VOID MonPoolTrackerShutdown(_Inout_ PMONITOR_CONTEXT Ctx);

/**
 * @function   MonPoolScanSchedule
 * @purpose    Arm scan timer to enqueue scan work via DPC after delay
 * @precondition IRQL <= DISPATCH_LEVEL; Ctx timer/DPC initialized
 * @postcondition Timer scheduled; DPC will enqueue work if not queued
 * @thread-safety Timer/DPC synchronized by kernel
 * @side-effects Sets timer
 */
_IRQL_requires_max_(DISPATCH_LEVEL) VOID
    MonPoolScanSchedule(_Inout_ PMONITOR_CONTEXT Ctx,
                        _In_range_(1, 60 * 60 * 1000) ULONG MillisecondsDelay);

/**
 * @function   MonPoolScanNow
 * @purpose    Query big pool and analyze tag-target entries now
 * @precondition IRQL <= PASSIVE_LEVEL; Ctx non-NULL; AnalyzeCb set
 * @postcondition Invokes analysis callback for matches
 * @thread-safety Designed for single work-item execution
 * @side-effects Alloc/frees nonpaged buffer
 */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS MonPoolScanNow(_Inout_ PMONITOR_CONTEXT Ctx);

/* win11_monitor_mgr.c (analysis path) */
/**
 * @function   MonAnalyzeIoRingRegArray
 * @purpose    Validate and analyze IoRing registered buffer array
 * @precondition IRQL <= APC_LEVEL; ArrayVirtualAddress readable
 * @postcondition Telemetry and counters may be updated
 * @thread-safety Re-entrant; SEH-guarded dereferences
 * @side-effects Enqueues telemetry; increments violation/detection counters
 */
_IRQL_requires_max_(APC_LEVEL) NTSTATUS
    MonAnalyzeIoRingRegArray(_In_ PVOID ArrayVirtualAddress, _In_ SIZE_T ArrayByteLength);

/* Utility */
__forceinline BOOLEAN MonIsUserAddress(_In_ const VOID *Ptr) {
  return Ptr < MmHighestUserAddress;
}

#endif /* _WIN11_MONITOR_INTERNAL_H_ */
