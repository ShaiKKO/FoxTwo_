/*
 * Per-Process Rate Limiting Module – Public Header
 *
 * Author: Colin MacRitchie
 * Organization: ziX Performance Labs
 * File: rate_limit.h
 * Version: 1.0
 * Date: 2025-12-01
 * Copyright:
 *   © 2025 ziX Performance Labs. All rights reserved. Proprietary and confidential.
 *   Redistribution or disclosure without prior written consent is prohibited.
 *
 * Summary
 * -------
 * Implements per-process rate limiting for telemetry events to prevent
 * flooding from malicious or misconfigured processes. Uses a sliding
 * window algorithm with hash table lookup for O(1) PID resolution.
 *
 * Algorithm
 * ---------
 * Sliding Window Counter: Combines current window count with weighted
 * previous window count for smooth rate limiting without fixed boundary
 * bursts.
 *
 * Effective Rate = PrevCount * (1 - elapsed/window) + CurrentCount
 *
 * Data Structure
 * --------------
 * Hash table with chained entries, protected by queued spinlock for
 * DISPATCH_LEVEL compatibility. Periodic cleanup removes stale entries.
 *
 * References:
 * - Sliding Window Rate Limiting: https://arpitbhayani.me/blogs/sliding-window-ratelimiter/
 * - Microsoft Queued Spin Locks: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/queued-spin-locks
 */

#ifndef _ZIX_LABS_RATE_LIMIT_H_
#define _ZIX_LABS_RATE_LIMIT_H_

#ifndef _KERNEL_MODE
# error "This header is for kernel-mode only."
#endif

#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------
 * Configuration Constants
 *-------------------------------------------------------------------------*/

/* Hash table size (power of 2 for fast modulo) */
#define MON_RATE_HASH_BUCKETS           256

/* Default per-process limit (events per second) */
#define MON_RATE_DEFAULT_PER_PROCESS    100

/* Default global limit (events per second) */
#define MON_RATE_DEFAULT_GLOBAL         1000

/* Sliding window size in milliseconds */
#define MON_RATE_WINDOW_MS              1000

/* Stale entry cleanup threshold (no activity for this many windows) */
#define MON_RATE_STALE_WINDOWS          60

/* Maximum tracked processes (prevents unbounded memory growth) */
#define MON_RATE_MAX_PROCESSES          1024

/* Maximum entries per hash bucket (DoS protection) */
#define MON_RATE_MAX_CHAIN_LENGTH       16

/* Automatic cleanup interval in milliseconds (60 seconds) */
#define MON_RATE_CLEANUP_INTERVAL_MS    60000

/*--------------------------------------------------------------------------
 * Rate Limit Check Result
 *-------------------------------------------------------------------------*/
typedef enum _MON_RATE_RESULT {
    MonRateResult_Allowed = 0,        /* Event within limit, allowed */
    MonRateResult_ProcessLimited = 1, /* Dropped due to per-process limit */
    MonRateResult_GlobalLimited = 2,  /* Dropped due to global limit */
    MonRateResult_Disabled = 3        /* Rate limiting disabled */
} MON_RATE_RESULT;

/*--------------------------------------------------------------------------
 * Statistics Structure (for IOCTL output)
 *-------------------------------------------------------------------------*/
typedef struct _MON_RATE_LIMIT_INTERNAL_STATS {
    ULONG     Size;
    ULONG     ActiveProcessCount;       /* Processes currently tracked */
    ULONG64   TotalEventsAllowed;       /* Events that passed rate limiting */
    ULONG64   TotalEventsDropped;       /* Events dropped due to rate limiting */
    ULONG64   ProcessDropCount;         /* Dropped due to per-process limit */
    ULONG64   GlobalDropCount;          /* Dropped due to global limit */
    ULONG     CurrentGlobalRate;        /* Events/sec in current window */
    ULONG     PeakGlobalRate;           /* Highest events/sec observed */
    ULONG     GlobalLimitPerSec;        /* Configured global limit */
    ULONG     PerProcessLimitPerSec;    /* Configured per-process limit */
    ULONG     HashCollisions;           /* Hash table collision count */
    ULONG     StaleEntriesRemoved;      /* Entries cleaned up */
} MON_RATE_LIMIT_INTERNAL_STATS, *PMON_RATE_LIMIT_INTERNAL_STATS;

/*--------------------------------------------------------------------------
 * Public Function Prototypes
 *-------------------------------------------------------------------------*/

/**
 * @function   MonRateLimitInitialize
 * @purpose    Initialize per-process rate limiting subsystem
 * @precondition IRQL == PASSIVE_LEVEL; Called from DriverEntry
 * @postcondition Hash table allocated, spinlock initialized
 * @thread-safety Single-threaded init
 * @side-effects Allocates hash table from NonPaged pool
 * @returns    STATUS_SUCCESS if initialization succeeded
 *             STATUS_INSUFFICIENT_RESOURCES on allocation failure
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS MonRateLimitInitialize(VOID);

/**
 * @function   MonRateLimitShutdown
 * @purpose    Clean up rate limiting subsystem
 * @precondition IRQL == PASSIVE_LEVEL; Called from DriverUnload
 * @postcondition All entries freed, hash table deallocated
 * @thread-safety Single-threaded shutdown
 * @side-effects Frees all memory
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID MonRateLimitShutdown(VOID);

/**
 * @function   MonRateLimitSetDeviceObject
 * @purpose    Set device object for work item allocation and start cleanup timer
 * @precondition IRQL == PASSIVE_LEVEL; Called after device creation
 * @postcondition Cleanup timer started if DeviceObject valid
 * @thread-safety Thread-safe
 * @side-effects Allocates work item, starts periodic timer
 *
 * @param[in] DeviceObject - Device object for IoAllocateWorkItem
 * @returns   STATUS_SUCCESS if timer started
 *            STATUS_INSUFFICIENT_RESOURCES if work item allocation failed
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS MonRateLimitSetDeviceObject(_In_ PDEVICE_OBJECT DeviceObject);

/**
 * @function   MonRateLimitEnable
 * @purpose    Enable or disable rate limiting
 * @precondition IRQL <= DISPATCH_LEVEL
 * @postcondition Rate limiting state updated
 * @thread-safety Thread-safe (atomic)
 *
 * @param[in] Enable - TRUE to enable, FALSE to disable
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID MonRateLimitEnable(_In_ BOOLEAN Enable);

/**
 * @function   MonRateLimitIsEnabled
 * @purpose    Check if rate limiting is enabled
 * @precondition IRQL <= DISPATCH_LEVEL
 * @returns    TRUE if enabled
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN MonRateLimitIsEnabled(VOID);

/**
 * @function   MonRateLimitSetLimits
 * @purpose    Configure rate limits
 * @precondition IRQL <= DISPATCH_LEVEL
 * @postcondition New limits take effect immediately
 * @thread-safety Thread-safe (atomic)
 *
 * @param[in] GlobalLimitPerSec - Global limit (0 = use default)
 * @param[in] PerProcessLimitPerSec - Per-process limit (0 = use default)
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID MonRateLimitSetLimits(
    _In_ ULONG GlobalLimitPerSec,
    _In_ ULONG PerProcessLimitPerSec
);

/**
 * @function   MonRateLimitCheckEvent
 * @purpose    Check if an event from a process should be allowed
 * @precondition IRQL <= DISPATCH_LEVEL; Subsystem initialized
 * @postcondition Counters updated, result returned
 * @thread-safety Thread-safe (spinlock protected)
 *
 * @param[in] ProcessId - Source process ID
 * @returns   MonRateResult_Allowed if event should be logged
 *            MonRateResult_ProcessLimited if per-process limit exceeded
 *            MonRateResult_GlobalLimited if global limit exceeded
 *            MonRateResult_Disabled if rate limiting is off
 *
 * Performance Notes:
 * - O(1) average case due to hash table
 * - Spinlock held for minimal duration
 * - Safe to call at DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
MON_RATE_RESULT MonRateLimitCheckEvent(_In_ ULONG ProcessId);

/**
 * @function   MonRateLimitCleanupStale
 * @purpose    Remove entries for processes with no recent activity
 * @precondition IRQL == PASSIVE_LEVEL
 * @postcondition Stale entries removed, memory reclaimed
 * @thread-safety Thread-safe (spinlock protected)
 * @side-effects May free memory
 *
 * Note: Should be called periodically (e.g., every 60 seconds)
 *       from a work item or timer callback at PASSIVE_LEVEL.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID MonRateLimitCleanupStale(VOID);

/**
 * @function   MonRateLimitGetStats
 * @purpose    Get current rate limiting statistics
 * @precondition IRQL <= DISPATCH_LEVEL
 * @postcondition Stats structure populated
 * @thread-safety Thread-safe
 *
 * @param[out] Stats - Output statistics structure
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID MonRateLimitGetStats(_Out_ PMON_RATE_LIMIT_INTERNAL_STATS Stats);

/**
 * @function   MonRateLimitResetStats
 * @purpose    Reset statistics counters
 * @precondition IRQL <= DISPATCH_LEVEL
 * @postcondition Counters zeroed
 * @thread-safety Thread-safe (atomic)
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID MonRateLimitResetStats(VOID);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _ZIX_LABS_RATE_LIMIT_H_ */
