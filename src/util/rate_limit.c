/*
 * Per-Process Rate Limiting Module – Implementation
 *
 * Author: Colin MacRitchie
 * Organization: ziX Performance Labs
 * File: rate_limit.c
 * Version: 1.0
 * Date: 2025-12-01
 * Copyright:
 *   © 2025 ziX Performance Labs. All rights reserved. Proprietary and
 * confidential. Redistribution or disclosure without prior written consent is
 * prohibited.
 *
 * Summary
 * -------
 * Implements sliding window rate limiting with hash table for O(1) PID lookup.
 * Uses queued spinlock for DISPATCH_LEVEL compatibility.
 */

#include "rate_limit.h"

#include <ntifs.h>

#include "monitor_internal.h"

#pragma warning(push)
#pragma warning(disable : 4201 4214)

/*--------------------------------------------------------------------------
 * Internal Structures
 *-------------------------------------------------------------------------*/

/* Per-process rate tracking entry */
typedef struct _MON_RATE_ENTRY {
  LIST_ENTRY HashLink;        /* Chain in hash bucket */
  ULONG ProcessId;            /* Tracked PID */
  ULONG CurrentWindowCount;   /* Events in current window */
  ULONG PrevWindowCount;      /* Events in previous window */
  LARGE_INTEGER WindowStart;  /* Start of current window (100ns) */
  LARGE_INTEGER LastActivity; /* Last event timestamp */
} MON_RATE_ENTRY, *PMON_RATE_ENTRY;

/* Module state */
typedef struct _MON_RATE_STATE {
  /* Hash table (array of list heads) */
  LIST_ENTRY HashBuckets[MON_RATE_HASH_BUCKETS];

  /* Bucket chain lengths for DoS protection */
  ULONG BucketChainLengths[MON_RATE_HASH_BUCKETS];

  /* Synchronization */
  KSPIN_LOCK Lock;

  /* Configuration */
  volatile LONG Enabled;
  volatile ULONG GlobalLimitPerSec;
  volatile ULONG PerProcessLimitPerSec;

  /* Global window tracking */
  ULONG GlobalCurrentCount;
  ULONG GlobalPrevCount;
  LARGE_INTEGER GlobalWindowStart;

  /* Statistics */
  volatile LONG64 TotalAllowed;
  volatile LONG64 TotalDropped;
  volatile LONG64 ProcessDrops;
  volatile LONG64 GlobalDrops;
  volatile ULONG PeakGlobalRate;
  volatile ULONG HashCollisions;
  volatile ULONG StaleRemoved;
  volatile ULONG ChainLimitHits; /* Dropped due to chain limit */
  volatile LONG ActiveProcesses;

  /* Automatic cleanup timer infrastructure */
  KTIMER CleanupTimer;
  KDPC CleanupDpc;
  PIO_WORKITEM CleanupWorkItem;
  PDEVICE_OBJECT DeviceObject;     /* For work item */
  volatile LONG CleanupWorkQueued; /* Prevent double-queue */
  volatile LONG ShuttingDown;      /* Prevent cleanup during shutdown */

  /* Initialization flag */
  BOOLEAN Initialized;
} MON_RATE_STATE, *PMON_RATE_STATE;

static MON_RATE_STATE g_RateState = {0};

/* Pool tag for rate limit entries */
#define MON_RATE_TAG 'tRMW'

/*--------------------------------------------------------------------------
 * Internal Helpers
 *-------------------------------------------------------------------------*/

/**
 * @function   MonRateHashPid
 * @purpose    Compute hash bucket index for a PID
 */
static FORCEINLINE ULONG MonRateHashPid(_In_ ULONG ProcessId) {
  /*
   * Simple multiplicative hash using golden ratio constant.
   * Good distribution for sequential PIDs.
   */
  ULONG hash = ProcessId * 2654435761UL;
  return hash & (MON_RATE_HASH_BUCKETS - 1);
}

/**
 * @function   MonRateFindEntry
 * @purpose    Find existing entry for a PID (caller holds lock)
 */
static PMON_RATE_ENTRY MonRateFindEntry(_In_ ULONG ProcessId, _In_ ULONG BucketIndex) {
  PLIST_ENTRY listHead = &g_RateState.HashBuckets[BucketIndex];
  PLIST_ENTRY entry;

  for (entry = listHead->Flink; entry != listHead; entry = entry->Flink) {
    PMON_RATE_ENTRY rateEntry = CONTAINING_RECORD(entry, MON_RATE_ENTRY, HashLink);

    if (rateEntry->ProcessId == ProcessId) {
      return rateEntry;
    }
  }

  return NULL;
}

/**
 * @function   MonRateGetCurrentTime
 * @purpose    Get current system time in 100ns units
 */
static FORCEINLINE LARGE_INTEGER MonRateGetCurrentTime(VOID) {
  LARGE_INTEGER time;
  KeQuerySystemTime(&time);
  return time;
}

/**
 * @function   MonRateGetWindowMs
 * @purpose    Get milliseconds elapsed in current window
 */
static FORCEINLINE ULONG MonRateGetWindowElapsedMs(_In_ LARGE_INTEGER WindowStart,
                                                   _In_ LARGE_INTEGER CurrentTime) {
  LONGLONG elapsed100ns = CurrentTime.QuadPart - WindowStart.QuadPart;
  if (elapsed100ns < 0) {
    return 0;
  }
  /* Convert 100ns to ms */
  return (ULONG)(elapsed100ns / 10000);
}

/**
 * @function   MonRateCalculateEffectiveCount
 * @purpose    Calculate sliding window effective count
 *
 * Sliding Window Formula:
 *   EffectiveRate = PrevCount * (1 - elapsed/window) + CurrentCount
 *
 * This smooths the rate across window boundaries.
 */
static ULONG MonRateCalculateEffectiveCount(_In_ ULONG PrevCount, _In_ ULONG CurrentCount,
                                            _In_ ULONG ElapsedMs) {
  if (ElapsedMs >= MON_RATE_WINDOW_MS) {
    /* Fully in new window */
    return CurrentCount;
  }

  /* Weight from previous window */
  ULONG prevWeight = MON_RATE_WINDOW_MS - ElapsedMs;
  ULONG weightedPrev = (PrevCount * prevWeight) / MON_RATE_WINDOW_MS;

  return weightedPrev + CurrentCount;
}

/**
 * @function   MonRateUpdateWindow
 * @purpose    Check if window needs to be rotated
 */
static VOID MonRateUpdateWindow(_Inout_ PULONG PrevCount, _Inout_ PULONG CurrentCount,
                                _Inout_ PLARGE_INTEGER WindowStart,
                                _In_ LARGE_INTEGER CurrentTime) {
  ULONG elapsedMs = MonRateGetWindowElapsedMs(*WindowStart, CurrentTime);

  if (elapsedMs >= MON_RATE_WINDOW_MS) {
    /* Rotate window */
    if (elapsedMs >= 2 * MON_RATE_WINDOW_MS) {
      /* More than 2 windows passed, reset both */
      *PrevCount = 0;
    } else {
      /* Move current to previous */
      *PrevCount = *CurrentCount;
    }
    *CurrentCount = 0;
    WindowStart->QuadPart = CurrentTime.QuadPart;
  }
}

/*--------------------------------------------------------------------------
 * Automatic Cleanup Timer Infrastructure
 *
 * Uses KTIMER + KDPC + IO_WORKITEM pattern:
 * 1. Timer fires periodically at DISPATCH_LEVEL
 * 2. DPC queues a work item to run at PASSIVE_LEVEL
 * 3. Work item calls MonRateLimitCleanupStale()
 *
 * Reference:
 * https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/timer-objects-and-dpcs
 *-------------------------------------------------------------------------*/

/**
 * @function   MonRateCleanupWorkRoutine
 * @purpose    Work item routine that performs stale entry cleanup at
 * PASSIVE_LEVEL
 * @precondition IRQL == PASSIVE_LEVEL; called by system worker thread
 */
_Function_class_(IO_WORKITEM_ROUTINE) static VOID
    MonRateCleanupWorkRoutine(_In_ PDEVICE_OBJECT DeviceObject, _In_opt_ PVOID Context) {
  UNREFERENCED_PARAMETER(DeviceObject);
  UNREFERENCED_PARAMETER(Context);

  /* Clear queued flag */
  InterlockedExchange(&g_RateState.CleanupWorkQueued, 0);

  /* Check if shutting down */
  if (InterlockedCompareExchange(&g_RateState.ShuttingDown, 0, 0) != 0) {
    return;
  }

  /* Perform the actual cleanup */
  MonRateLimitCleanupStale();
}

/**
 * @function   MonRateCleanupDpcRoutine
 * @purpose    DPC routine that queues work item for PASSIVE_LEVEL cleanup
 * @precondition IRQL == DISPATCH_LEVEL; called by timer expiration
 */
_Function_class_(KDEFERRED_ROUTINE) static VOID
    MonRateCleanupDpcRoutine(_In_ PKDPC Dpc, _In_opt_ PVOID DeferredContext,
                             _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2) {
  UNREFERENCED_PARAMETER(Dpc);
  UNREFERENCED_PARAMETER(DeferredContext);
  UNREFERENCED_PARAMETER(SystemArgument1);
  UNREFERENCED_PARAMETER(SystemArgument2);

  /* Check if shutting down or already queued */
  if (InterlockedCompareExchange(&g_RateState.ShuttingDown, 0, 0) != 0) {
    return;
  }

  if (InterlockedCompareExchange(&g_RateState.CleanupWorkQueued, 1, 0) != 0) {
    /* Work already queued, skip this cycle */
    return;
  }

  /* Queue work item for PASSIVE_LEVEL execution */
  if (g_RateState.CleanupWorkItem != NULL && g_RateState.DeviceObject != NULL) {
    IoQueueWorkItem(g_RateState.CleanupWorkItem, MonRateCleanupWorkRoutine, DelayedWorkQueue, NULL);
  } else {
    /* Reset queued flag if we couldn't queue */
    InterlockedExchange(&g_RateState.CleanupWorkQueued, 0);
  }
}

/**
 * @function   MonRateLimitStartCleanupTimer
 * @purpose    Start the automatic cleanup timer
 * @precondition Subsystem initialized, DeviceObject set
 */
static VOID MonRateLimitStartCleanupTimer(VOID) {
  if (g_RateState.CleanupWorkItem == NULL) {
    return;
  }

  /* Set periodic timer */
  LARGE_INTEGER dueTime;
  dueTime.QuadPart = -((LONGLONG)MON_RATE_CLEANUP_INTERVAL_MS * 10000LL);

  KeSetTimerEx(&g_RateState.CleanupTimer, dueTime,
               MON_RATE_CLEANUP_INTERVAL_MS, /* Periodic interval in ms */
               &g_RateState.CleanupDpc);

  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
             "[WIN11MON][RATE] Cleanup timer started (interval=%lu ms)\n",
             MON_RATE_CLEANUP_INTERVAL_MS);
}

/**
 * @function   MonRateLimitStopCleanupTimer
 * @purpose    Stop the automatic cleanup timer
 * @precondition Called during shutdown
 */
static VOID MonRateLimitStopCleanupTimer(VOID) {
  /* Signal shutdown */
  InterlockedExchange(&g_RateState.ShuttingDown, 1);

  /* Cancel the timer */
  KeCancelTimer(&g_RateState.CleanupTimer);

  /* Wait for any pending DPC to complete */
  KeFlushQueuedDpcs();

  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[WIN11MON][RATE] Cleanup timer stopped\n");
}

/*--------------------------------------------------------------------------
 * Public API Implementation
 *-------------------------------------------------------------------------*/

_Use_decl_annotations_ NTSTATUS MonRateLimitInitialize(VOID) {
  if (g_RateState.Initialized) {
    return STATUS_SUCCESS;
  }

  /* Initialize hash buckets and chain lengths */
  for (ULONG i = 0; i < MON_RATE_HASH_BUCKETS; i++) {
    InitializeListHead(&g_RateState.HashBuckets[i]);
    g_RateState.BucketChainLengths[i] = 0;
  }

  /* Initialize spinlock */
  KeInitializeSpinLock(&g_RateState.Lock);

  /* Initialize cleanup timer and DPC */
  KeInitializeTimer(&g_RateState.CleanupTimer);
  KeInitializeDpc(&g_RateState.CleanupDpc, MonRateCleanupDpcRoutine, NULL);

  /* Work item will be allocated when DeviceObject is set */
  g_RateState.CleanupWorkItem = NULL;
  g_RateState.DeviceObject = NULL;
  g_RateState.CleanupWorkQueued = 0;
  g_RateState.ShuttingDown = 0;

  /* Set defaults */
  g_RateState.GlobalLimitPerSec = MON_RATE_DEFAULT_GLOBAL;
  g_RateState.PerProcessLimitPerSec = MON_RATE_DEFAULT_PER_PROCESS;
  g_RateState.Enabled = FALSE;

  /* Initialize global window */
  g_RateState.GlobalWindowStart = MonRateGetCurrentTime();
  g_RateState.GlobalCurrentCount = 0;
  g_RateState.GlobalPrevCount = 0;

  /* Zero statistics */
  g_RateState.TotalAllowed = 0;
  g_RateState.TotalDropped = 0;
  g_RateState.ProcessDrops = 0;
  g_RateState.GlobalDrops = 0;
  g_RateState.PeakGlobalRate = 0;
  g_RateState.HashCollisions = 0;
  g_RateState.StaleRemoved = 0;
  g_RateState.ChainLimitHits = 0;
  g_RateState.ActiveProcesses = 0;

  g_RateState.Initialized = TRUE;

  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
             "[WIN11MON][RATE] Initialized (global=%lu, perproc=%lu)\n",
             g_RateState.GlobalLimitPerSec, g_RateState.PerProcessLimitPerSec);

  return STATUS_SUCCESS;
}

_Use_decl_annotations_ NTSTATUS MonRateLimitSetDeviceObject(_In_ PDEVICE_OBJECT DeviceObject) {
  if (!g_RateState.Initialized) {
    return STATUS_NOT_SUPPORTED;
  }

  if (DeviceObject == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  /* Already set? */
  if (g_RateState.DeviceObject != NULL) {
    return STATUS_SUCCESS;
  }

  g_RateState.DeviceObject = DeviceObject;

  /* Allocate work item for cleanup timer */
  g_RateState.CleanupWorkItem = IoAllocateWorkItem(DeviceObject);
  if (g_RateState.CleanupWorkItem == NULL) {
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
               "[WIN11MON][RATE] Failed to allocate cleanup work item\n");
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  /* Start the automatic cleanup timer */
  MonRateLimitStartCleanupTimer();

  return STATUS_SUCCESS;
}

_Use_decl_annotations_ VOID MonRateLimitShutdown(VOID) {
  KIRQL oldIrql;
  PLIST_ENTRY entry, next;

  if (!g_RateState.Initialized) {
    return;
  }

  /* Stop cleanup timer first (this waits for any pending DPC) */
  MonRateLimitStopCleanupTimer();

  /* Free the work item */
  if (g_RateState.CleanupWorkItem != NULL) {
    IoFreeWorkItem(g_RateState.CleanupWorkItem);
    g_RateState.CleanupWorkItem = NULL;
  }

  /* Acquire lock to prevent concurrent access during cleanup */
  KeAcquireSpinLock(&g_RateState.Lock, &oldIrql);

  /* Free all entries */
  for (ULONG i = 0; i < MON_RATE_HASH_BUCKETS; i++) {
    PLIST_ENTRY listHead = &g_RateState.HashBuckets[i];

    for (entry = listHead->Flink; entry != listHead; entry = next) {
      next = entry->Flink;
      PMON_RATE_ENTRY rateEntry = CONTAINING_RECORD(entry, MON_RATE_ENTRY, HashLink);

      RemoveEntryList(entry);
      ExFreePoolWithTag(rateEntry, MON_RATE_TAG);
    }

    g_RateState.BucketChainLengths[i] = 0;
  }

  g_RateState.ActiveProcesses = 0;
  g_RateState.DeviceObject = NULL;
  g_RateState.Initialized = FALSE;

  KeReleaseSpinLock(&g_RateState.Lock, oldIrql);

  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[WIN11MON][RATE] Shutdown complete\n");
}

_Use_decl_annotations_ VOID MonRateLimitEnable(_In_ BOOLEAN Enable) {
  InterlockedExchange(&g_RateState.Enabled, Enable ? 1 : 0);

  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[WIN11MON][RATE] %s\n",
             Enable ? "Enabled" : "Disabled");
}

_Use_decl_annotations_ BOOLEAN MonRateLimitIsEnabled(VOID) {
  return InterlockedCompareExchange(&g_RateState.Enabled, 0, 0) != 0;
}

_Use_decl_annotations_ VOID MonRateLimitSetLimits(_In_ ULONG GlobalLimitPerSec,
                                                  _In_ ULONG PerProcessLimitPerSec) {
  if (GlobalLimitPerSec == 0) {
    GlobalLimitPerSec = MON_RATE_DEFAULT_GLOBAL;
  }
  if (PerProcessLimitPerSec == 0) {
    PerProcessLimitPerSec = MON_RATE_DEFAULT_PER_PROCESS;
  }

  InterlockedExchange((volatile LONG *)&g_RateState.GlobalLimitPerSec, (LONG)GlobalLimitPerSec);
  InterlockedExchange((volatile LONG *)&g_RateState.PerProcessLimitPerSec,
                      (LONG)PerProcessLimitPerSec);

  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
             "[WIN11MON][RATE] Limits set: global=%lu, perproc=%lu\n", GlobalLimitPerSec,
             PerProcessLimitPerSec);
}

_Use_decl_annotations_ MON_RATE_RESULT MonRateLimitCheckEvent(_In_ ULONG ProcessId) {
  KIRQL oldIrql;
  MON_RATE_RESULT result = MonRateResult_Allowed;
  LARGE_INTEGER currentTime;
  ULONG bucketIndex;
  ULONG elapsedMs;
  ULONG effectiveGlobal;
  ULONG effectiveProcess;

  /* Quick check if disabled */
  if (!g_RateState.Initialized || !MonRateLimitIsEnabled()) {
    return MonRateResult_Disabled;
  }

  currentTime = MonRateGetCurrentTime();
  bucketIndex = MonRateHashPid(ProcessId);

  KeAcquireSpinLock(&g_RateState.Lock, &oldIrql);

  /* Update global window */
  MonRateUpdateWindow(&g_RateState.GlobalPrevCount, &g_RateState.GlobalCurrentCount,
                      &g_RateState.GlobalWindowStart, currentTime);

  /* Check global limit first */
  elapsedMs = MonRateGetWindowElapsedMs(g_RateState.GlobalWindowStart, currentTime);
  effectiveGlobal = MonRateCalculateEffectiveCount(g_RateState.GlobalPrevCount,
                                                   g_RateState.GlobalCurrentCount, elapsedMs);

  if (effectiveGlobal >= g_RateState.GlobalLimitPerSec) {
    result = MonRateResult_GlobalLimited;
    InterlockedIncrement64(&g_RateState.GlobalDrops);
    InterlockedIncrement64(&g_RateState.TotalDropped);
    goto Exit;
  }

  /* Find or create per-process entry */
  PMON_RATE_ENTRY entry = MonRateFindEntry(ProcessId, bucketIndex);

  if (entry == NULL) {
    /* Check if we're at max tracked processes */
    if (g_RateState.ActiveProcesses >= MON_RATE_MAX_PROCESSES) {
      /* Allow but don't track (fail open) */
      g_RateState.GlobalCurrentCount++;
      InterlockedIncrement64(&g_RateState.TotalAllowed);
      goto Exit;
    }

    /*
     * DoS Protection: Check hash chain length
     *
     * If an attacker spawns many processes with PIDs that hash to the
     * same bucket, lookup becomes O(n) and can cause latency spikes.
     * Limit chain length to prevent this attack vector.
     */
    if (g_RateState.BucketChainLengths[bucketIndex] >= MON_RATE_MAX_CHAIN_LENGTH) {
      /* Chain too long - allow but don't track (fail open) */
      InterlockedIncrement((volatile LONG *)&g_RateState.ChainLimitHits);
      g_RateState.GlobalCurrentCount++;
      InterlockedIncrement64(&g_RateState.TotalAllowed);
      goto Exit;
    }

    /* Create new entry */
    entry = (PMON_RATE_ENTRY)MonAllocatePoolNonPaged(sizeof(MON_RATE_ENTRY), MON_RATE_TAG);

    if (entry == NULL) {
      /* Allocation failed, allow event (fail open) */
      g_RateState.GlobalCurrentCount++;
      InterlockedIncrement64(&g_RateState.TotalAllowed);
      goto Exit;
    }

    /* Initialize new entry */
    entry->ProcessId = ProcessId;
    entry->CurrentWindowCount = 0;
    entry->PrevWindowCount = 0;
    entry->WindowStart = currentTime;
    entry->LastActivity = currentTime;

    /* Check for collision (for stats) */
    if (!IsListEmpty(&g_RateState.HashBuckets[bucketIndex])) {
      InterlockedIncrement((volatile LONG *)&g_RateState.HashCollisions);
    }

    /* Insert into hash table and update chain length */
    InsertHeadList(&g_RateState.HashBuckets[bucketIndex], &entry->HashLink);
    g_RateState.BucketChainLengths[bucketIndex]++;
    InterlockedIncrement(&g_RateState.ActiveProcesses);
  }

  /* Update entry's window */
  MonRateUpdateWindow(&entry->PrevWindowCount, &entry->CurrentWindowCount, &entry->WindowStart,
                      currentTime);

  /* Check per-process limit */
  elapsedMs = MonRateGetWindowElapsedMs(entry->WindowStart, currentTime);
  effectiveProcess =
      MonRateCalculateEffectiveCount(entry->PrevWindowCount, entry->CurrentWindowCount, elapsedMs);

  if (effectiveProcess >= g_RateState.PerProcessLimitPerSec) {
    result = MonRateResult_ProcessLimited;
    InterlockedIncrement64(&g_RateState.ProcessDrops);
    InterlockedIncrement64(&g_RateState.TotalDropped);
    goto Exit;
  }

  /* Event allowed - increment counters */
  entry->CurrentWindowCount++;
  entry->LastActivity = currentTime;
  g_RateState.GlobalCurrentCount++;
  InterlockedIncrement64(&g_RateState.TotalAllowed);

  /* Update peak rate */
  if (effectiveGlobal + 1 > g_RateState.PeakGlobalRate) {
    InterlockedExchange((volatile LONG *)&g_RateState.PeakGlobalRate, (LONG)(effectiveGlobal + 1));
  }

Exit:
  KeReleaseSpinLock(&g_RateState.Lock, oldIrql);
  return result;
}

_Use_decl_annotations_ VOID MonRateLimitCleanupStale(VOID) {
  KIRQL oldIrql;
  LARGE_INTEGER currentTime;
  LARGE_INTEGER staleThreshold;
  PLIST_ENTRY entry, next;
  ULONG removedCount = 0;

  if (!g_RateState.Initialized) {
    return;
  }

  currentTime = MonRateGetCurrentTime();

  /* Calculate stale threshold (no activity for N windows) */
  staleThreshold.QuadPart =
      currentTime.QuadPart - ((LONGLONG)MON_RATE_STALE_WINDOWS * MON_RATE_WINDOW_MS * 10000);

  KeAcquireSpinLock(&g_RateState.Lock, &oldIrql);

  for (ULONG i = 0; i < MON_RATE_HASH_BUCKETS; i++) {
    PLIST_ENTRY listHead = &g_RateState.HashBuckets[i];
    ULONG bucketRemoved = 0;

    for (entry = listHead->Flink; entry != listHead; entry = next) {
      next = entry->Flink;
      PMON_RATE_ENTRY rateEntry = CONTAINING_RECORD(entry, MON_RATE_ENTRY, HashLink);

      if (rateEntry->LastActivity.QuadPart < staleThreshold.QuadPart) {
        RemoveEntryList(entry);
        ExFreePoolWithTag(rateEntry, MON_RATE_TAG);
        InterlockedDecrement(&g_RateState.ActiveProcesses);
        bucketRemoved++;
        removedCount++;
      }
    }

    /* Update bucket chain length */
    if (bucketRemoved > 0 && g_RateState.BucketChainLengths[i] >= bucketRemoved) {
      g_RateState.BucketChainLengths[i] -= bucketRemoved;
    }
  }

  KeReleaseSpinLock(&g_RateState.Lock, oldIrql);

  if (removedCount > 0) {
    InterlockedAdd((volatile LONG *)&g_RateState.StaleRemoved, (LONG)removedCount);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[WIN11MON][RATE] Cleaned %lu stale entries\n", removedCount);
  }
}

_Use_decl_annotations_ VOID MonRateLimitGetStats(_Out_ PMON_RATE_LIMIT_INTERNAL_STATS Stats) {
  if (Stats == NULL) {
    return;
  }

  Stats->Size = sizeof(MON_RATE_LIMIT_INTERNAL_STATS);
  Stats->ActiveProcessCount = (ULONG)InterlockedCompareExchange(&g_RateState.ActiveProcesses, 0, 0);
  Stats->TotalEventsAllowed = InterlockedCompareExchange64(&g_RateState.TotalAllowed, 0, 0);
  Stats->TotalEventsDropped = InterlockedCompareExchange64(&g_RateState.TotalDropped, 0, 0);
  Stats->ProcessDropCount = InterlockedCompareExchange64(&g_RateState.ProcessDrops, 0, 0);
  Stats->GlobalDropCount = InterlockedCompareExchange64(&g_RateState.GlobalDrops, 0, 0);
  Stats->CurrentGlobalRate = g_RateState.GlobalCurrentCount;
  Stats->PeakGlobalRate = g_RateState.PeakGlobalRate;
  Stats->GlobalLimitPerSec = g_RateState.GlobalLimitPerSec;
  Stats->PerProcessLimitPerSec = g_RateState.PerProcessLimitPerSec;
  Stats->HashCollisions = g_RateState.HashCollisions;
  Stats->StaleEntriesRemoved = g_RateState.StaleRemoved;
}

_Use_decl_annotations_ VOID MonRateLimitResetStats(VOID) {
  InterlockedExchange64(&g_RateState.TotalAllowed, 0);
  InterlockedExchange64(&g_RateState.TotalDropped, 0);
  InterlockedExchange64(&g_RateState.ProcessDrops, 0);
  InterlockedExchange64(&g_RateState.GlobalDrops, 0);
  InterlockedExchange((volatile LONG *)&g_RateState.PeakGlobalRate, 0);
  InterlockedExchange((volatile LONG *)&g_RateState.HashCollisions, 0);
  InterlockedExchange((volatile LONG *)&g_RateState.StaleRemoved, 0);

  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[WIN11MON][RATE] Statistics reset\n");
}

#pragma warning(pop)
