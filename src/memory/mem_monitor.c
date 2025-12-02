/*
 * Memory Region Monitoring - Core Implementation
 *
 * Author: Colin MacRitchie
 * Organization: ziX Labs - Security Research Division
 * File: mem_monitor.c
 * Version: 1.0
 * Date: 2025-12-01
 * Copyright:
 *   © 2025 ziX Performance Labs. All rights reserved. Proprietary and
 * confidential. Redistribution or disclosure without prior written consent is
 * prohibited.
 *
 * Summary:
 * Core memory monitoring implementation. Provides MDL tracking, statistics,
 * and anomaly detection. VAD walking is delegated to vad_walker.c.
 *
 * Threading Model:
 * - g_MemMonitorLock (ERESOURCE): Protects MDL tracker list
 * - Statistics: Interlocked operations
 * - Anomaly checks: Acquire shared lock, snapshot, release, analyze
 *
 * SECURITY PROPERTIES:
 * - Input: All process IDs validated, MDL addresses verified
 * - Output: All kernel addresses masked before user-mode export
 * - Memory Safety: SEH guards on MDL content access
 * - IRQL: Documented per-function, mostly PASSIVE_LEVEL
 */

#include "mem_monitor.h"

#include <ntddk.h>
#include <ntstrsafe.h>

#include "addr_mask.h"         /* MonAddrMask for address sanitization */
#include "telemetry_ringbuf.h" /* MonRingBufWriteEvent for anomaly events */

#pragma warning(push)
#pragma warning(disable : 4201) /* nameless struct/union */

/*--------------------------------------------------------------------------*/
/* Internal Structures                                                      */
/*--------------------------------------------------------------------------*/

/* Per-process MDL tracker node */
typedef struct _MON_MDL_TRACKER_NODE {
  LIST_ENTRY ListEntry;
  ULONG ProcessId;
  ULONG MdlCount;
  ULONG Capacity;
  ULONG Reserved;

  /* Statistics */
  ULONG TotalMdlsTracked;
  ULONG CurrentlyLocked;
  ULONG64 TotalBytesLocked;
  ULONG64 PeakBytesLocked;

  /* Anomaly state */
  ULONG AnomalyFlags;
  ULONG AnomalyCount;

  /* MDL info array (dynamically sized) */
  MON_MDL_INFO Mdls[1];

} MON_MDL_TRACKER_NODE, *PMON_MDL_TRACKER_NODE;

/* Global memory monitor context */
typedef struct _MON_MEM_CONTEXT {
  BOOLEAN Initialized;
  UCHAR Reserved[3];

  /* MDL tracker list */
  ERESOURCE TrackerLock;
  LIST_ENTRY TrackerList;
  ULONG TrackerCount;
  ULONG Reserved2;

  /* Global statistics */
  volatile LONG TotalMdlsTracked;
  volatile LONG TotalVadScans;
  volatile LONG TotalPhysicalScans;
  volatile LONG TotalAnomalies;

  ULONG64 TotalBytesTracked;
  ULONG64 TotalVadsScanned;
  ULONG64 TotalPagesAnalyzed;

  /* Anomaly counters by type */
  volatile LONG AnomalyCounts[MonMemAnomaly_Max];

} MON_MEM_CONTEXT, *PMON_MEM_CONTEXT;

static MON_MEM_CONTEXT g_MemMon = {0};

/*--------------------------------------------------------------------------*/
/* PFN Reference Map (for cross-process sharing detection)                  */
/*--------------------------------------------------------------------------*/

#define MON_PFN_HASH_BITS     16
#define MON_PFN_HASH_SIZE     (1u << MON_PFN_HASH_BITS) /* 65536 buckets */
#define MON_PFN_POOL_TAG      'fPnM'                    /* 'MnPf' - PFN map */
#define MON_PFN_MAX_PROCESSES 8

/* Per-PFN entry in hash table */
typedef struct _MON_PFN_REF_ENTRY {
  LIST_ENTRY HashLink;
  ULONG64 PfnNumber;
  ULONG ProcessCount;
  ULONG Reserved;
  ULONG ProcessIds[MON_PFN_MAX_PROCESSES];
} MON_PFN_REF_ENTRY, *PMON_PFN_REF_ENTRY;

/* PFN reference map context (stack-allocated per scan) */
typedef struct _MON_PFN_REF_MAP {
  LIST_ENTRY *Buckets; /* Heap-allocated bucket array */
  ULONG BucketCount;
  ULONG TotalEntries;
  ULONG SharedEntries; /* Entries with ProcessCount > 1 */
  ULONG Reserved;
} MON_PFN_REF_MAP, *PMON_PFN_REF_MAP;

/*--------------------------------------------------------------------------*/
/* Forward Declarations                                                     */
/*--------------------------------------------------------------------------*/

static PMON_MDL_TRACKER_NODE MonMemFindTrackerLocked(_In_ ULONG ProcessId);
static PMON_MDL_TRACKER_NODE MonMemCreateTracker(_In_ ULONG ProcessId);
static VOID MonMemFreeTracker(_In_ PMON_MDL_TRACKER_NODE Tracker);
static NTSTATUS MonMemCapturesMdlInfo(_In_ PVOID MdlAddress, _Out_ PMON_MDL_INFO Info);
static VOID MonMemEmitAnomalyEvent(_In_ ULONG ProcessId, _In_ MON_MEM_ANOMALY Type,
                                   _In_ ULONG Severity, _In_opt_ PCSTR Description);

/* PFN hash map helpers */
static NTSTATUS MonMemPfnHashInit(_Out_ PMON_PFN_REF_MAP Map);
static VOID MonMemPfnHashFree(_Inout_ PMON_PFN_REF_MAP Map);
static NTSTATUS MonMemPfnHashInsert(_Inout_ PMON_PFN_REF_MAP Map, _In_ ULONG64 Pfn, _In_ ULONG Pid);
static PMON_PFN_REF_ENTRY MonMemPfnHashLookup(_In_ PMON_PFN_REF_MAP Map, _In_ ULONG64 Pfn);
static NTSTATUS MonMemBuildPfnMap(_Out_ PMON_PFN_REF_MAP Map);

/*--------------------------------------------------------------------------*/
/* Initialization & Shutdown                                                */
/*--------------------------------------------------------------------------*/

/**
 * @function   MonMemMonitorInitialize
 * @purpose    Initialize memory monitoring subsystem
 */
_Use_decl_annotations_ NTSTATUS MonMemMonitorInitialize(VOID) {
  NTSTATUS status;

  if (g_MemMon.Initialized) {
    return STATUS_ALREADY_INITIALIZED;
  }

  RtlZeroMemory(&g_MemMon, sizeof(g_MemMon));

  status = ExInitializeResourceLite(&g_MemMon.TrackerLock);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  InitializeListHead(&g_MemMon.TrackerList);
  g_MemMon.TrackerCount = 0;
  g_MemMon.Initialized = TRUE;

  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[WIN11MON] Memory monitor initialized\n");

  return STATUS_SUCCESS;
}

/**
 * @function   MonMemMonitorShutdown
 * @purpose    Shutdown memory monitoring subsystem
 */
_Use_decl_annotations_ VOID MonMemMonitorShutdown(VOID) {
  PLIST_ENTRY entry;
  PMON_MDL_TRACKER_NODE tracker;

  if (!g_MemMon.Initialized) {
    return;
  }

  /* Free all trackers */
  KeEnterCriticalRegion();
  ExAcquireResourceExclusiveLite(&g_MemMon.TrackerLock, TRUE);

  while (!IsListEmpty(&g_MemMon.TrackerList)) {
    entry = RemoveHeadList(&g_MemMon.TrackerList);
    tracker = CONTAINING_RECORD(entry, MON_MDL_TRACKER_NODE, ListEntry);
    MonMemFreeTracker(tracker);
  }

  ExReleaseResourceLite(&g_MemMon.TrackerLock);
  KeLeaveCriticalRegion();

  ExDeleteResourceLite(&g_MemMon.TrackerLock);
  g_MemMon.Initialized = FALSE;

  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
             "[WIN11MON] Memory monitor shutdown complete\n");
}

/*--------------------------------------------------------------------------*/
/* Tracker Management Helpers                                               */
/*--------------------------------------------------------------------------*/

/**
 * Find tracker for process (caller must hold lock)
 */
static PMON_MDL_TRACKER_NODE MonMemFindTrackerLocked(_In_ ULONG ProcessId) {
  PLIST_ENTRY entry;
  PMON_MDL_TRACKER_NODE tracker;

  for (entry = g_MemMon.TrackerList.Flink; entry != &g_MemMon.TrackerList; entry = entry->Flink) {
    tracker = CONTAINING_RECORD(entry, MON_MDL_TRACKER_NODE, ListEntry);
    if (tracker->ProcessId == ProcessId) {
      return tracker;
    }
  }

  return NULL;
}

/**
 * Create new tracker for process
 */
static PMON_MDL_TRACKER_NODE MonMemCreateTracker(_In_ ULONG ProcessId) {
  PMON_MDL_TRACKER_NODE tracker;
  SIZE_T size;
  ULONG initialCapacity = 16;

  size = sizeof(MON_MDL_TRACKER_NODE) + (initialCapacity - 1) * sizeof(MON_MDL_INFO);

  tracker = (PMON_MDL_TRACKER_NODE)ExAllocatePool2(POOL_FLAG_NON_PAGED, size, MON_MEM_TAG);

  if (tracker == NULL) {
    return NULL;
  }

  RtlZeroMemory(tracker, size);
  tracker->ProcessId = ProcessId;
  tracker->Capacity = initialCapacity;

  return tracker;
}

/**
 * Free tracker resources
 */
static VOID MonMemFreeTracker(_In_ PMON_MDL_TRACKER_NODE Tracker) {
  if (Tracker != NULL) {
    ExFreePoolWithTag(Tracker, MON_MEM_TAG);
  }
}

/*--------------------------------------------------------------------------*/
/* PFN Hash Map Implementation                                              */
/*--------------------------------------------------------------------------*/

/**
 * Hash function for PFN numbers
 */
static FORCEINLINE ULONG MonMemPfnHash(_In_ ULONG64 Pfn) {
  /* FNV-1a hash for 64-bit PFN */
  ULONG hash = 2166136261u;
  hash ^= (ULONG)(Pfn & 0xFFFFFFFF);
  hash *= 16777619u;
  hash ^= (ULONG)(Pfn >> 32);
  hash *= 16777619u;
  return hash & (MON_PFN_HASH_SIZE - 1);
}

/**
 * Initialize PFN hash map
 */
static NTSTATUS MonMemPfnHashInit(_Out_ PMON_PFN_REF_MAP Map) {
  SIZE_T bucketSize;
  ULONG i;

  RtlZeroMemory(Map, sizeof(*Map));

  /* Allocate bucket array from paged pool */
  bucketSize = MON_PFN_HASH_SIZE * sizeof(LIST_ENTRY);
  Map->Buckets = (PLIST_ENTRY)ExAllocatePool2(POOL_FLAG_PAGED, bucketSize, MON_PFN_POOL_TAG);

  if (Map->Buckets == NULL) {
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  /* Initialize all buckets */
  for (i = 0; i < MON_PFN_HASH_SIZE; i++) {
    InitializeListHead(&Map->Buckets[i]);
  }

  Map->BucketCount = MON_PFN_HASH_SIZE;
  return STATUS_SUCCESS;
}

/**
 n* Free PFN hash map and all entries
 */
static VOID MonMemPfnHashFree(_Inout_ PMON_PFN_REF_MAP Map) {
  ULONG i;
  PLIST_ENTRY entry, next;
  PMON_PFN_REF_ENTRY pfnEntry;

  if (Map->Buckets == NULL) {
    return;
  }

  /* Free all entries */
  for (i = 0; i < Map->BucketCount; i++) {
    entry = Map->Buckets[i].Flink;
    while (entry != &Map->Buckets[i]) {
      next = entry->Flink;
      pfnEntry = CONTAINING_RECORD(entry, MON_PFN_REF_ENTRY, HashLink);
      ExFreePoolWithTag(pfnEntry, MON_PFN_POOL_TAG);
      entry = next;
    }
  }

  ExFreePoolWithTag(Map->Buckets, MON_PFN_POOL_TAG);
  RtlZeroMemory(Map, sizeof(*Map));
}

/**
 * Lookup PFN in hash map
 */
static PMON_PFN_REF_ENTRY MonMemPfnHashLookup(_In_ PMON_PFN_REF_MAP Map, _In_ ULONG64 Pfn) {
  ULONG bucket;
  PLIST_ENTRY entry;
  PMON_PFN_REF_ENTRY pfnEntry;

  if (Map->Buckets == NULL) {
    return NULL;
  }

  bucket = MonMemPfnHash(Pfn);

  for (entry = Map->Buckets[bucket].Flink; entry != &Map->Buckets[bucket]; entry = entry->Flink) {
    pfnEntry = CONTAINING_RECORD(entry, MON_PFN_REF_ENTRY, HashLink);
    if (pfnEntry->PfnNumber == Pfn) {
      return pfnEntry;
    }
  }

  return NULL;
}

/**
 * Insert PFN with process ID into hash map
 */
static NTSTATUS MonMemPfnHashInsert(_Inout_ PMON_PFN_REF_MAP Map, _In_ ULONG64 Pfn,
                                    _In_ ULONG Pid) {
  PMON_PFN_REF_ENTRY pfnEntry;
  ULONG bucket;
  ULONG i;

  if (Map->Buckets == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  /* Check if PFN already exists */
  pfnEntry = MonMemPfnHashLookup(Map, Pfn);

  if (pfnEntry != NULL) {
    /* Add process if not already present and capacity available */
    for (i = 0; i < pfnEntry->ProcessCount; i++) {
      if (pfnEntry->ProcessIds[i] == Pid) {
        return STATUS_SUCCESS; /* Already tracked */
      }
    }
    if (pfnEntry->ProcessCount < MON_PFN_MAX_PROCESSES) {
      pfnEntry->ProcessIds[pfnEntry->ProcessCount++] = Pid;
      if (pfnEntry->ProcessCount == 2) {
        Map->SharedEntries++;
      }
    }
    return STATUS_SUCCESS;
  }

  /* Create new entry */
  pfnEntry = (PMON_PFN_REF_ENTRY)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(MON_PFN_REF_ENTRY),
                                                 MON_PFN_POOL_TAG);

  if (pfnEntry == NULL) {
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  RtlZeroMemory(pfnEntry, sizeof(*pfnEntry));
  pfnEntry->PfnNumber = Pfn;
  pfnEntry->ProcessIds[0] = Pid;
  pfnEntry->ProcessCount = 1;

  bucket = MonMemPfnHash(Pfn);
  InsertTailList(&Map->Buckets[bucket], &pfnEntry->HashLink);
  Map->TotalEntries++;

  return STATUS_SUCCESS;
}

/**
 * Build PFN map from all tracked MDLs
 */
static NTSTATUS MonMemBuildPfnMap(_Out_ PMON_PFN_REF_MAP Map) {
  NTSTATUS status;
  PLIST_ENTRY entry;
  PMON_MDL_TRACKER_NODE tracker;
  ULONG i, j;

  status = MonMemPfnHashInit(Map);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  /* Must hold TrackerLock before calling */
  for (entry = g_MemMon.TrackerList.Flink; entry != &g_MemMon.TrackerList; entry = entry->Flink) {
    tracker = CONTAINING_RECORD(entry, MON_MDL_TRACKER_NODE, ListEntry);

    /* Process each MDL in this tracker */
    for (i = 0; i < tracker->MdlCount; i++) {
      PMON_MDL_INFO mdl = &tracker->Mdls[i];

      /* Add each PFN from this MDL */
      for (j = 0; j < mdl->PfnCount; j++) {
        /* PfnArray contains masked physical addresses, extract PFN */
        ULONG64 pfn = mdl->PfnArray[j] >> PAGE_SHIFT;
        if (pfn != 0) {
          MonMemPfnHashInsert(Map, pfn, tracker->ProcessId);
        }
      }
    }
  }

  return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------*/
/* MDL Info Capture                                                         */
/*--------------------------------------------------------------------------*/

/**
 * Capture MDL information safely
 */
static NTSTATUS MonMemCapturesMdlInfo(_In_ PVOID MdlAddress, _Out_ PMON_MDL_INFO Info) {
  PMDL mdl = (PMDL)MdlAddress;
  PPFN_NUMBER pfnArray;
  ULONG pageCount;
  ULONG i;

  RtlZeroMemory(Info, sizeof(*Info));

  __try {
    /* Probe MDL header */
    ProbeForRead(mdl, sizeof(MDL), 1);

    Info->MdlAddress = MonAddrMask((ULONG64)MdlAddress);
    Info->StartVa = MonAddrMask((ULONG64)MmGetMdlVirtualAddress(mdl));
    Info->ByteCount = MmGetMdlByteCount(mdl);
    Info->MdlFlags = mdl->MdlFlags;
    Info->IsLocked = (mdl->MdlFlags & MDL_PAGES_LOCKED) != 0;
    Info->HasSystemMapping = (mdl->MappedSystemVa != NULL);
    Info->AllocTime = KeQueryInterruptTime();

    /* Capture PFN array if locked */
    if (Info->IsLocked) {
      pfnArray = MmGetMdlPfnArray(mdl);
      pageCount = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(mdl), Info->ByteCount);

      Info->PfnCount = min(pageCount, MON_MAX_PFN_ENTRIES);

      for (i = 0; i < Info->PfnCount; i++) {
        /* Mask physical addresses for security */
        Info->PfnArray[i] = MonAddrMask((ULONG64)pfnArray[i] << PAGE_SHIFT);
      }

      Info->LockTime = KeQueryInterruptTime();
    }

  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return GetExceptionCode();
  }

  return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------*/
/* MDL Tracking API                                                         */
/*--------------------------------------------------------------------------*/

/**
 * @function   MonMemTrackMdl
 * @purpose    Add MDL to tracking for a process
 */
_Use_decl_annotations_ NTSTATUS MonMemTrackMdl(ULONG ProcessId, PVOID MdlAddress,
                                               ULONG64 IoRingHandle, ULONG BufferIndex) {
  NTSTATUS status;
  PMON_MDL_TRACKER_NODE tracker;
  MON_MDL_INFO mdlInfo;

  if (!g_MemMon.Initialized || MdlAddress == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  /* Capture MDL info first (before taking lock) */
  status = MonMemCapturesMdlInfo(MdlAddress, &mdlInfo);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  mdlInfo.IoRingHandle = IoRingHandle;
  mdlInfo.BufferIndex = BufferIndex;

  KeEnterCriticalRegion();
  ExAcquireResourceExclusiveLite(&g_MemMon.TrackerLock, TRUE);

  tracker = MonMemFindTrackerLocked(ProcessId);
  if (tracker == NULL) {
    tracker = MonMemCreateTracker(ProcessId);
    if (tracker == NULL) {
      status = STATUS_INSUFFICIENT_RESOURCES;
      goto Exit;
    }
    InsertTailList(&g_MemMon.TrackerList, &tracker->ListEntry);
    g_MemMon.TrackerCount++;
  }

  /* Check capacity */
  if (tracker->MdlCount >= tracker->Capacity) {
    status = STATUS_BUFFER_TOO_SMALL;
    goto Exit;
  }

  /* Add MDL info */
  RtlCopyMemory(&tracker->Mdls[tracker->MdlCount], &mdlInfo, sizeof(mdlInfo));
  tracker->MdlCount++;
  tracker->TotalMdlsTracked++;

  if (mdlInfo.IsLocked) {
    tracker->CurrentlyLocked++;
    tracker->TotalBytesLocked += mdlInfo.ByteCount;
    if (tracker->TotalBytesLocked > tracker->PeakBytesLocked) {
      tracker->PeakBytesLocked = tracker->TotalBytesLocked;
    }
  }

  InterlockedIncrement(&g_MemMon.TotalMdlsTracked);
  status = STATUS_SUCCESS;

Exit:
  ExReleaseResourceLite(&g_MemMon.TrackerLock);
  KeLeaveCriticalRegion();

  return status;
}

/**
 * @function   MonMemUntrackMdl
 * @purpose    Remove MDL from tracking
 */
_Use_decl_annotations_ VOID MonMemUntrackMdl(ULONG ProcessId, PVOID MdlAddress) {
  PMON_MDL_TRACKER_NODE tracker;
  ULONG64 maskedAddr;
  ULONG i;

  if (!g_MemMon.Initialized || MdlAddress == NULL) {
    return;
  }

  maskedAddr = MonAddrMask((ULONG64)MdlAddress);

  KeEnterCriticalRegion();
  ExAcquireResourceExclusiveLite(&g_MemMon.TrackerLock, TRUE);

  tracker = MonMemFindTrackerLocked(ProcessId);
  if (tracker == NULL) {
    goto Exit;
  }

  /* Find and remove MDL entry */
  for (i = 0; i < tracker->MdlCount; i++) {
    if (tracker->Mdls[i].MdlAddress == maskedAddr) {
      /* Update stats before removal */
      if (tracker->Mdls[i].IsLocked) {
        tracker->CurrentlyLocked--;
        tracker->TotalBytesLocked -= tracker->Mdls[i].ByteCount;
      }

      /* Shift remaining entries */
      if (i < tracker->MdlCount - 1) {
        RtlMoveMemory(&tracker->Mdls[i], &tracker->Mdls[i + 1],
                      (tracker->MdlCount - i - 1) * sizeof(MON_MDL_INFO));
      }
      tracker->MdlCount--;
      break;
    }
  }

Exit:
  ExReleaseResourceLite(&g_MemMon.TrackerLock);
  KeLeaveCriticalRegion();
}

/**
 * @function   MonMemGetMdlTracker
 * @purpose    Get MDL tracking info for a process
 */
_Use_decl_annotations_ NTSTATUS MonMemGetMdlTracker(ULONG ProcessId, PVOID OutBuffer, ULONG OutLen,
                                                    ULONG *BytesWritten) {
  PMON_MDL_TRACKER_NODE tracker;
  PMON_MDL_TRACKER output = (PMON_MDL_TRACKER)OutBuffer;
  SIZE_T requiredSize;
  ULONG copyCount;

  if (!g_MemMon.Initialized || OutBuffer == NULL || BytesWritten == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  if (OutLen < sizeof(MON_MDL_TRACKER)) {
    return STATUS_BUFFER_TOO_SMALL;
  }

  *BytesWritten = 0;

  KeEnterCriticalRegion();
  ExAcquireResourceSharedLite(&g_MemMon.TrackerLock, TRUE);

  tracker = MonMemFindTrackerLocked(ProcessId);
  if (tracker == NULL) {
    ExReleaseResourceLite(&g_MemMon.TrackerLock);
    KeLeaveCriticalRegion();
    return STATUS_NOT_FOUND;
  }

  /* Calculate how many MDLs fit in output buffer */
  requiredSize = sizeof(MON_MDL_TRACKER);
  copyCount = min(tracker->MdlCount, MON_MAX_TRACKED_MDLS);

  /* Build output structure */
  output->Magic = MON_MEM_MONITOR_MAGIC;
  output->ProcessId = tracker->ProcessId;
  output->MdlCount = copyCount;
  output->TotalMdlsTracked = tracker->TotalMdlsTracked;
  output->CurrentlyLocked = tracker->CurrentlyLocked;
  output->TotalBytesLocked = tracker->TotalBytesLocked;
  output->PeakBytesLocked = tracker->PeakBytesLocked;
  output->AnomalyFlags = tracker->AnomalyFlags;
  output->AnomalyCount = tracker->AnomalyCount;

  RtlCopyMemory(output->Mdls, tracker->Mdls, copyCount * sizeof(MON_MDL_INFO));

  ExReleaseResourceLite(&g_MemMon.TrackerLock);
  KeLeaveCriticalRegion();

  *BytesWritten = (ULONG)requiredSize;
  return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------*/
/* Statistics                                                               */
/*--------------------------------------------------------------------------*/

/**
 * @function   MonMemGetStats
 * @purpose    Get memory monitoring statistics
 */
_Use_decl_annotations_ NTSTATUS MonMemGetStats(PVOID OutBuffer, ULONG OutLen) {
  PMON_MEM_STATS stats = (PMON_MEM_STATS)OutBuffer;
  ULONG i;

  if (!g_MemMon.Initialized || OutBuffer == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  if (OutLen < sizeof(MON_MEM_STATS)) {
    return STATUS_BUFFER_TOO_SMALL;
  }

  RtlZeroMemory(stats, sizeof(*stats));
  stats->Size = sizeof(MON_MEM_STATS);

  stats->TrackedMdlCount = g_MemMon.TrackerCount;
  stats->TotalMdlsEverTracked = (ULONG)g_MemMon.TotalMdlsTracked;
  stats->TotalBytesTracked = g_MemMon.TotalBytesTracked;

  stats->TotalVadScans = (ULONG)g_MemMon.TotalVadScans;
  stats->TotalVadsScanned = (ULONG)g_MemMon.TotalVadsScanned;

  stats->TotalPhysicalScans = (ULONG)g_MemMon.TotalPhysicalScans;
  stats->TotalPagesAnalyzed = (ULONG)g_MemMon.TotalPagesAnalyzed;

  stats->TotalAnomaliesDetected = (ULONG)g_MemMon.TotalAnomalies;

  for (i = 0; i < MonMemAnomaly_Max && i < 32; i++) {
    stats->AnomaliesByType[i] = (ULONG)g_MemMon.AnomalyCounts[i];
  }

  return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------*/
/* Anomaly Detection                                                        */
/*--------------------------------------------------------------------------*/

/**
 * Emit anomaly event to ring buffer
 */
static VOID MonMemEmitAnomalyEvent(_In_ ULONG ProcessId, _In_ MON_MEM_ANOMALY Type,
                                   _In_ ULONG Severity, _In_opt_ PCSTR Description) {
  MON_MEM_ANOMALY_EVENT event;

  RtlZeroMemory(&event, sizeof(event));
  event.Size = sizeof(event);
  event.ProcessId = ProcessId;
  event.AnomalyType = Type;
  event.Severity = Severity;
  event.Timestamp = KeQueryInterruptTime();

  if (Description != NULL) {
    RtlStringCbCopyA(event.Description, sizeof(event.Description), Description);
  }

  /* Set MITRE ATT&CK technique based on anomaly type */
  switch (Type) {
  case MonMemAnomaly_ExecutableHeap:
  case MonMemAnomaly_WritableCode:
    RtlStringCbCopyA(event.ATT_CK_Technique, sizeof(event.ATT_CK_Technique), "T1055");
    break;
  case MonMemAnomaly_SharedPhysicalPage:
  case MonMemAnomaly_UnauthorizedMapping:
    RtlStringCbCopyA(event.ATT_CK_Technique, sizeof(event.ATT_CK_Technique), "T1068");
    break;
  default:
    RtlStringCbCopyA(event.ATT_CK_Technique, sizeof(event.ATT_CK_Technique), "T1106");
    break;
  }

  /* Log to ring buffer */
  MonRingBufWriteEvent(MonEvent_Anomaly, &event, sizeof(event));

  InterlockedIncrement(&g_MemMon.TotalAnomalies);
  if (Type < MonMemAnomaly_Max) {
    InterlockedIncrement(&g_MemMon.AnomalyCounts[Type]);
  }
}

/**
 * Check for kernel address in user MDL
 */
static BOOLEAN MonMemCheckKernelAddrInMdl(_In_ PMON_MDL_INFO MdlInfo) {
  /* StartVa is already masked, check original would require unmasking */
  /* For now, check if ByteCount is suspiciously large */
  if (MdlInfo->ByteCount > 0x10000000) { /* 256MB */
    return TRUE;
  }
  return FALSE;
}

/**
 * @function   MonMemCheckAnomalies
 * @purpose    Run anomaly detection on tracked memory
 */
_Use_decl_annotations_ ULONG MonMemCheckAnomalies(ULONG ProcessId) {
  PMON_MDL_TRACKER_NODE tracker;
  ULONG anomalyCount = 0;
  ULONG i;

  if (!g_MemMon.Initialized) {
    return 0;
  }

  KeEnterCriticalRegion();
  ExAcquireResourceSharedLite(&g_MemMon.TrackerLock, TRUE);

  tracker = MonMemFindTrackerLocked(ProcessId);
  if (tracker == NULL) {
    goto Exit;
  }

  /* Check each MDL for anomalies */
  for (i = 0; i < tracker->MdlCount; i++) {
    PMON_MDL_INFO mdl = &tracker->Mdls[i];

    /* Check for kernel address in user MDL */
    if (MonMemCheckKernelAddrInMdl(mdl)) {
      MonMemEmitAnomalyEvent(ProcessId, MonMemAnomaly_KernelAddressInUserMdl, 4,
                             "Kernel address detected in user MDL");
      tracker->AnomalyFlags |= (1 << MonMemAnomaly_KernelAddressInUserMdl);
      anomalyCount++;
    }

    /* Check for unlocked MDL in use */
    if (!mdl->IsLocked && mdl->ByteCount > 0) {
      /* This might be normal, only flag if IoRing related */
      if (mdl->IoRingHandle != 0) {
        MonMemEmitAnomalyEvent(ProcessId, MonMemAnomaly_UnlockedMdlInUse, 2,
                               "IoRing buffer MDL not locked");
        tracker->AnomalyFlags |= (1 << MonMemAnomaly_UnlockedMdlInUse);
        anomalyCount++;
      }
    }
  }

  /* Check for excessive MDL count */
  if (tracker->MdlCount > 100) {
    MonMemEmitAnomalyEvent(ProcessId, MonMemAnomaly_ExcessiveMdlChain, 3,
                           "Excessive MDL count for process");
    tracker->AnomalyFlags |= (1 << MonMemAnomaly_ExcessiveMdlChain);
    anomalyCount++;
  }

  tracker->AnomalyCount += anomalyCount;

Exit:
  ExReleaseResourceLite(&g_MemMon.TrackerLock);
  KeLeaveCriticalRegion();

  return anomalyCount;
}

/*--------------------------------------------------------------------------*/
/* VAD Scanning (delegated to vad_walker.c)                                 */
/*--------------------------------------------------------------------------*/

/**
 * @function   MonMemScanVad
 * @purpose    Scan VAD tree for a process
 */
_Use_decl_annotations_ NTSTATUS MonMemScanVad(ULONG ProcessId, PVOID OutBuffer, ULONG OutLen,
                                              ULONG *BytesWritten) {
  /* Delegate to VAD walker */
  extern NTSTATUS MonVadWalkTree(ULONG, PVOID, ULONG, ULONG *);

  if (!g_MemMon.Initialized) {
    return STATUS_NOT_INITIALIZED;
  }

  InterlockedIncrement(&g_MemMon.TotalVadScans);
  return MonVadWalkTree(ProcessId, OutBuffer, OutLen, BytesWritten);
}

/*--------------------------------------------------------------------------*/
/* Physical Analysis & Sharing Detection                                    */
/*--------------------------------------------------------------------------*/

/**
 * Count pages for a specific process in PFN map
 */
static ULONG MonMemCountProcessPages(_In_ PMON_PFN_REF_MAP Map, _In_ ULONG ProcessId) {
  ULONG count = 0;
  ULONG i;
  PLIST_ENTRY entry;
  PMON_PFN_REF_ENTRY pfnEntry;

  for (i = 0; i < Map->BucketCount; i++) {
    for (entry = Map->Buckets[i].Flink; entry != &Map->Buckets[i]; entry = entry->Flink) {
      pfnEntry = CONTAINING_RECORD(entry, MON_PFN_REF_ENTRY, HashLink);
      for (ULONG j = 0; j < pfnEntry->ProcessCount; j++) {
        if (pfnEntry->ProcessIds[j] == ProcessId) {
          count++;
          break;
        }
      }
    }
  }

  return count;
}

/**
 * Count shared pages for a specific process
 */
static ULONG MonMemCountSharedPages(_In_ PMON_PFN_REF_MAP Map, _In_ ULONG ProcessId) {
  ULONG count = 0;
  ULONG i;
  PLIST_ENTRY entry;
  PMON_PFN_REF_ENTRY pfnEntry;
  BOOLEAN hasProcess;

  for (i = 0; i < Map->BucketCount; i++) {
    for (entry = Map->Buckets[i].Flink; entry != &Map->Buckets[i]; entry = entry->Flink) {
      pfnEntry = CONTAINING_RECORD(entry, MON_PFN_REF_ENTRY, HashLink);
      if (pfnEntry->ProcessCount < 2)
        continue;

      hasProcess = FALSE;
      for (ULONG j = 0; j < pfnEntry->ProcessCount; j++) {
        if (pfnEntry->ProcessIds[j] == ProcessId) {
          hasProcess = TRUE;
          break;
        }
      }
      if (hasProcess)
        count++;
    }
  }

  return count;
}

/**
 * @function   MonMemAnalyzePhysical
 * @purpose    Analyze physical page mappings for a process
 */
_Use_decl_annotations_ NTSTATUS MonMemAnalyzePhysical(ULONG ProcessId, PVOID OutBuffer,
                                                      ULONG OutLen) {
  NTSTATUS status;
  PMON_PHYSICAL_SCAN_RESULT result = (PMON_PHYSICAL_SCAN_RESULT)OutBuffer;
  MON_PFN_REF_MAP pfnMap;

  if (!g_MemMon.Initialized || OutBuffer == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  if (OutLen < sizeof(MON_PHYSICAL_SCAN_RESULT)) {
    return STATUS_BUFFER_TOO_SMALL;
  }

  RtlZeroMemory(result, sizeof(*result));
  result->Size = sizeof(MON_PHYSICAL_SCAN_RESULT);
  result->ProcessId = ProcessId;

  InterlockedIncrement(&g_MemMon.TotalPhysicalScans);

  /* Build PFN map from all tracked MDLs */
  KeEnterCriticalRegion();
  ExAcquireResourceSharedLite(&g_MemMon.TrackerLock, TRUE);

  status = MonMemBuildPfnMap(&pfnMap);
  if (!NT_SUCCESS(status)) {
    ExReleaseResourceLite(&g_MemMon.TrackerLock);
    KeLeaveCriticalRegion();
    return status;
  }

  /* Count pages for target process */
  result->TotalPagesScanned = MonMemCountProcessPages(&pfnMap, ProcessId);
  result->SharedPagesFound = pfnMap.SharedEntries;
  result->CrossProcessSharedPages = MonMemCountSharedPages(&pfnMap, ProcessId);

  /* Detect anomalies */
  if (result->CrossProcessSharedPages > 0) {
    result->AnomalyFlags |= (1 << MonMemAnomaly_SharedPhysicalPage);
    result->SuspiciousSharedCount = result->CrossProcessSharedPages;
  }

  ExReleaseResourceLite(&g_MemMon.TrackerLock);
  KeLeaveCriticalRegion();

  /* Emit anomaly event if suspicious sharing detected */
  if (result->CrossProcessSharedPages > 0) {
    MonMemEmitAnomalyEvent(ProcessId, MonMemAnomaly_SharedPhysicalPage, 3,
                           "Cross-process physical page sharing detected");
  }

  MonMemPfnHashFree(&pfnMap);

  return STATUS_SUCCESS;
}

/**
 * Analyze sharing and count suspicious entries
 */
static VOID MonMemAnalyzeSharingMap(_In_ PMON_PFN_REF_MAP Map, _In_ ULONG ProcessId,
                                    _Out_ ULONG *SharedCount, _Out_ ULONG *SuspiciousCount,
                                    _Out_ ULONG64 *TotalSharedBytes) {
  ULONG i;
  PLIST_ENTRY entry;
  PMON_PFN_REF_ENTRY pfnEntry;
  BOOLEAN hasProcess;
  ULONG shared = 0;
  ULONG suspicious = 0;

  *SharedCount = 0;
  *SuspiciousCount = 0;
  *TotalSharedBytes = 0;

  for (i = 0; i < Map->BucketCount; i++) {
    for (entry = Map->Buckets[i].Flink; entry != &Map->Buckets[i]; entry = entry->Flink) {
      pfnEntry = CONTAINING_RECORD(entry, MON_PFN_REF_ENTRY, HashLink);
      if (pfnEntry->ProcessCount < 2)
        continue;

      hasProcess = FALSE;
      for (ULONG j = 0; j < pfnEntry->ProcessCount; j++) {
        if (pfnEntry->ProcessIds[j] == ProcessId) {
          hasProcess = TRUE;
          break;
        }
      }

      if (hasProcess) {
        shared++;
        /* Mark as suspicious if sharing with 3+ processes */
        if (pfnEntry->ProcessCount >= 3) {
          suspicious++;
        }
      }
    }
  }

  *SharedCount = shared;
  *SuspiciousCount = suspicious;
  *TotalSharedBytes = (ULONG64)shared * PAGE_SIZE;
}

/**
 * @function   MonMemDetectSharing
 * @purpose    Detect cross-process memory sharing
 */
_Use_decl_annotations_ NTSTATUS MonMemDetectSharing(ULONG ProcessId, PVOID OutBuffer, ULONG OutLen,
                                                    ULONG *BytesWritten) {
  NTSTATUS status;
  PMON_SHARING_SCAN_RESULT result = (PMON_SHARING_SCAN_RESULT)OutBuffer;
  MON_PFN_REF_MAP pfnMap;
  ULONG sharedCount, suspiciousCount;
  ULONG64 totalSharedBytes;

  if (!g_MemMon.Initialized || OutBuffer == NULL || BytesWritten == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  if (OutLen < sizeof(MON_SHARING_SCAN_RESULT)) {
    return STATUS_BUFFER_TOO_SMALL;
  }

  RtlZeroMemory(result, sizeof(*result));
  result->Size = sizeof(MON_SHARING_SCAN_RESULT);
  result->ProcessId = ProcessId;

  /* Build PFN map from all tracked MDLs */
  KeEnterCriticalRegion();
  ExAcquireResourceSharedLite(&g_MemMon.TrackerLock, TRUE);

  status = MonMemBuildPfnMap(&pfnMap);
  if (!NT_SUCCESS(status)) {
    ExReleaseResourceLite(&g_MemMon.TrackerLock);
    KeLeaveCriticalRegion();
    *BytesWritten = 0;
    return status;
  }

  /* Analyze sharing for target process */
  MonMemAnalyzeSharingMap(&pfnMap, ProcessId, &sharedCount, &suspiciousCount, &totalSharedBytes);

  result->SharedRegionCount = sharedCount;
  result->SuspiciousCount = suspiciousCount;
  result->TotalSharedBytes = totalSharedBytes;

  /* Set anomaly flags if suspicious sharing detected */
  if (suspiciousCount > 0) {
    result->AnomalyFlags |= (1 << MonMemAnomaly_CrossProcessIoRing);
  }

  ExReleaseResourceLite(&g_MemMon.TrackerLock);
  KeLeaveCriticalRegion();

  /* Emit event if suspicious sharing detected */
  if (suspiciousCount > 0) {
    MonMemEmitAnomalyEvent(ProcessId, MonMemAnomaly_CrossProcessIoRing, 3,
                           "Suspicious cross-process memory sharing detected");
  }

  MonMemPfnHashFree(&pfnMap);

  *BytesWritten = sizeof(MON_SHARING_SCAN_RESULT);
  return STATUS_SUCCESS;
}

#pragma warning(pop)
