/*
 * Memory Region Monitoring - Header
 *
 * Author: Colin MacRitchie
 * Organization: ziX Labs - Security Research Division
 * File: mem_monitor.h
 * Version: 1.0
 * Date: 2025-12-01
 * Copyright:
 *   © 2025 ziX Performance Labs. All rights reserved. Proprietary and confidential.
 *   Redistribution or disclosure without prior written consent is prohibited.
 *
 * Summary:
 * Memory monitoring subsystem for IoRing-related buffer analysis. Provides MDL
 * tracking, VAD tree enumeration, physical page analysis, and cross-process
 * shared memory detection. Phase 8 implementation.
 *
 * Threading Model:
 * - MDL tracker: ERESOURCE for list, interlocked for counters
 * - VAD scanning: Snapshot-based, no persistent locks held
 * - Physical analysis: Read-only kernel queries
 *
 * SECURITY PROPERTIES:
 * - Input: All user-mode addresses validated before use
 * - Output: Physical addresses masked/zeroed per policy
 * - Memory Safety: SEH guards on all untrusted dereferences
 * - IRQL: Most APIs require PASSIVE_LEVEL for VAD/MDL access
 */

#pragma once

#ifdef _KERNEL_MODE
# include <ntddk.h>
#else
# include <windows.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------*/
/* Constants & Limits                                                       */
/*--------------------------------------------------------------------------*/

#define MON_MEM_MONITOR_MAGIC       0x4D454D4Fu /* 'MEMO' */
#define MON_MEM_TAG                 'mMoM'      /* Memory monitor pool tag */

#define MON_MAX_TRACKED_MDLS        256
#define MON_MAX_PFN_ENTRIES         64          /* Per MDL */
#define MON_MAX_VAD_DETAILED        128         /* Max detailed VADs per scan */
#define MON_MAX_PROCESS_IDS         8           /* Per shared page */

/*--------------------------------------------------------------------------*/
/* Memory Anomaly Types                                                     */
/*--------------------------------------------------------------------------*/

typedef enum _MON_MEM_ANOMALY {
    MonMemAnomaly_None = 0,

    /* MDL Anomalies (1-10) */
    MonMemAnomaly_KernelAddressInUserMdl = 1,   /* User MDL contains kernel VA */
    MonMemAnomaly_UnlockedMdlInUse = 2,         /* MDL used without locking */
    MonMemAnomaly_ExcessiveMdlChain = 3,        /* Unusually long MDL chain */
    MonMemAnomaly_MdlDoubleFree = 4,            /* MDL freed twice */

    /* VAD Anomalies (11-20) */
    MonMemAnomaly_ExecutableHeap = 11,          /* Heap region made executable */
    MonMemAnomaly_WritableCode = 12,            /* Code region made writable */
    MonMemAnomaly_UnbackedExecutable = 13,      /* Executable without file backing */
    MonMemAnomaly_SuspiciousVadFlags = 14,      /* Unusual VAD flag combination */
    MonMemAnomaly_HiddenVad = 15,               /* VAD not in tree but exists */

    /* Physical Memory Anomalies (21-30) */
    MonMemAnomaly_SharedPhysicalPage = 21,      /* Same PFN in multiple processes */
    MonMemAnomaly_ContiguousLargeAlloc = 22,    /* Large physically contiguous alloc */
    MonMemAnomaly_ZeroPageReference = 23,       /* Page with zero ref count in use */
    MonMemAnomaly_PhysicalPageReuse = 24,       /* PFN reused suspiciously fast */

    /* Cross-Process Anomalies (31-40) */
    MonMemAnomaly_UnauthorizedMapping = 31,     /* Buffer mapped without consent */
    MonMemAnomaly_SectionObjectLeak = 32,       /* Section handle in unexpected process */
    MonMemAnomaly_CrossProcessIoRing = 33,      /* IoRing targeting other process */

    MonMemAnomaly_Max

} MON_MEM_ANOMALY;

/*--------------------------------------------------------------------------*/
/* VAD Type Classifications                                                 */
/*--------------------------------------------------------------------------*/

typedef enum _MON_VAD_TYPE {
    MonVadType_Unknown = 0,
    MonVadType_Private = 1,         /* VadNone - private memory */
    MonVadType_Mapped = 2,          /* VadImageMap - mapped file */
    MonVadType_Image = 3,           /* Image section */
    MonVadType_Physical = 4,        /* Physical memory mapping */
    MonVadType_WriteWatch = 5,      /* Write-watch region */
    MonVadType_LargePages = 6,      /* Large page allocation */
    MonVadType_Rotate = 7,          /* AWE region */
    MonVadType_Max
} MON_VAD_TYPE;

/*--------------------------------------------------------------------------*/
/* MDL Tracking Structures                                                  */
/*--------------------------------------------------------------------------*/

typedef struct _MON_MDL_INFO {
    ULONG64     MdlAddress;             /* MDL kernel address (masked) */
    ULONG64     StartVa;                /* Virtual address start */
    ULONG       ByteCount;              /* Buffer size */
    USHORT      MdlFlags;               /* MDL flags snapshot */
    BOOLEAN     IsLocked;               /* Pages locked? */
    BOOLEAN     HasSystemMapping;       /* MappedSystemVa set? */

    /* Physical page info (first N pages) */
    ULONG       PfnCount;
    ULONG64     PfnArray[MON_MAX_PFN_ENTRIES];

    /* Timestamps */
    ULONG64     AllocTime;
    ULONG64     LockTime;

    /* Related IoRing (if applicable) */
    ULONG64     IoRingHandle;
    ULONG       BufferIndex;            /* Index in RegBuffers array */

} MON_MDL_INFO, *PMON_MDL_INFO;

typedef struct _MON_MDL_TRACKER {
    ULONG       Magic;
    ULONG       ProcessId;
    ULONG       MdlCount;
    ULONG       Reserved;

    /* Statistics */
    ULONG       TotalMdlsTracked;
    ULONG       CurrentlyLocked;
    ULONG64     TotalBytesLocked;
    ULONG64     PeakBytesLocked;

    /* Anomaly tracking */
    ULONG       AnomalyFlags;           /* Bitmask of MON_MEM_ANOMALY */
    ULONG       AnomalyCount;

    /* MDL array (variable length in actual use) */
    MON_MDL_INFO Mdls[MON_MAX_TRACKED_MDLS];

} MON_MDL_TRACKER, *PMON_MDL_TRACKER;

/*--------------------------------------------------------------------------*/
/* VAD Information Structures                                               */
/*--------------------------------------------------------------------------*/

typedef struct _MON_VAD_INFO {
    ULONG64     StartAddress;           /* Region start */
    ULONG64     EndAddress;             /* Region end */
    ULONG64     Size;                   /* Region size in bytes */

    /* Protection */
    ULONG       Protection;             /* Current protection flags */
    ULONG       InitialProtection;      /* Protection at allocation */
    BOOLEAN     IsExecutable;
    BOOLEAN     IsWritable;
    BOOLEAN     IsPrivate;
    BOOLEAN     Reserved1;

    /* Type */
    MON_VAD_TYPE VadType;
    BOOLEAN     HasFileBackingStore;
    BOOLEAN     Reserved2[3];
    WCHAR       BackingFileName[64];    /* If mapped file */

    /* State */
    BOOLEAN     IsCommitted;
    BOOLEAN     Reserved3[3];
    ULONG       CommitCharge;

    /* IoRing correlation */
    BOOLEAN     IsIoRingRelated;
    BOOLEAN     Reserved4[3];
    ULONG64     RelatedIoRingHandle;

} MON_VAD_INFO, *PMON_VAD_INFO;

typedef struct _MON_VAD_SCAN_RESULT {
    ULONG       Size;                   /* Structure size */
    ULONG       ProcessId;
    ULONG       VadCount;               /* Total VADs scanned */
    ULONG       IoRingRelatedCount;     /* VADs related to IoRing */

    /* Summary statistics */
    ULONG64     TotalPrivateBytes;
    ULONG64     TotalMappedBytes;
    ULONG64     TotalExecutableBytes;
    ULONG64     TotalCommittedBytes;

    /* Anomaly tracking */
    ULONG       AnomalyFlags;
    ULONG       SuspiciousVadCount;

    /* Timing */
    ULONG64     ScanStartTime;
    ULONG64     ScanEndTime;
    ULONG       ScanDurationUs;
    ULONG       Reserved;

    /* Detailed info count (actual array follows) */
    ULONG       DetailedInfoCount;
    ULONG       Reserved2;

    /* Detailed VAD info array follows (MON_VAD_INFO[DetailedInfoCount]) */

} MON_VAD_SCAN_RESULT, *PMON_VAD_SCAN_RESULT;

/*--------------------------------------------------------------------------*/
/* Physical Page Analysis Structures                                        */
/*--------------------------------------------------------------------------*/

typedef struct _MON_PAGE_INFO {
    ULONG64     PhysicalAddress;        /* Physical frame address */
    ULONG64     PfnNumber;              /* Page Frame Number */
    ULONG       ReferenceCount;         /* Times this PFN appears */
    ULONG       ProcessCount;           /* Processes mapping this page */
    ULONG       ProcessIds[MON_MAX_PROCESS_IDS];

    /* Page state */
    BOOLEAN     IsLocked;
    BOOLEAN     IsShared;
    BOOLEAN     IsModified;
    BOOLEAN     IsZeroPage;

} MON_PAGE_INFO, *PMON_PAGE_INFO;

typedef struct _MON_PHYSICAL_SCAN_RESULT {
    ULONG       Size;
    ULONG       ProcessId;
    ULONG       TotalPagesScanned;
    ULONG       SharedPagesFound;
    ULONG       ContiguousRanges;
    ULONG       Reserved;

    /* Largest contiguous allocation */
    ULONG64     LargestContiguousStart;
    ULONG       LargestContiguousPages;
    ULONG       Reserved2;

    /* Cross-process sharing detection */
    ULONG       CrossProcessSharedPages;
    ULONG       SuspiciousSharedCount;

    /* Anomaly tracking */
    ULONG       AnomalyFlags;
    ULONG       Reserved3;

} MON_PHYSICAL_SCAN_RESULT, *PMON_PHYSICAL_SCAN_RESULT;

/*--------------------------------------------------------------------------*/
/* Memory Anomaly Event                                                     */
/*--------------------------------------------------------------------------*/

typedef struct _MON_MEM_ANOMALY_EVENT {
    ULONG           Size;
    ULONG           ProcessId;
    MON_MEM_ANOMALY AnomalyType;
    ULONG           Severity;           /* 1-5 */

    /* Location info */
    ULONG64         VirtualAddress;     /* Masked */
    ULONG64         PhysicalAddress;    /* Masked or zeroed */
    ULONG64         RegionSize;

    /* Context */
    ULONG           RelatedProcessId;   /* For cross-process anomalies */
    ULONG           Reserved;
    ULONG64         IoRingHandle;       /* Related IoRing if applicable */

    /* Details */
    ULONG           Flags;              /* Anomaly-specific flags */
    CHAR            Description[128];   /* Human-readable description */
    CHAR            ATT_CK_Technique[16];

    ULONG64         Timestamp;

} MON_MEM_ANOMALY_EVENT, *PMON_MEM_ANOMALY_EVENT;

/*--------------------------------------------------------------------------*/
/* Shared Memory Detection                                                  */
/*--------------------------------------------------------------------------*/

typedef struct _MON_SHARED_REGION {
    ULONG64     VirtualAddress;         /* In source process */
    ULONG64     Size;
    ULONG       SourceProcessId;
    ULONG       TargetProcessCount;
    ULONG       TargetProcessIds[MON_MAX_PROCESS_IDS];

    /* Sharing mechanism */
    BOOLEAN     IsSectionBased;         /* Via section object */
    BOOLEAN     IsPhysicalMapping;      /* Direct physical sharing */
    BOOLEAN     IsSuspicious;
    BOOLEAN     Reserved;

} MON_SHARED_REGION, *PMON_SHARED_REGION;

typedef struct _MON_SHARING_SCAN_RESULT {
    ULONG       Size;
    ULONG       ProcessId;
    ULONG       SharedRegionCount;
    ULONG       SuspiciousCount;

    ULONG64     TotalSharedBytes;
    ULONG       AnomalyFlags;
    ULONG       Reserved;

    /* Array of shared regions follows */

} MON_SHARING_SCAN_RESULT, *PMON_SHARING_SCAN_RESULT;

/*--------------------------------------------------------------------------*/
/* Memory Monitor Statistics                                                */
/*--------------------------------------------------------------------------*/

typedef struct _MON_MEM_STATS {
    ULONG       Size;
    ULONG       Reserved;

    /* MDL tracking */
    ULONG       TrackedMdlCount;
    ULONG       TotalMdlsEverTracked;
    ULONG64     TotalBytesTracked;

    /* VAD scanning */
    ULONG       TotalVadScans;
    ULONG       TotalVadsScanned;
    ULONG64     AvgScanDurationUs;

    /* Physical analysis */
    ULONG       TotalPhysicalScans;
    ULONG       TotalPagesAnalyzed;

    /* Anomalies */
    ULONG       TotalAnomaliesDetected;
    ULONG       AnomaliesByType[32];    /* Indexed by MON_MEM_ANOMALY */

    /* Cross-process */
    ULONG       SharedRegionsDetected;
    ULONG       SuspiciousSharingEvents;

} MON_MEM_STATS, *PMON_MEM_STATS;

/*--------------------------------------------------------------------------*/
/* Kernel-Mode API Declarations                                             */
/*--------------------------------------------------------------------------*/

#ifdef _KERNEL_MODE

/**
 * @function   MonMemMonitorInitialize
 * @purpose    Initialize memory monitoring subsystem
 * @precondition IRQL == PASSIVE_LEVEL, called from DriverEntry
 * @postcondition Subsystem ready for use
 * @returns    STATUS_SUCCESS or error
 * @thread-safety Single-threaded initialization
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MonMemMonitorInitialize(VOID);

/**
 * @function   MonMemMonitorShutdown
 * @purpose    Shutdown memory monitoring subsystem
 * @precondition IRQL == PASSIVE_LEVEL, called from DriverUnload
 * @postcondition All resources freed
 * @thread-safety Single-threaded shutdown
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
MonMemMonitorShutdown(VOID);

/**
 * @function   MonMemTrackMdl
 * @purpose    Add MDL to tracking for a process
 * @precondition IRQL <= APC_LEVEL
 * @postcondition MDL info captured and stored
 * @returns    STATUS_SUCCESS or error
 * @thread-safety Uses ERESOURCE for list protection
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
MonMemTrackMdl(
    _In_ ULONG ProcessId,
    _In_ PVOID MdlAddress,
    _In_opt_ ULONG64 IoRingHandle,
    _In_opt_ ULONG BufferIndex
);

/**
 * @function   MonMemUntrackMdl
 * @purpose    Remove MDL from tracking
 * @precondition IRQL <= APC_LEVEL
 * @postcondition MDL removed from tracker
 * @thread-safety Uses ERESOURCE for list protection
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
MonMemUntrackMdl(
    _In_ ULONG ProcessId,
    _In_ PVOID MdlAddress
);

/**
 * @function   MonMemGetMdlTracker
 * @purpose    Get MDL tracking info for a process
 * @precondition IRQL == PASSIVE_LEVEL
 * @postcondition Output buffer populated
 * @returns    STATUS_SUCCESS or error
 * @thread-safety Uses ERESOURCE for read access
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MonMemGetMdlTracker(
    _In_ ULONG ProcessId,
    _Out_writes_bytes_to_(OutLen, *BytesWritten) PVOID OutBuffer,
    _In_ ULONG OutLen,
    _Out_ ULONG* BytesWritten
);

/**
 * @function   MonMemScanVad
 * @purpose    Scan VAD tree for a process
 * @precondition IRQL == PASSIVE_LEVEL
 * @postcondition VAD scan result populated
 * @returns    STATUS_SUCCESS or error
 * @thread-safety Snapshot-based, no persistent locks
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MonMemScanVad(
    _In_ ULONG ProcessId,
    _Out_writes_bytes_to_(OutLen, *BytesWritten) PVOID OutBuffer,
    _In_ ULONG OutLen,
    _Out_ ULONG* BytesWritten
);

/**
 * @function   MonMemAnalyzePhysical
 * @purpose    Analyze physical page mappings for a process
 * @precondition IRQL == PASSIVE_LEVEL
 * @postcondition Physical analysis result populated
 * @returns    STATUS_SUCCESS or error
 * @thread-safety Read-only kernel queries
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MonMemAnalyzePhysical(
    _In_ ULONG ProcessId,
    _Out_writes_bytes_(sizeof(MON_PHYSICAL_SCAN_RESULT)) PVOID OutBuffer,
    _In_ ULONG OutLen
);

/**
 * @function   MonMemDetectSharing
 * @purpose    Detect cross-process memory sharing
 * @precondition IRQL == PASSIVE_LEVEL
 * @postcondition Sharing scan result populated
 * @returns    STATUS_SUCCESS or error
 * @thread-safety Snapshot-based analysis
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MonMemDetectSharing(
    _In_ ULONG ProcessId,
    _Out_writes_bytes_to_(OutLen, *BytesWritten) PVOID OutBuffer,
    _In_ ULONG OutLen,
    _Out_ ULONG* BytesWritten
);

/**
 * @function   MonMemGetStats
 * @purpose    Get memory monitoring statistics
 * @precondition IRQL <= DISPATCH_LEVEL
 * @postcondition Stats structure populated
 * @returns    STATUS_SUCCESS or error
 * @thread-safety Uses interlocked reads
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
MonMemGetStats(
    _Out_writes_bytes_(sizeof(MON_MEM_STATS)) PVOID OutBuffer,
    _In_ ULONG OutLen
);

/**
 * @function   MonMemCheckAnomalies
 * @purpose    Run anomaly detection on tracked memory
 * @precondition IRQL == PASSIVE_LEVEL
 * @postcondition Anomaly events emitted if detected
 * @returns    Number of anomalies detected
 * @thread-safety Uses ERESOURCE for list access
 */
_IRQL_requires_(PASSIVE_LEVEL)
ULONG
MonMemCheckAnomalies(
    _In_ ULONG ProcessId
);

#endif /* _KERNEL_MODE */

#ifdef __cplusplus
} /* extern "C" */
#endif
