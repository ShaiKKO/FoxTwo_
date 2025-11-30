# Phase 8: Memory Region Monitoring

## Implementation Plan

**Author:** Colin MacRitchie | ziX Labs
**Version:** 1.0
**Date:** 2025-11-30
**Status:** Planning

---

## 1. Executive Summary

This phase implements memory region monitoring for IoRing-related buffers, including MDL tracking, VAD enumeration, and physical memory backing analysis. The goal is to detect suspicious memory configurations that could indicate exploitation attempts or cross-process attacks.

---

## 2. Research Findings

### 2.1 Memory Descriptor Lists (MDLs)

**Purpose:**
- MDLs describe physical memory pages backing virtual addresses
- Essential for I/O operations and DMA
- IoRing uses MDLs for registered buffer mappings

**MDL Structure:**
```c
typedef struct _MDL {
    struct _MDL *Next;      // Chained MDLs
    CSHORT Size;            // MDL size
    CSHORT MdlFlags;        // State flags
    struct _EPROCESS *Process; // Owning process
    PVOID MappedSystemVa;   // System space mapping
    PVOID StartVa;          // Starting virtual address
    ULONG ByteCount;        // Buffer size
    ULONG ByteOffset;       // Page offset
} MDL, *PMDL;
```

**Security Relevance:**
- MDL flags indicate if memory is locked, mapped, or shared
- MappedSystemVa reveals kernel-accessible views of user buffers
- Physical page array (after MDL header) shows actual backing pages

### 2.2 Virtual Address Descriptors (VADs)

**Purpose:**
- Windows memory manager uses VADs to track process memory ranges
- AVL tree structure per process (VadRoot)
- Contains allocation type, protection, and state

**VAD Security Implications:**
- Detect unauthorized code injections
- Identify memory protection anomalies
- Track executable regions created post-allocation

**VAD Information Available:**
| Field | Security Relevance |
|-------|-------------------|
| StartingVpn/EndingVpn | Memory range boundaries |
| Protection | R/W/X permissions |
| PrivateMemory | Shared vs private |
| VadType | MEM_MAPPED, MEM_PRIVATE, etc |
| CommitCharge | Committed page count |

### 2.3 Physical Memory Analysis

**Key Functions:**
- `MmGetPhysicalAddress()` - Translate VA to PA
- `MmGetVirtualForPhysical()` - Reverse translation
- `MmProbeAndLockPages()` - Lock pages and build PFN array

**Security Concerns (BYOVD Research):**
- Vulnerable drivers expose physical memory access
- PA-to-VA mapping can bypass ASLR
- Shared physical pages indicate potential cross-process sharing

### 2.4 Shared Memory Detection

**Indicators of Sharing:**
1. Same physical page mapped in multiple processes
2. Section objects (file mappings) with multiple handles
3. MDLs with MappedSystemVa pointing to shared regions
4. VAD entries with PrivateMemory=FALSE

---

## 3. Architecture Design

### 3.1 Component Overview

```
+------------------------------------------------------------------+
|                    Memory Monitor Subsystem                       |
|  +----------------------------+  +-----------------------------+  |
|  | MDL Tracker                |  | VAD Scanner                 |  |
|  | - Track MDL allocations    |  | - Walk VAD tree             |  |
|  | - Monitor lock/unlock      |  | - Detect anomalies          |  |
|  | - Map shared views         |  | - Protection changes        |  |
|  +----------------------------+  +-----------------------------+  |
|  +----------------------------+  +-----------------------------+  |
|  | Physical Page Analyzer     |  | Shared Region Detector      |  |
|  | - PFN enumeration          |  | - Cross-process mapping     |  |
|  | - Page reference counting  |  | - Section object tracking   |  |
|  | - Contiguous detection     |  | - Handle correlation        |  |
|  +----------------------------+  +-----------------------------+  |
+------------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------------+
|                    IoRing Integration Points                      |
|  +----------------------------+  +-----------------------------+  |
|  | regbuf_integrity.c         |  | ioring_enum.c               |  |
|  | - RegBuffers MDL analysis  |  | - IoRing object discovery   |  |
|  | - Buffer validity checks   |  | - Section mapping detection |  |
|  +----------------------------+  +-----------------------------+  |
+------------------------------------------------------------------+
```

### 3.2 Monitoring Points

```
1. IoRing RegBuffers Registration
   -> Capture MDL for each registered buffer
   -> Store physical page mapping
   -> Check for suspicious characteristics

2. Periodic VAD Scan
   -> Walk target process VAD tree
   -> Identify IoRing-related regions
   -> Detect protection changes

3. Physical Page Analysis
   -> Build reference count for IoRing pages
   -> Detect multi-process mapping
   -> Identify contiguous large allocations

4. Section Object Correlation
   -> Track section handles per process
   -> Match IoRing regions to sections
   -> Detect cross-process sharing
```

### 3.3 Detection Rules

```c
// Memory anomaly detection rules

typedef enum _MON_MEM_ANOMALY {
    MonMemAnomaly_None = 0,

    // MDL Anomalies
    MonMemAnomaly_KernelAddressInUserMdl = 1,    // User MDL contains kernel VA
    MonMemAnomaly_UnlockedMdlInUse = 2,          // MDL used without locking
    MonMemAnomaly_ExcessiveMdlChain = 3,         // Unusually long MDL chain

    // VAD Anomalies
    MonMemAnomaly_ExecutableHeap = 4,            // Heap region made executable
    MonMemAnomaly_WritableCode = 5,              // Code region made writable
    MonMemAnomaly_UnbackedExecutable = 6,        // Executable without file backing
    MonMemAnomaly_SuspiciousVadFlags = 7,        // Unusual VAD flag combination

    // Physical Memory Anomalies
    MonMemAnomaly_SharedPhysicalPage = 8,        // Same PFN in multiple processes
    MonMemAnomaly_ContiguousLargeAlloc = 9,      // Large physically contiguous alloc
    MonMemAnomaly_ZeroPageReference = 10,        // Page with zero ref count in use

    // Cross-Process Anomalies
    MonMemAnomaly_UnauthorizedMapping = 11,      // Buffer mapped without consent
    MonMemAnomaly_SectionObjectLeak = 12,        // Section handle in unexpected process

} MON_MEM_ANOMALY;
```

---

## 4. Data Structures

### 4.1 MDL Tracking

```c
// New file: mem_monitor.h

#define MON_MEM_MONITOR_MAGIC       0x4D454D4F  /* 'MEMO' */
#define MON_MAX_TRACKED_MDLS        256
#define MON_MAX_PFN_ENTRIES         64          /* Per MDL */

typedef struct _MON_MDL_INFO {
    PVOID       MdlAddress;         /* MDL kernel address (masked for export) */
    PVOID       StartVa;            /* Virtual address start */
    ULONG       ByteCount;          /* Buffer size */
    USHORT      MdlFlags;           /* MDL flags snapshot */
    BOOLEAN     IsLocked;           /* Pages locked? */
    BOOLEAN     HasSystemMapping;   /* MappedSystemVa set? */

    /* Physical page info (first N pages) */
    ULONG       PfnCount;
    ULONG64     PfnArray[MON_MAX_PFN_ENTRIES];

    /* Timestamps */
    ULONG64     AllocTime;
    ULONG64     LockTime;

} MON_MDL_INFO, *PMON_MDL_INFO;

typedef struct _MON_MDL_TRACKER {
    ULONG       Magic;
    ULONG       ProcessId;
    ULONG       MdlCount;
    MON_MDL_INFO Mdls[MON_MAX_TRACKED_MDLS];

    /* Statistics */
    ULONG       TotalMdlsTracked;
    ULONG       CurrentlyLocked;
    ULONG64     TotalBytesLocked;

    /* Anomaly tracking */
    ULONG       AnomalyFlags;       /* Bitmask of MON_MEM_ANOMALY */
    ULONG       AnomalyCount;

} MON_MDL_TRACKER, *PMON_MDL_TRACKER;
```

### 4.2 VAD Information

```c
/* VAD type classifications */
typedef enum _MON_VAD_TYPE {
    MonVadType_Unknown = 0,
    MonVadType_Private = 1,         /* VadNone - private memory */
    MonVadType_Mapped = 2,          /* VadImageMap - mapped file */
    MonVadType_Image = 3,           /* VadDevicePhysicalMemory - image */
    MonVadType_Physical = 4,        /* Physical memory mapping */
    MonVadType_WriteWatch = 5,      /* Write-watch region */
    MonVadType_LargePages = 6,      /* Large page allocation */
    MonVadType_Rotate = 7,          /* AWE region */
} MON_VAD_TYPE;

typedef struct _MON_VAD_INFO {
    ULONG64     StartAddress;       /* Region start */
    ULONG64     EndAddress;         /* Region end */
    ULONG64     Size;               /* Region size in bytes */

    /* Protection */
    ULONG       Protection;         /* Current protection flags */
    ULONG       InitialProtection;  /* Protection at allocation */
    BOOLEAN     IsExecutable;
    BOOLEAN     IsWritable;
    BOOLEAN     IsPrivate;

    /* Type */
    MON_VAD_TYPE VadType;
    BOOLEAN     HasFileBackingStore;
    WCHAR       BackingFileName[64];    /* If mapped file */

    /* State */
    BOOLEAN     IsCommitted;
    ULONG       CommitCharge;

} MON_VAD_INFO, *PMON_VAD_INFO;

typedef struct _MON_VAD_SCAN_RESULT {
    ULONG       ProcessId;
    ULONG       VadCount;           /* Total VADs scanned */
    ULONG       IoRingRelatedCount; /* VADs related to IoRing */

    /* Summary statistics */
    ULONG64     TotalPrivateBytes;
    ULONG64     TotalMappedBytes;
    ULONG64     TotalExecutableBytes;

    /* Anomaly tracking */
    ULONG       AnomalyFlags;
    ULONG       SuspiciousVadCount;

    /* Detailed info (variable length) */
    ULONG       DetailedInfoCount;
    MON_VAD_INFO DetailedInfo[ANYSIZE_ARRAY];

} MON_VAD_SCAN_RESULT, *PMON_VAD_SCAN_RESULT;
```

### 4.3 Physical Page Analysis

```c
typedef struct _MON_PAGE_INFO {
    ULONG64     PhysicalAddress;    /* Physical frame address */
    ULONG64     PfnNumber;          /* Page Frame Number */
    ULONG       ReferenceCount;     /* Times this PFN appears */
    ULONG       ProcessCount;       /* Processes mapping this page */
    ULONG       ProcessIds[8];      /* First 8 process IDs */

    /* Page state */
    BOOLEAN     IsLocked;
    BOOLEAN     IsShared;
    BOOLEAN     IsModified;
    BOOLEAN     IsZeroPage;

} MON_PAGE_INFO, *PMON_PAGE_INFO;

typedef struct _MON_PHYSICAL_SCAN_RESULT {
    ULONG       ProcessId;
    ULONG       TotalPagesScanned;
    ULONG       SharedPagesFound;
    ULONG       ContiguousRanges;

    /* Largest contiguous allocation */
    ULONG64     LargestContiguousStart;
    ULONG       LargestContiguousPages;

    /* Cross-process sharing detection */
    ULONG       CrossProcessSharedPages;
    ULONG       SuspiciousSharedCount;

} MON_PHYSICAL_SCAN_RESULT, *PMON_PHYSICAL_SCAN_RESULT;
```

### 4.4 Memory Anomaly Event

```c
typedef struct _MON_MEM_ANOMALY_EVENT {
    ULONG           Size;
    ULONG           ProcessId;
    MON_MEM_ANOMALY AnomalyType;
    ULONG           Severity;       /* 1-5 */

    /* Location info */
    ULONG64         VirtualAddress;     /* Masked */
    ULONG64         PhysicalAddress;    /* Masked or zeroed */
    ULONG64         RegionSize;

    /* Context */
    ULONG           RelatedProcessId;   /* For cross-process anomalies */
    ULONG64         IoRingHandle;       /* Related IoRing if applicable */

    /* Details */
    ULONG           Flags;              /* Anomaly-specific flags */
    CHAR            Description[128];   /* Human-readable description */
    CHAR            ATT_CK_Technique[16];

    ULONG64         Timestamp;

} MON_MEM_ANOMALY_EVENT, *PMON_MEM_ANOMALY_EVENT;
```

---

## 5. Implementation Tasks

### 5.1 Kernel-Mode Components

**File: mem_monitor.h**
- Data structures (above)
- Function prototypes
- Constants and limits

**File: mem_monitor.c**
- `MonMemMonitorInitialize()` - Initialize subsystem
- `MonMemMonitorShutdown()` - Cleanup
- `MonMemTrackMdl()` - Add MDL to tracking
- `MonMemUntrackMdl()` - Remove MDL tracking
- `MonMemScanVad()` - Enumerate process VADs
- `MonMemAnalyzePhysical()` - Physical page analysis
- `MonMemDetectSharing()` - Cross-process detection
- `MonMemCheckAnomalies()` - Run all anomaly checks

**File: vad_walker.c**
- `MonVadWalkTree()` - Walk VAD AVL tree
- `MonVadGetNodeInfo()` - Extract VAD node info
- `MonVadFindByAddress()` - Find VAD for address
- `MonVadCompareProtection()` - Detect protection changes

**IOCTL Additions:**
```c
#define IOCTL_MONITOR_MEM_SCAN_VAD       CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x40, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_MEM_GET_MDLS       CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x41, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_MEM_SCAN_PHYSICAL  CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x42, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_MEM_GET_SHARING    CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x43, METHOD_BUFFERED, FILE_READ_ACCESS)
```

### 5.2 User-Mode Components

**File: client/win11mon_memory.h**
- Memory scanning APIs
- Anomaly notification callbacks

**File: client/win11mon_memory.c**
- `Mon_MemScanVad()` - Request VAD scan
- `Mon_MemGetMdls()` - Get tracked MDLs
- `Mon_MemScanPhysical()` - Physical analysis
- `Mon_MemGetSharing()` - Sharing detection

### 5.3 Integration Points

1. **regbuf_integrity.c**: Call `MonMemTrackMdl()` when validating RegBuffers
2. **ioring_enum.c**: Trigger VAD scan on IoRing discovery
3. **process_profile.c**: Add memory metrics to profiles
4. **telemetry_ringbuf.c**: Log memory anomaly events

---

## 6. VAD Walking Implementation

### 6.1 Undocumented Structures

```c
/* VAD structures (undocumented, version-dependent) */

typedef struct _MMVAD_FLAGS {
    ULONG Lock : 1;
    ULONG LockContended : 1;
    ULONG DeleteInProgress : 1;
    ULONG NoChange : 1;
    ULONG VadType : 3;
    ULONG Protection : 5;
    ULONG PreferredNode : 7;
    ULONG PageSize : 2;
    ULONG PrivateMemory : 1;
} MMVAD_FLAGS;

typedef struct _MMVAD_SHORT {
    union {
        struct _MMVAD_SHORT* NextVad;
        RTL_BALANCED_NODE VadNode;
    };
    ULONG StartingVpn;
    ULONG EndingVpn;
    UCHAR StartingVpnHigh;
    UCHAR EndingVpnHigh;
    UCHAR CommitChargeHigh;
    UCHAR SpareNT64VadUChar;
    LONG ReferenceCount;
    EX_PUSH_LOCK PushLock;
    MMVAD_FLAGS u;
    ULONG u1;
    PVOID EventList;
} MMVAD_SHORT, *PMMVAD_SHORT;
```

### 6.2 Walking Algorithm

```
1. Get EPROCESS for target PID
2. Locate VadRoot (offset from EPROCESS - version dependent)
3. Traverse AVL tree:
   - Start at root node
   - For each node:
     a. Extract StartingVpn/EndingVpn
     b. Read protection flags
     c. Determine VAD type
     d. Check against IoRing buffer ranges
     e. Recurse left/right children
4. Build result structure
5. Run anomaly detection
```

---

## 7. Testing Plan

### 7.1 Unit Tests

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| MEM-T01 | MDL tracking add/remove | No leaks, accurate count |
| MEM-T02 | VAD tree traversal | All VADs enumerated |
| MEM-T03 | PFN extraction from MDL | Valid physical addresses |
| MEM-T04 | Shared page detection | Cross-process sharing detected |
| MEM-T05 | Anomaly rule evaluation | Correct flags set |
| MEM-T06 | IOCTL VAD scan | Valid response |
| MEM-T07 | Large process handling | No timeout/BSOD |

### 7.2 Integration Tests

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| MEM-I01 | IoRing buffer VAD detection | Correct regions identified |
| MEM-I02 | RegBuffers MDL correlation | MDLs linked to IoRing |
| MEM-I03 | Anomaly event to ring buffer | Event captured |
| MEM-I04 | Profile memory metrics | Updated correctly |
| MEM-I05 | Multi-process sharing scan | All shares detected |

### 7.3 Anomaly Detection Tests

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| MEM-A01 | Executable heap region | MonMemAnomaly_ExecutableHeap |
| MEM-A02 | Writable code section | MonMemAnomaly_WritableCode |
| MEM-A03 | Shared physical pages | MonMemAnomaly_SharedPhysicalPage |
| MEM-A04 | Kernel address in user MDL | MonMemAnomaly_KernelAddressInUserMdl |

---

## 8. Security Considerations

### 8.1 Information Disclosure Risks

- Physical addresses are sensitive (ASLR bypass potential)
- Mask or zero physical addresses in user-mode exports
- Limit VAD detail exposure to admin clients

### 8.2 Performance Impact

- VAD walking: O(n) where n = VAD count
- Avoid scanning processes with >10K VADs frequently
- Use periodic sampling, not continuous monitoring

### 8.3 Version Dependencies

- VAD structure offsets vary by Windows build
- Integrate with offset_resolver.c (Phase 5B)
- Fail gracefully on unknown builds

---

## 9. Dependencies

- Phase 5B: Dynamic Offset Resolution (VAD offsets)
- Phase 7: Process Behavior Profiling (memory metrics)
- A1: IoRing Handle Enumeration (target processes)
- A2: RegBuffers Integrity Validation (MDL source)

---

## 10. File Deliverables

| File | Type | Description |
|------|------|-------------|
| `mem_monitor.h` | Header | Memory monitoring structures |
| `mem_monitor.c` | Source | Core memory monitoring |
| `vad_walker.c` | Source | VAD tree traversal |
| `client/win11mon_memory.h` | Header | Client memory APIs |
| `client/win11mon_memory.c` | Source | Client implementation |
| `test_memory.c` | Test | Unit tests |

---

## 11. Research Sources

- [Using MDLs - Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-mdls)
- [MDL Structure - Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_mdl)
- [Understanding MDLs for Exploit Development - Medium](https://medium.com/@WaterBucket/understanding-memory-descriptor-lists-mdls-for-windows-vulnerability-research-exploit-7de8729caee7)
- [VAD Internals - Medium](https://imphash.medium.com/windows-process-internals-a-few-concepts-to-know-before-jumping-on-memory-forensics-part-4-16c47b89e826)
- [VAD in WinDbg - Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-vad)
- [Hunting Vulnerable Kernel Drivers - VMware](https://blogs.vmware.com/security/2023/10/hunting-vulnerable-kernel-drivers.html)
- [SiC - Shared Memory Enumeration - GitHub](https://github.com/0vercl0k/sic)
- [VA to PA Mapping with SuperFetch - Outflank](https://www.outflank.nl/blog/2023/12/14/mapping-virtual-to-physical-adresses-using-superfetch/)

---

## 12. Approval

- [ ] Architecture review completed
- [ ] Security review completed
- [ ] Implementation approved

---

*End of Phase 8 Plan*
