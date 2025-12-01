# Phase 9: Cross-Process Communication Detection

## Implementation Plan

**Author:** Colin MacRitchie | ziX Labs
**Version:** 1.0
**Date:** 2025-11-30
**Status:** Planning

---

## 1. Executive Summary

This phase implements cross-process communication detection focused on IoRing buffer sharing scenarios. The system detects shared buffers between processes, tracks handle inheritance and duplication, and correlates named object access to identify potential data exfiltration or privilege escalation attempts.

---

## 2. Research Findings

### 2.1 Handle Inheritance Mechanisms

**Windows Handle Sharing Methods:**
1. **Inheritance** - Parent creates inheritable handle, child inherits on spawn
2. **DuplicateHandle** - Copy handle to another process
3. **Named Objects** - Open by name from multiple processes
4. **Section Objects** - File mappings shared between processes

**Key Structures:**
- Handle table per process (ObjectTable in EPROCESS)
- SYSTEM_HANDLE_TABLE_ENTRY_INFO from NtQuerySystemInformation
- OB_PRE_OPERATION_INFORMATION from ObRegisterCallbacks

### 2.2 ObRegisterCallbacks for Handle Monitoring

**Supported Object Types:**
- Process (PsProcessType)
- Thread (PsThreadType)
- Desktop (ExDesktopObjectType)

**Limitation for IoRing:**
- IoRing object type NOT supported by ObRegisterCallbacks
- Must use alternative detection: handle enumeration + correlation

**Operations Captured:**
- OB_OPERATION_HANDLE_CREATE
- OB_OPERATION_HANDLE_DUPLICATE

### 2.3 Cross-Process Sharing Indicators

| Indicator | Detection Method |
|-----------|-----------------|
| Same physical page in multiple VADs | PFN correlation |
| Handle value in unexpected process | Periodic enumeration |
| Section object with multiple handles | NtQuerySystemInformation |
| Named object opened by multiple PIDs | Object directory enumeration |
| DuplicateHandle call detected | ObRegisterCallbacks (for Process/Thread) |

### 2.4 IoRing-Specific Sharing Scenarios

**Legitimate Sharing:**
- Parent creates IoRing, child inherits (rare)
- Shared memory section for IPC

**Suspicious Sharing:**
- IoRing handle duplicated to SYSTEM process
- RegBuffers shared between unrelated processes
- Section object created, IoRing attached, shared

---

## 3. Architecture Design

### 3.1 Component Overview

```
+------------------------------------------------------------------+
|                Cross-Process Detection Subsystem                  |
|  +----------------------------+  +-----------------------------+  |
|  | Handle Correlation Engine  |  | Section Object Tracker      |  |
|  | - Per-process handle lists |  | - Named section enumeration |  |
|  | - Cross-reference by obj   |  | - Mapping process list      |  |
|  | - DuplicateHandle detect   |  | - Access pattern analysis   |  |
|  +----------------------------+  +-----------------------------+  |
|  +----------------------------+  +-----------------------------+  |
|  | Inheritance Tracker        |  | Named Object Monitor        |  |
|  | - Parent-child mapping     |  | - Object directory walk     |  |
|  | - Handle flow tracing      |  | - IoRing object names       |  |
|  | - PID lineage validation   |  | - Access correlation        |  |
|  +----------------------------+  +-----------------------------+  |
+------------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------------+
|                    Integration Points                             |
|  +----------------------------+  +-----------------------------+  |
|  | ioring_enum.c              |  | mem_monitor.c (Phase 8)     |  |
|  | - IoRing handle discovery  |  | - Shared page detection     |  |
|  | - Per-process handle list  |  | - PFN correlation           |  |
|  +----------------------------+  +-----------------------------+  |
+------------------------------------------------------------------+
```

### 3.2 Detection Workflow

```
1. Handle Enumeration (periodic)
   -> Query all system handles
   -> Build per-process handle lists
   -> Identify IoRing handles

2. Cross-Reference Analysis
   -> For each IoRing object address:
      - Find all processes with handles to it
      - If >1 process, flag as potential sharing

3. Section Object Correlation
   -> Enumerate section handles
   -> Match sections to IoRing memory regions
   -> Detect multi-process mappings

4. Inheritance Validation
   -> Build process tree
   -> For shared IoRing handles:
      - Verify parent-child relationship
      - Check if inheritance is expected

5. Anomaly Detection
   -> Score based on:
      - Unrelated processes sharing
      - Elevated process with handle from lower
      - SYSTEM/Service with user-created IoRing
```

### 3.3 Handle Correlation Algorithm

```
Algorithm: DetectCrossProcessSharing

Input: List of all system handles
Output: List of shared IoRing objects with process pairs

1. GroupedHandles = Group handles by Object Address
2. For each (ObjectAddr, HandleList) in GroupedHandles:
   a. If HandleList contains IoRing handles:
      b. UniqueProcesses = Distinct PIDs in HandleList
      c. If |UniqueProcesses| > 1:
         d. SharedObject = {
              ObjectAddress: ObjectAddr,
              Processes: UniqueProcesses,
              HandleValues: per-process handles,
              AccessMasks: per-process access
            }
         e. Validate relationship:
            - Check process tree for parent-child
            - Check process tokens for similarity
            - Check if inheritance is flagged
         f. If relationship invalid:
            g. Generate CrossProcessAlert
3. Return AlertList
```

---

## 4. Data Structures

### 4.1 Handle Tracking

```c
// New file: cross_process.h

#define MON_XP_MAX_PROCESSES        64      /* Max processes sharing one object */
#define MON_XP_MAX_TRACKED_OBJECTS  256     /* Max objects tracked */

typedef struct _MON_HANDLE_ENTRY {
    ULONG       ProcessId;
    ULONG64     HandleValue;
    ULONG       AccessMask;
    BOOLEAN     IsInherited;        /* If known */
    ULONG64     CreateTime;         /* When first seen */
} MON_HANDLE_ENTRY, *PMON_HANDLE_ENTRY;

typedef struct _MON_SHARED_OBJECT {
    ULONG64     ObjectAddress;      /* Kernel object address (masked) */
    UCHAR       ObjectTypeIndex;    /* From handle table */
    UCHAR       ProcessCount;       /* Number of processes with handles */
    USHORT      Reserved;

    /* Per-process info */
    MON_HANDLE_ENTRY Processes[MON_XP_MAX_PROCESSES];

    /* Relationship analysis */
    BOOLEAN     HasParentChildRelation;
    ULONG       CommonAncestorPid;
    ULONG       RelationshipDepth;

    /* Flags */
    ULONG       Flags;
    #define MON_XP_FLAG_CROSS_INTEGRITY     0x0001  /* Different integrity levels */
    #define MON_XP_FLAG_CROSS_SESSION       0x0002  /* Different sessions */
    #define MON_XP_FLAG_SYSTEM_INVOLVED     0x0004  /* SYSTEM process involved */
    #define MON_XP_FLAG_SERVICE_INVOLVED    0x0008  /* Service process involved */
    #define MON_XP_FLAG_UNRELATED           0x0010  /* No process relationship */
    #define MON_XP_FLAG_SUSPICIOUS          0x0020  /* Anomaly detected */

    /* Section correlation */
    BOOLEAN     HasSectionBacking;
    ULONG64     SectionHandle;
    WCHAR       SectionName[64];

} MON_SHARED_OBJECT, *PMON_SHARED_OBJECT;
```

### 4.2 Process Relationship Tracking

```c
typedef struct _MON_PROCESS_RELATION {
    ULONG       ProcessId;
    ULONG       ParentProcessId;
    ULONG       SessionId;
    ULONG       IntegrityLevel;     /* SECURITY_MANDATORY_*_RID */

    /* Token info */
    BOOLEAN     IsElevated;
    BOOLEAN     IsService;
    BOOLEAN     IsSystem;
    BOOLEAN     IsInteractive;

    /* Lineage */
    ULONG       AncestorCount;
    ULONG       Ancestors[8];       /* Up to 8 generations */

    /* IoRing specific */
    ULONG       IoRingHandleCount;
    ULONG64     FirstIoRingTime;

} MON_PROCESS_RELATION, *PMON_PROCESS_RELATION;

typedef struct _MON_PROCESS_TREE {
    ULONG       ProcessCount;
    MON_PROCESS_RELATION Processes[1024];

    /* Index for fast lookup */
    ULONG       PidIndex[65536];    /* Sparse index */

} MON_PROCESS_TREE, *PMON_PROCESS_TREE;
```

### 4.3 Section Object Tracking

```c
typedef struct _MON_SECTION_INFO {
    ULONG64     SectionAddress;     /* Kernel object address */
    WCHAR       SectionName[128];   /* Name if named */
    BOOLEAN     IsNamed;

    /* Size info */
    ULONG64     MaximumSize;
    ULONG       AllocationAttributes;

    /* Process mappings */
    ULONG       MappingCount;
    struct {
        ULONG   ProcessId;
        ULONG64 BaseAddress;        /* In process VA space */
        ULONG64 ViewSize;
        ULONG   Protection;
    } Mappings[32];

    /* IoRing correlation */
    BOOLEAN     RelatedToIoRing;
    ULONG       RelatedIoRingPid;

} MON_SECTION_INFO, *PMON_SECTION_INFO;
```

### 4.4 Cross-Process Alert

```c
typedef enum _MON_XP_ALERT_TYPE {
    MonXpAlert_None = 0,
    MonXpAlert_SharedIoRing = 1,            /* IoRing handle in multiple processes */
    MonXpAlert_UnrelatedSharing = 2,        /* Non-parent/child sharing */
    MonXpAlert_CrossIntegrityShare = 3,     /* Different integrity levels */
    MonXpAlert_SystemIoRingAccess = 4,      /* SYSTEM has handle to user IoRing */
    MonXpAlert_HandleDuplication = 5,       /* DuplicateHandle detected */
    MonXpAlert_SectionSharing = 6,          /* Section shared with IoRing buffer */
    MonXpAlert_InheritanceAnomaly = 7,      /* Unexpected inheritance */
} MON_XP_ALERT_TYPE;

typedef struct _MON_XP_ALERT_EVENT {
    ULONG               Size;
    MON_XP_ALERT_TYPE   AlertType;
    ULONG               Severity;           /* 1-5 */
    ULONG64             Timestamp;

    /* Object info */
    ULONG64             ObjectAddress;      /* Masked */
    UCHAR               ObjectTypeIndex;

    /* Process info */
    ULONG               SourceProcessId;
    ULONG               TargetProcessId;
    WCHAR               SourceProcessName[64];
    WCHAR               TargetProcessName[64];

    /* Handle info */
    ULONG64             SourceHandle;
    ULONG64             TargetHandle;
    ULONG               SourceAccess;
    ULONG               TargetAccess;

    /* Relationship */
    BOOLEAN             IsParentChild;
    ULONG               SourceIntegrity;
    ULONG               TargetIntegrity;

    /* Context */
    CHAR                Description[256];
    CHAR                ATT_CK_Technique[16];   /* e.g., "T1055" */

} MON_XP_ALERT_EVENT, *PMON_XP_ALERT_EVENT;
```

---

## 5. Implementation Tasks

### 5.1 Kernel-Mode Components

**File: cross_process.h**
- Data structures (above)
- Function prototypes
- Alert type definitions

**File: cross_process.c**
- `MonXpInitialize()` - Initialize subsystem
- `MonXpShutdown()` - Cleanup
- `MonXpBuildProcessTree()` - Construct process relationships
- `MonXpCorrelateHandles()` - Find shared objects
- `MonXpValidateRelationship()` - Check if sharing is expected
- `MonXpGenerateAlert()` - Create alert event
- `MonXpScanSections()` - Enumerate section objects
- `MonXpGetProcessIntegrity()` - Query process integrity level

**File: handle_correlator.c**
- `MonHcEnumerateHandles()` - Query all system handles
- `MonHcGroupByObject()` - Group handles by object address
- `MonHcFilterIoRing()` - Extract IoRing handles
- `MonHcDetectDuplication()` - Identify duplicated handles

**IOCTL Additions:**
```c
#define IOCTL_MONITOR_XP_GET_SHARED      CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x50, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_XP_GET_TREE        CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x51, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_XP_SCAN_SECTIONS   CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x52, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_XP_GET_ALERTS      CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x53, METHOD_BUFFERED, FILE_READ_ACCESS)
```

### 5.2 User-Mode Components

**File: client/win11mon_xprocess.h**
- Cross-process detection APIs
- Alert callback registration

**File: client/win11mon_xprocess.c**
- `Mon_XpGetSharedObjects()` - Query shared IoRing objects
- `Mon_XpGetProcessTree()` - Get process relationships
- `Mon_XpScanSections()` - Section enumeration
- `Mon_XpGetAlerts()` - Retrieve alerts

### 5.3 Integration Points

1. **ioring_enum.c**: Feed IoRing handles to correlator
2. **mem_monitor.c**: PFN sharing detection correlates with XP
3. **process_profile.c**: Add cross-process metrics
4. **telemetry_ringbuf.c**: Log XP alerts

---

## 6. Detection Rules

### 6.1 Built-in Rules

```c
typedef struct _MON_XP_RULE {
    ULONG               RuleId;
    PCWSTR              RuleName;
    MON_XP_ALERT_TYPE   AlertType;
    ULONG               Severity;
    BOOLEAN             Enabled;
} MON_XP_RULE;

// Pre-defined rules:

const MON_XP_RULE g_XpRules[] = {
    // Rule 1: IoRing shared between unrelated processes
    { 1, L"UnrelatedIoRingSharing", MonXpAlert_UnrelatedSharing, 4, TRUE },

    // Rule 2: User process IoRing handle in SYSTEM
    { 2, L"SystemIoRingFromUser", MonXpAlert_SystemIoRingAccess, 5, TRUE },

    // Rule 3: Cross-integrity IoRing sharing
    { 3, L"CrossIntegrityIoRing", MonXpAlert_CrossIntegrityShare, 4, TRUE },

    // Rule 4: Section used for IoRing buffer sharing
    { 4, L"SectionIoRingBuffer", MonXpAlert_SectionSharing, 3, TRUE },

    // Rule 5: Unexpected handle inheritance
    { 5, L"UnexpectedInheritance", MonXpAlert_InheritanceAnomaly, 3, TRUE },

    // Rule 6: Rapid handle duplication
    { 6, L"RapidDuplication", MonXpAlert_HandleDuplication, 4, TRUE },

    { 0, NULL, 0, 0, FALSE }  // Sentinel
};
```

### 6.2 Scoring System

```
Sharing Risk Score =
    (IntegrityDelta * 20) +           // 0-60 points
    (UnrelatedBonus * 30) +           // 0 or 30
    (SystemInvolved * 25) +           // 0 or 25
    (SectionSharing * 15) +           // 0 or 15
    (RapidDuplication * 10)           // 0 or 10

Thresholds:
- Score >= 60: Critical alert
- Score >= 40: High alert
- Score >= 20: Medium alert
- Score <  20: Informational
```

---

## 7. Testing Plan

### 7.1 Unit Tests

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| XP-T01 | Handle enumeration | All handles retrieved |
| XP-T02 | Group by object address | Correct grouping |
| XP-T03 | Process tree construction | Parent-child accurate |
| XP-T04 | Integrity level query | Correct RID returned |
| XP-T05 | Section enumeration | All sections found |
| XP-T06 | Alert generation | Valid event structure |

### 7.2 Integration Tests

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| XP-I01 | Parent-child IoRing inheritance | No alert (legitimate) |
| XP-I02 | Unrelated process sharing | Alert generated |
| XP-I03 | SYSTEM with user IoRing | Critical alert |
| XP-I04 | Section-backed sharing | Alert with section info |
| XP-I05 | Cross-session sharing | Cross-session flag set |

### 7.3 Scenario Tests

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| XP-S01 | Legitimate child process | Score < 20 |
| XP-S02 | Injected handle | Score >= 40 |
| XP-S03 | Privilege escalation attempt | Score >= 60 |
| XP-S04 | Named section IPC | Context captured |

---

## 8. Performance Considerations

### 8.1 Handle Enumeration Cost

- SystemHandleInformation returns ALL handles
- Typical system: 50K-200K handles
- Filter to IoRing early to reduce processing
- Use periodic sampling (every 5-10 seconds)

### 8.2 Process Tree Cache

- Build once, update incrementally
- Cache process info (integrity, session)
- Invalidate on PsSetCreateProcessNotifyRoutine callback

### 8.3 Memory Usage

- Handle correlation buffer: ~4MB (200K handles)
- Process tree: ~256KB
- Section tracking: ~64KB
- Alerts: Ring buffer (reuse telemetry_ringbuf)

---

## 9. Security Considerations

### 9.1 Information Disclosure

- Object addresses masked before user-mode export
- Process names may reveal system configuration
- Limit detailed info to admin clients

### 9.2 False Positives

- Some legitimate software uses handle inheritance
- White-list known patterns (browser sandboxing, etc.)
- Provide rule configuration

### 9.3 Evasion Possibilities

- Attacker could close original handle after duplication
- Detection window: enumeration period
- Mitigation: Correlate with memory sharing (Phase 8)

---

## 10. Dependencies

- Phase 8: Memory Region Monitoring (PFN correlation)
- Phase 10: Kernel Callback Integration (process tree updates)
- A1: IoRing Handle Enumeration (data source)

---

## 11. File Deliverables

| File | Type | Description |
|------|------|-------------|
| `cross_process.h` | Header | Cross-process structures |
| `cross_process.c` | Source | Detection logic |
| `handle_correlator.c` | Source | Handle correlation engine |
| `client/win11mon_xprocess.h` | Header | Client XP APIs |
| `client/win11mon_xprocess.c` | Source | Client implementation |
| `test_xprocess.c` | Test | Unit tests |

---

## 12. Research Sources

- [Handle Inheritance - Microsoft](https://learn.microsoft.com/en-us/windows/win32/procthread/inheritance)
- [Sharing Kernel Objects - FlyLib](https://flylib.com/books/en/4.419.1.30/1/)
- [ObRegisterCallbacks - Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks)
- [ObCallback Sample - Microsoft](https://github.com/Microsoft/Windows-driver-samples/blob/main/general/obcallback/driver/callback.c)
- [Handle Tables & Object Manager - GenXCyber](https://genxcyber.com/handle-tables-object-manager/)
- [EDRSandblast - Wavestone](https://github.com/wavestone-cdt/EDRSandblast)
- [Understanding Telemetry: Kernel Callbacks - Medium](https://jsecurity101.medium.com/understanding-telemetry-kernel-callbacks-1a97cfcb8fb3)
- [Reversing Windows Internals - Rayanfam](https://rayanfam.com/topics/reversing-windows-internals-part1/)
- [Section Objects - Malware.news](https://malware.news/t/dissecting-windows-section-objects/65448)

---

## 13. Approval

- [ ] Architecture review completed
- [ ] Security review completed
- [ ] Implementation approved

---

*End of Phase 9 Plan*
