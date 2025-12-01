# Phase 10: Kernel Callback Integration

## Implementation Plan

**Author:** Colin MacRitchie | ziX Labs
**Version:** 1.0
**Date:** 2025-11-30
**Status:** Planning

---

## 1. Executive Summary

This phase integrates Windows kernel notification callbacks to provide real-time event awareness for process creation, thread creation, image loading, and registry operations. These callbacks enable proactive IoRing monitoring rather than relying solely on periodic enumeration.

---

## 2. Research Findings

### 2.1 Available Kernel Callbacks

| Callback Function | Purpose | Max Registrations |
|-------------------|---------|-------------------|
| PsSetCreateProcessNotifyRoutineEx | Process creation/termination | 64 |
| PsSetCreateThreadNotifyRoutineEx | Thread creation/termination | 64 |
| PsSetLoadImageNotifyRoutineEx | Image (DLL/EXE) loading | 64 |
| ObRegisterCallbacks | Handle operations (create/duplicate) | Unlimited* |
| CmRegisterCallbackEx | Registry operations | Unlimited* |
| FltRegisterFilter | File system operations | Altitude-based |

*Limited by system resources

### 2.2 Process Notify Callback

**PsSetCreateProcessNotifyRoutineEx:**
- Called when process is created or exits
- Runs at PASSIVE_LEVEL in critical region
- Can block process creation (set CreationStatus)
- Requires IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY (/integritycheck linker flag)

**Callback Information Available:**
```c
typedef struct _PS_CREATE_NOTIFY_INFO {
    SIZE_T Size;
    union {
        ULONG Flags;
        struct {
            ULONG FileOpenNameAvailable : 1;
            ULONG IsSubsystemProcess : 1;
            ULONG Reserved : 30;
        };
    };
    HANDLE ParentProcessId;
    CLIENT_ID CreatingThreadId;
    struct _FILE_OBJECT *FileObject;
    PCUNICODE_STRING ImageFileName;
    PCUNICODE_STRING CommandLine;
    NTSTATUS CreationStatus;        // Can modify to block
} PS_CREATE_NOTIFY_INFO, *PPS_CREATE_NOTIFY_INFO;
```

### 2.3 Image Load Callback

**PsSetLoadImageNotifyRoutineEx:**
- Called when DLL/EXE mapped into address space
- Includes ntdll.dll loading (first user-mode image)
- Can detect suspicious DLL loading patterns

**Information Available:**
- Full image name (PUNICODE_STRING)
- Process ID
- Image base address
- Image size

### 2.4 Object Manager Callbacks

**ObRegisterCallbacks:**
- Monitor handle creation/duplication
- Supported object types: Process, Thread, Desktop
- Can strip access rights (pre-callback)
- Cannot block outright, only modify access

**Limitation:** IoRing object type NOT supported

### 2.5 Registry Callbacks

**CmRegisterCallbackEx:**
- All registry operations (create, open, query, set, delete)
- Pre and post notifications
- Can block operations
- Altitude-based ordering

### 2.6 Minifilter Callbacks

**FltRegisterFilter:**
- File system I/O operations
- Pre/post operation callbacks
- Altitude-based ordering
- Communication ports for user-mode

---

## 3. Architecture Design

### 3.1 Component Overview

```
+------------------------------------------------------------------+
|                Kernel Callback Integration Layer                  |
|  +----------------------------+  +-----------------------------+  |
|  | Process Callback Handler   |  | Thread Callback Handler     |  |
|  | - Track new processes      |  | - Track new threads         |  |
|  | - Detect IoRing loaders    |  | - Correlation with IoRing   |  |
|  | - Build process tree       |  | - Suspicious thread detect  |  |
|  +----------------------------+  +-----------------------------+  |
|  +----------------------------+  +-----------------------------+  |
|  | Image Load Handler         |  | Handle Operation Handler    |  |
|  | - Detect suspicious DLLs   |  | - Track handle creation     |  |
|  | - ntdll hook detection     |  | - Detect DuplicateHandle    |  |
|  | - IoRing API imports       |  | - Process/Thread handles    |  |
|  +----------------------------+  +-----------------------------+  |
|  +----------------------------+                                   |
|  | Registry Callback Handler  |                                   |
|  | - IoRing persistence keys  |                                   |
|  | - Suspicious key patterns  |                                   |
|  +----------------------------+                                   |
+------------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------------+
|                    Integration with Other Phases                  |
|  +----------------------------+  +-----------------------------+  |
|  | process_profile.c (Ph7)    |  | cross_process.c (Ph9)       |  |
|  | - Profile on process start |  | - Real-time tree updates    |  |
|  | - Update on thread create  |  | - Handle correlation        |  |
|  +----------------------------+  +-----------------------------+  |
|  +----------------------------+  +-----------------------------+  |
|  | ioring_enum.c              |  | telemetry_ringbuf.c         |  |
|  | - Trigger scan on new proc |  | - Log all callback events   |  |
|  | - Associate handles early  |  | - Event correlation         |  |
|  +----------------------------+  +-----------------------------+  |
+------------------------------------------------------------------+
```

### 3.2 Callback Registration Flow

```
DriverEntry:
  1. Register process callback (PsSetCreateProcessNotifyRoutineEx)
  2. Register thread callback (PsSetCreateThreadNotifyRoutineEx)
  3. Register image callback (PsSetLoadImageNotifyRoutineEx)
  4. Register object callbacks (ObRegisterCallbacks) - optional
  5. Register registry callback (CmRegisterCallbackEx) - optional
  6. Initialize callback state tracking

DriverUnload:
  1. Unregister all callbacks (reverse order)
  2. Wait for pending callbacks to complete
  3. Free callback state
```

### 3.3 Process Callback Integration

```
OnProcessNotify(CreateInfo):
  IF CreateInfo != NULL:  // Process creation
    1. Create process profile (Phase 7)
    2. Add to process tree (Phase 9)
    3. Check if known IoRing loader
    4. Schedule IoRing scan for new process
    5. Log to ring buffer
  ELSE:  // Process termination
    1. Export process profile (ML features)
    2. Cleanup process resources
    3. Remove from tracking
    4. Log termination event
```

### 3.4 Image Load Integration

```
OnImageLoad(FullImageName, ProcessId, ImageBase):
  1. Check if image is IoRing-related:
     - KernelBase.dll (contains CreateIoRing)
     - ntdll.dll (contains NtCreateIoRing)
  2. If IoRing-related DLL:
     a. Mark process as potential IoRing user
     b. Schedule early IoRing enumeration
  3. Check for suspicious patterns:
     - Unusual DLL in sensitive process
     - Reflective loader patterns
  4. Log image load event
```

---

## 4. Data Structures

### 4.1 Callback State

```c
// New file: kernel_callbacks.h

#define MON_CB_MAX_PROCESS_CACHE    4096
#define MON_CB_MAX_PENDING_SCANS    256

/* Callback registration state */
typedef struct _MON_CALLBACK_STATE {
    /* Registration status */
    BOOLEAN ProcessCallbackRegistered;
    BOOLEAN ThreadCallbackRegistered;
    BOOLEAN ImageCallbackRegistered;
    BOOLEAN ObjectCallbackRegistered;
    BOOLEAN RegistryCallbackRegistered;

    /* Registration handles/cookies */
    PVOID   ObjectCallbackHandle;
    LARGE_INTEGER RegistryCallbackCookie;

    /* Statistics */
    volatile LONG64 ProcessCreations;
    volatile LONG64 ProcessTerminations;
    volatile LONG64 ThreadCreations;
    volatile LONG64 ThreadTerminations;
    volatile LONG64 ImageLoads;
    volatile LONG64 HandleOperations;
    volatile LONG64 RegistryOperations;

    /* Process cache for quick lookup */
    struct {
        ULONG   ProcessId;
        ULONG   ParentProcessId;
        ULONG64 CreateTime;
        BOOLEAN HasIoRingPotential;
    } ProcessCache[MON_CB_MAX_PROCESS_CACHE];

    KSPIN_LOCK CacheLock;

    /* Pending scan queue */
    ULONG   PendingScanPids[MON_CB_MAX_PENDING_SCANS];
    ULONG   PendingScanHead;
    ULONG   PendingScanTail;
    KEVENT  PendingScanEvent;

} MON_CALLBACK_STATE, *PMON_CALLBACK_STATE;
```

### 4.2 Callback Events

```c
/* Event types for callback notifications */
typedef enum _MON_CALLBACK_EVENT_TYPE {
    MonCbEvent_ProcessCreate = 0,
    MonCbEvent_ProcessTerminate = 1,
    MonCbEvent_ThreadCreate = 2,
    MonCbEvent_ThreadTerminate = 3,
    MonCbEvent_ImageLoad = 4,
    MonCbEvent_HandleCreate = 5,
    MonCbEvent_HandleDuplicate = 6,
    MonCbEvent_RegistryOperation = 7,
} MON_CALLBACK_EVENT_TYPE;

/* Process creation event */
typedef struct _MON_PROCESS_CREATE_EVENT {
    ULONG       ProcessId;
    ULONG       ParentProcessId;
    ULONG       CreatingThreadId;
    ULONG64     CreateTime;
    WCHAR       ImageFileName[260];
    WCHAR       CommandLine[512];
    BOOLEAN     IsSubsystemProcess;
    ULONG       SessionId;
    ULONG       IntegrityLevel;
} MON_PROCESS_CREATE_EVENT, *PMON_PROCESS_CREATE_EVENT;

/* Process termination event */
typedef struct _MON_PROCESS_TERMINATE_EVENT {
    ULONG       ProcessId;
    ULONG64     TerminateTime;
    NTSTATUS    ExitStatus;
    ULONG64     TotalIoRingOperations;  /* From profile */
    ULONG       AnomalyScore;           /* From profile */
} MON_PROCESS_TERMINATE_EVENT, *PMON_PROCESS_TERMINATE_EVENT;

/* Image load event */
typedef struct _MON_IMAGE_LOAD_EVENT {
    ULONG       ProcessId;
    ULONG64     ImageBase;
    ULONG64     ImageSize;
    WCHAR       ImageFileName[260];
    BOOLEAN     IsIoRingRelated;
    BOOLEAN     IsSuspicious;
    UCHAR       SuspiciousReason;
} MON_IMAGE_LOAD_EVENT, *PMON_IMAGE_LOAD_EVENT;

/* Handle operation event */
typedef struct _MON_HANDLE_OP_EVENT {
    ULONG       SourceProcessId;
    ULONG       TargetProcessId;
    ULONG64     Handle;
    ULONG       DesiredAccess;
    ULONG       OriginalDesiredAccess;  /* Before our modification */
    BOOLEAN     WasModified;            /* Did we strip access? */
    UCHAR       Operation;              /* Create or Duplicate */
    UCHAR       ObjectType;             /* Process, Thread, Desktop */
} MON_HANDLE_OP_EVENT, *PMON_HANDLE_OP_EVENT;
```

### 4.3 Object Callback Registration

```c
/* ObRegisterCallbacks structures */
typedef struct _MON_OB_CALLBACK_CONTEXT {
    PVOID       RegistrationHandle;
    ULONG       Version;

    /* Pre-operation callback counters */
    volatile LONG64 ProcessHandleCreates;
    volatile LONG64 ProcessHandleDuplicates;
    volatile LONG64 ThreadHandleCreates;
    volatile LONG64 ThreadHandleDuplicates;

    /* Access modifications */
    volatile LONG64 AccessModifications;

} MON_OB_CALLBACK_CONTEXT, *PMON_OB_CALLBACK_CONTEXT;
```

---

## 5. Implementation Tasks

### 5.1 Kernel-Mode Components

**File: kernel_callbacks.h**
- Callback structures and prototypes
- Event type definitions
- Configuration constants

**File: kernel_callbacks.c**
- `MonCbInitialize()` - Register all callbacks
- `MonCbShutdown()` - Unregister all callbacks
- `MonCbProcessNotify()` - Process callback handler
- `MonCbThreadNotify()` - Thread callback handler
- `MonCbImageLoadNotify()` - Image load handler
- `MonCbObjectPreCallback()` - Handle pre-operation
- `MonCbObjectPostCallback()` - Handle post-operation
- `MonCbRegistryCallback()` - Registry operation handler

**File: callback_process.c**
- `MonCbOnProcessCreate()` - Handle new process
- `MonCbOnProcessTerminate()` - Handle process exit
- `MonCbIsIoRingLoader()` - Check if known IoRing user
- `MonCbScheduleScan()` - Queue IoRing enumeration

**File: callback_image.c**
- `MonCbOnImageLoad()` - Handle image load
- `MonCbCheckIoRingDll()` - Check for IoRing imports
- `MonCbDetectSuspiciousImage()` - Anomaly detection

**IOCTL Additions:**
```c
#define IOCTL_MONITOR_CB_GET_STATS       CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x60, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_CB_GET_EVENTS      CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x61, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_CB_SET_CONFIG      CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x62, METHOD_BUFFERED, FILE_WRITE_ACCESS)
```

### 5.2 User-Mode Components

**File: client/win11mon_callbacks.h**
- Callback statistics query
- Event retrieval
- Configuration APIs

**File: client/win11mon_callbacks.c**
- `Mon_CbGetStats()` - Get callback statistics
- `Mon_CbGetEvents()` - Retrieve callback events
- `Mon_CbSetConfig()` - Configure callback behavior

### 5.3 Integration Points

1. **process_profile.c**: Create profile on process create callback
2. **cross_process.c**: Update tree on process create/terminate
3. **ioring_enum.c**: Schedule scan on process create
4. **telemetry_ringbuf.c**: Log all callback events

### 5.4 Linker Requirements

```
/INTEGRITYCHECK flag required for:
- PsSetCreateProcessNotifyRoutineEx
- PsSetLoadImageNotifyRoutineEx

Add to driver project:
- Additional linker options: /INTEGRITYCHECK
```

---

## 6. Callback Implementations

### 6.1 Process Callback

```c
VOID MonCbProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    if (CreateInfo != NULL) {
        // Process creation
        MON_PROCESS_CREATE_EVENT event = {0};
        event.ProcessId = HandleToULong(ProcessId);
        event.ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);

        if (CreateInfo->ImageFileName) {
            RtlCopyMemory(event.ImageFileName,
                          CreateInfo->ImageFileName->Buffer,
                          min(CreateInfo->ImageFileName->Length, sizeof(event.ImageFileName) - 2));
        }

        // Create process profile
        MonProfileCreate(event.ProcessId);

        // Update process tree
        MonXpAddProcess(event.ProcessId, event.ParentProcessId);

        // Check if potential IoRing user
        if (MonCbIsIoRingLoader(CreateInfo->ImageFileName)) {
            MonCbScheduleScan(event.ProcessId);
        }

        // Log event
        MonRingBufferWrite(MonCbEvent_ProcessCreate, &event, sizeof(event));

    } else {
        // Process termination
        MonCbOnProcessTerminate(Process, ProcessId);
    }
}
```

### 6.2 Image Load Callback

```c
VOID MonCbImageLoadNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
)
{
    MON_IMAGE_LOAD_EVENT event = {0};
    event.ProcessId = HandleToULong(ProcessId);
    event.ImageBase = (ULONG64)ImageInfo->ImageBase;
    event.ImageSize = ImageInfo->ImageSize;

    if (FullImageName) {
        RtlCopyMemory(event.ImageFileName,
                      FullImageName->Buffer,
                      min(FullImageName->Length, sizeof(event.ImageFileName) - 2));

        // Check for IoRing-related DLLs
        if (MonCbCheckIoRingDll(FullImageName)) {
            event.IsIoRingRelated = TRUE;
            MonCbScheduleScan(event.ProcessId);
        }
    }

    MonRingBufferWrite(MonCbEvent_ImageLoad, &event, sizeof(event));
}
```

### 6.3 Object Pre-Callback

```c
OB_PREOP_CALLBACK_STATUS MonCbObjectPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInfo
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    // Only interested in process handles for now
    if (OperationInfo->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    PEPROCESS targetProcess = (PEPROCESS)OperationInfo->Object;
    HANDLE targetPid = PsGetProcessId(targetProcess);
    HANDLE sourcePid = PsGetCurrentProcessId();

    // Log handle operation
    MON_HANDLE_OP_EVENT event = {0};
    event.SourceProcessId = HandleToULong(sourcePid);
    event.TargetProcessId = HandleToULong(targetPid);
    event.Operation = (OperationInfo->Operation == OB_OPERATION_HANDLE_CREATE) ? 0 : 1;
    event.ObjectType = 0; // Process

    if (OperationInfo->Operation == OB_OPERATION_HANDLE_CREATE) {
        event.DesiredAccess = OperationInfo->Parameters->CreateHandleInformation.DesiredAccess;
    } else {
        event.DesiredAccess = OperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess;
    }

    event.OriginalDesiredAccess = event.DesiredAccess;

    // Update cross-process detection
    if (sourcePid != targetPid) {
        MonXpOnHandleOperation(&event);
    }

    MonRingBufferWrite(MonCbEvent_HandleCreate + event.Operation, &event, sizeof(event));

    return OB_PREOP_SUCCESS;
}
```

---

## 7. Testing Plan

### 7.1 Unit Tests

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| CB-T01 | Process callback registration | STATUS_SUCCESS |
| CB-T02 | Thread callback registration | STATUS_SUCCESS |
| CB-T03 | Image callback registration | STATUS_SUCCESS |
| CB-T04 | Object callback registration | STATUS_SUCCESS |
| CB-T05 | Process create notification | Event logged |
| CB-T06 | Process terminate notification | Profile exported |
| CB-T07 | Image load notification | Event logged |
| CB-T08 | Callback unregistration | Clean unload |

### 7.2 Integration Tests

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| CB-I01 | Process create -> Profile create | Profile exists |
| CB-I02 | Process terminate -> Profile export | ML features saved |
| CB-I03 | IoRing DLL load -> Scan triggered | Handles enumerated |
| CB-I04 | Handle duplicate -> XP detection | Alert if suspicious |
| CB-I05 | High callback volume | No dropped events |

### 7.3 Stress Tests

| Test ID | Description | Target |
|---------|-------------|--------|
| CB-S01 | 1000 process creates/sec | No callback drops |
| CB-S02 | 10000 image loads/sec | Stable performance |
| CB-S03 | Extended runtime (24hr) | No memory leaks |

---

## 8. Performance Considerations

### 8.1 Callback Execution Context

- Process callbacks: PASSIVE_LEVEL, critical region
- Thread callbacks: PASSIVE_LEVEL
- Image callbacks: PASSIVE_LEVEL (usually)
- Object callbacks: Variable (check IRQL)

### 8.2 Minimize Callback Work

1. Quick path filtering (check flags first)
2. Defer heavy work to worker thread
3. Use lock-free counters where possible
4. Avoid allocations in callback path

### 8.3 Memory Usage

- Process cache: ~64KB
- Event queue: Reuse ring buffer
- Pending scan queue: ~1KB

---

## 9. Security Considerations

### 9.1 Callback Protection

- Callbacks can be enumerated by attackers
- RealBlindingEDR can remove callback registrations
- Consider hiding registration or adding integrity checks

### 9.2 /INTEGRITYCHECK Requirement

- Driver must be signed with valid certificate
- Test signing mode may affect behavior
- Document requirement for deployment

### 9.3 Callback Reentrancy

- Some callbacks may be called recursively
- Use proper synchronization
- Avoid deadlocks with other driver components

---

## 10. Dependencies

- Phase 7: Process Behavior Profiling (profile creation)
- Phase 9: Cross-Process Communication Detection (tree updates)
- Phase 5A: Ring Buffer Telemetry (event logging)

---

## 11. File Deliverables

| File | Type | Description |
|------|------|-------------|
| `kernel_callbacks.h` | Header | Callback structures |
| `kernel_callbacks.c` | Source | Callback registration |
| `callback_process.c` | Source | Process/thread handlers |
| `callback_image.c` | Source | Image load handler |
| `client/win11mon_callbacks.h` | Header | Client callback APIs |
| `client/win11mon_callbacks.c` | Source | Client implementation |
| `test_callbacks.c` | Test | Unit tests |

---

## 12. Research Sources

- [PsSetCreateProcessNotifyRoutine - Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutine)
- [PsSetCreateProcessNotifyRoutineEx - Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- [PsSetLoadImageNotifyRoutine - Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutine)
- [ObRegisterCallbacks - Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks)
- [CmRegisterCallback - Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-cmregistercallback)
- [Kernel Callbacks - Red Team Notes](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/subscribing-to-process-creation-thread-creation-and-image-load-notifications-from-a-kernel-driver)
- [Understanding Kernel Callbacks - Medium](https://jsecurity101.medium.com/understanding-telemetry-kernel-callbacks-1a97cfcb8fb3)
- [Kernel Callback Functions - CodeMachine](https://codemachine.com/articles/kernel_callback_functions.html)
- [Minifilter Drivers - Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/about-file-system-filter-drivers)
- [EDR Chapter on Minifilters - No Starch](https://nostarch.com/download/EvadingEDR_chapter6.pdf)

---

## 13. Approval

- [ ] Architecture review completed
- [ ] Security review completed
- [ ] Implementation approved

---

*End of Phase 10 Plan*
