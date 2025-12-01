# Phase 1 Remediation Plan – Production Hardening

**Version**: 1.0
**Date**: 2025-11-30
**Status**: Ready for Implementation
**Author**: Colin MacRitchie | ziX Labs

---

## Overview

This plan addresses all issues identified in the Distinguished Engineer review of Phase 1 code. Issues are prioritized by severity and dependency order.

---

## Implementation Order

```
Stage 1: Critical Fixes (Blocking)
├── 1.1 Fix deprecated pool APIs (ExAllocatePool2)
├── 1.2 Implement IoRing type index discovery
└── 1.3 Fix TraceLogging event name literals

Stage 2: High Priority (Security/Correctness)
├── 2.1 Add memory barriers for global state
├── 2.2 Add integer overflow protection
└── 2.3 Fix SEH flag preservation

Stage 3: Code Quality (Maintainability)
├── 3.1 Consolidate duplicate type definitions
├── 3.2 Normalize naming conventions
├── 3.3 Extract magic numbers to constants
└── 3.4 Add SAL lock annotations

Stage 4: Enhancements (Best Practices)
├── 4.1 Add kernel address validation macro
├── 4.2 Implement ETW fallback for legacy path
└── 4.3 Refactor long functions
```

---

## Stage 1: Critical Fixes

### 1.1 Fix Deprecated Pool APIs

**Files**: `ioring_enum.c`, `test_harness.c`

**Changes**:
1. Replace `ExAllocatePoolWithTag` → `ExAllocatePool2`
2. Replace `NonPagedPoolNx` → `POOL_FLAG_NON_PAGED`
3. Replace `PagedPool` → `POOL_FLAG_PAGED`
4. Add `POOL_ZERO_DOWN_LEVEL_SUPPORT` for WDK < 2004 compatibility
5. Update return value checks (NULL vs exception)

**New Helper Macro** (in `monitor_internal.h`):
```c
/*
 * Pool allocation wrapper for down-level compatibility.
 * Uses ExAllocatePool2 on Win10 2004+, falls back to ExAllocatePoolZero.
 */
#if (NTDDI_VERSION >= NTDDI_WIN10_VB)
#define MonAllocatePool(Flags, Size, Tag) \
    ExAllocatePool2((Flags), (Size), (Tag))
#else
#define POOL_ZERO_DOWN_LEVEL_SUPPORT
#include <wdm.h>
#define MonAllocatePool(Flags, Size, Tag) \
    ExAllocatePoolZero( \
        ((Flags) & POOL_FLAG_NON_PAGED) ? NonPagedPoolNx : PagedPool, \
        (Size), (Tag))
#endif
```

---

### 1.2 Implement IoRing Type Index Discovery

**File**: `ioring_enum.c`

**Problem**: `g_IoRingTypeInfo.TypeIndex` is never set, so enumeration callback is never invoked.

**Solution**: Query object type name during first enumeration to discover IoRing type index.

**Implementation**:
```c
/* New internal function */
static NTSTATUS MonDiscoverIoRingTypeIndex(VOID);

/* Type index discovery using ObQueryNameString on object type */
static NTSTATUS
MonDiscoverIoRingTypeIndex(VOID)
{
    NTSTATUS status;
    ULONG bufferSize = 0;
    PSYSTEM_HANDLE_INFORMATION_EX handleInfo = NULL;
    POBJECT_TYPE_INFORMATION typeInfo = NULL;

    /* Allocate type info buffer */
    typeInfo = MonAllocatePool(POOL_FLAG_PAGED, 256, MON_POOL_TAG);
    if (!typeInfo) return STATUS_INSUFFICIENT_RESOURCES;

    /* Query handle table */
    status = ZwQuerySystemInformation(...);

    /* Find first handle and query its type name */
    for (each handle) {
        if (handle->Object is kernel address) {
            status = ObQueryNameString(
                handle->Object,
                typeInfo,
                256,
                &returnLength);

            /* Check if type name contains "IoRing" */
            if (wcsstr(typeInfo->Name.Buffer, L"IoRing")) {
                g_IoRingTypeInfo.TypeIndex = handle->ObjectTypeIndex;
                break;
            }
        }
    }

    ExFreePoolWithTag(typeInfo, MON_POOL_TAG);
    return status;
}
```

**Alternative Approach** (simpler, more robust):
Since we cannot reliably get IoRing type index without existing handles, use heuristic:
- Query `\ObjectTypes\IoRing` directory object
- Or enumerate ALL handles and validate each with RegBuffers check

**Chosen Approach**: Enumerate all handles, use A2 validation as filter.

---

### 1.3 Fix TraceLogging Event Name Literals

**File**: `telemetry_etw.c`

**Problem**: `TraceLoggingWrite` requires string literal for event name.

**Solution**: Use separate macro calls for each event type.

```c
/* Before (BROKEN) */
const char* eventName = "DriverLoaded";
TraceLoggingWrite(g_hMonitorEtwProvider, eventName, ...);

/* After (CORRECT) */
#define MON_ETW_LOG_DRIVER_LOADED(Caps, Build) \
    TraceLoggingWrite( \
        g_hMonitorEtwProvider, \
        "DriverLoaded", \
        TraceLoggingLevel(MON_ETW_LEVEL_INFO), \
        TraceLoggingKeyword(MON_ETW_KEYWORD_TELEMETRY), \
        TraceLoggingUInt32(MonEtwEvent_DriverLoaded, "EventId"), \
        TraceLoggingHexUInt32((Caps), "Capabilities"), \
        TraceLoggingUInt32((Build), "WindowsBuild"))

/* Usage */
switch (EventId) {
    case MonEtwEvent_DriverLoaded:
        MON_ETW_LOG_DRIVER_LOADED(Capabilities, WindowsBuild);
        break;
    case MonEtwEvent_DriverUnloaded:
        MON_ETW_LOG_DRIVER_UNLOADED(Capabilities, WindowsBuild);
        break;
    // ...
}
```

---

## Stage 2: High Priority Fixes

### 2.1 Add Memory Barriers for Global State

**Files**: `ioring_enum.c`, `telemetry_etw.c`

**Changes**:
```c
/* ioring_enum.c - Initialization */
g_IoRingTypeInfo.ObjectBodySize = (USHORT)g_CurrentOffsets->StructureSize;
KeMemoryBarrier();  /* Ensure all fields visible before Initialized */
InterlockedExchange8((volatile CHAR*)&g_IoRingTypeInfo.Initialized, TRUE);

/* ioring_enum.c - Read path */
if (!ReadBooleanAcquire(&g_IoRingTypeInfo.Initialized)) {
    return STATUS_NOT_SUPPORTED;
}
```

**New Helper** (in `monitor_internal.h`):
```c
FORCEINLINE BOOLEAN ReadBooleanAcquire(_In_ volatile BOOLEAN* Value)
{
    BOOLEAN result = *Value;
    KeMemoryBarrierWithoutFence();  /* Acquire semantics */
    return result;
}
```

---

### 2.2 Add Integer Overflow Protection

**File**: `ioring_enum.c`

```c
/* Before */
bufferSize += 0x10000;

/* After */
#define HANDLE_BUFFER_MARGIN 0x10000

if (bufferSize > (ULONG_MAX - HANDLE_BUFFER_MARGIN)) {
    return STATUS_INTEGER_OVERFLOW;
}
bufferSize += HANDLE_BUFFER_MARGIN;
```

---

### 2.3 Fix SEH Flag Preservation

**File**: `regbuf_integrity.c`

```c
/* Before */
} __except (EXCEPTION_EXECUTE_HANDLER) {
    violations = MON_REGBUF_VF_ACCESS_VIOLATION;  /* OVERWRITES */

/* After */
} __except (EXCEPTION_EXECUTE_HANDLER) {
    violations |= MON_REGBUF_VF_ACCESS_VIOLATION;  /* PRESERVES */
    localInfo.ViolationType |= MON_REGBUF_VF_ACCESS_VIOLATION;
```

---

## Stage 3: Code Quality

### 3.1 Consolidate Duplicate Type Definitions

**Action**: Remove `MON_OFFSET_RESOLUTION_METHOD` from `ioring_enum.h`, use definition from `win11_monitor_public.h`.

**File**: `ioring_enum.h`
```c
/* DELETE lines 103-111 */
/* Type is now defined in win11_monitor_public.h */
```

---

### 3.2 Normalize Naming Conventions

**Files**: Multiple

| Current | New | File |
|---------|-----|------|
| `RegBufInitViolationInfo` | `MonRegBufInitViolationInfo` | regbuf_integrity.c |
| `g_hMonitorEtwProvider` | `g_MonEtwProvider` | telemetry_etw.c |
| `REGBUF_DEFAULT_MAX_ENTRIES` | `MON_REGBUF_DEFAULT_MAX_ENTRIES` | regbuf_integrity.c |
| `REGBUF_ABSOLUTE_MAX_COUNT` | `MON_REGBUF_ABSOLUTE_MAX_COUNT` | regbuf_integrity.c |

---

### 3.3 Extract Magic Numbers to Constants

**File**: `ioring_enum.c`

```c
/* Add to header section */
#define MON_IORING_BUILD_TOLERANCE      100
#define MON_HANDLE_BUFFER_MARGIN        0x10000

/* Update usage */
if (delta >= -MON_IORING_BUILD_TOLERANCE &&
    delta <= MON_IORING_BUILD_TOLERANCE) {
```

---

### 3.4 Add SAL Lock Annotations

**File**: `ioring_enum.h`

```c
/**
 * @function   MonEnumerateIoRingObjects
 * ...
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Requires_lock_not_held_(g_MonitorLock)
NTSTATUS
MonEnumerateIoRingObjects(...);
```

---

## Stage 4: Enhancements

### 4.1 Add Kernel Address Validation Macro

**File**: `monitor_internal.h`

```c
/*
 * Address validation macros.
 * MmUserProbeAddress is the boundary between user and kernel space.
 */
#define MON_IS_KERNEL_ADDRESS(addr) \
    ((ULONG_PTR)(addr) >= MmUserProbeAddress)

#define MON_IS_USER_ADDRESS(addr) \
    ((ULONG_PTR)(addr) < MmUserProbeAddress && (addr) != NULL)

#define MON_VALIDATE_KERNEL_PTR(ptr) \
    do { \
        if ((ptr) == NULL || !MON_IS_KERNEL_ADDRESS(ptr)) { \
            return STATUS_INVALID_PARAMETER; \
        } \
    } while (0)
```

---

### 4.2 Implement ETW Fallback for Legacy Path

**File**: `telemetry_etw.c`

```c
#if !MON_ETW_TRACELOGGING_AVAILABLE
/* Legacy fallback using direct EtwWrite */
static VOID
MonEtwWriteLegacy(
    _In_ USHORT EventId,
    _In_ UCHAR Level,
    _In_ ULONGLONG Keyword,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize
)
{
    if (g_EtwRegHandle == 0) return;

    EVENT_DESCRIPTOR descriptor = {0};
    descriptor.Id = EventId;
    descriptor.Level = Level;
    descriptor.Keyword = Keyword;

    EVENT_DATA_DESCRIPTOR dataDesc;
    EventDataDescCreate(&dataDesc, Data, DataSize);

    EtwWrite(g_EtwRegHandle, &descriptor, NULL, 1, &dataDesc);
}
#endif
```

---

### 4.3 Refactor Long Functions

**File**: `regbuf_integrity.c`

Extract array validation loop:

```c
/* New helper function */
static ULONG
MonValidateRegBuffersArray(
    _In_ PVOID RegBuffers,
    _In_ ULONG RegBuffersCount,
    _In_ ULONG MaxEntriesToInspect,
    _Inout_ PMON_REGBUF_VIOLATION_INFO LocalInfo
);
```

---

## Test Matrix

| Stage | Test | Verification |
|-------|------|--------------|
| 1.1 | Pool allocation | Driver Verifier `UnSafeAllocatePool` passes |
| 1.2 | IoRing enumeration | Callback invoked for IoRing handles |
| 1.3 | ETW events | Event names correct in tracelog |
| 2.1 | Memory barriers | No torn reads under stress |
| 2.2 | Overflow | Returns STATUS_INTEGER_OVERFLOW on crafted input |
| 2.3 | SEH preservation | Multiple flags returned on compound failure |
| 3.* | Code quality | Static analysis clean |
| 4.* | Enhancements | Unit tests pass |

---

## Estimated Effort

| Stage | Files Modified | Lines Changed | Time |
|-------|----------------|---------------|------|
| 1 | 4 | ~200 | 2h |
| 2 | 3 | ~50 | 1h |
| 3 | 5 | ~80 | 1h |
| 4 | 3 | ~150 | 1.5h |
| **Total** | **6** | **~480** | **5.5h** |

---

## Success Criteria

1. ✅ All Driver Verifier checks pass
2. ✅ IoRing enumeration discovers and reports handles
3. ✅ ETW events emit with correct names in tracelog
4. ✅ No compiler warnings at /W4
5. ✅ Static analysis (SDV, PREfast) clean
6. ✅ 24h stress test stable
