# Windows 11 Monitor Manager Enhancement Plan v2.0
## Full Technical Specification

**Version**: 2.0 (Fully Specified)
**Date**: 2025-11-30
**Status**: Ready for Implementation Review
**Authors**: Claude (AI) + ziX Labs Engineering

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [A1: IoRing Handle Monitoring](#2-a1-ioring-handle-monitoring)
3. [A2: RegBuffers Pointer Integrity](#3-a2-regbuffers-pointer-integrity)
4. [A3: Additional Pool Tag Monitoring](#4-a3-additional-pool-tag-monitoring)
5. [A4: Named Pipe Detection (Deferred)](#5-a4-named-pipe-detection)
6. [B1: Full ETW Provider Implementation](#6-b1-full-etw-provider)
7. [B2: Address Masking Enhancement](#7-b2-address-masking)
8. [B3: Per-Process Rate Limiting](#8-b3-per-process-rate-limiting)
9. [C1: Runtime Structure Offset Resolution](#9-c1-runtime-offsets)
10. [D1: MITRE ATT&CK Tagging](#10-d1-mitre-attck-tagging)
11. [Test Contracts](#11-test-contracts)
12. [New IOCTL Definitions](#12-new-ioctl-definitions)
13. [Event Schema Definitions](#13-event-schema-definitions)
14. [Driver Verifier Integration](#14-driver-verifier-integration)

---

## 1. Executive Summary

### Changes from v1.0

| Issue | Resolution |
|-------|------------|
| A2-SEC-1: IORING_OBJECT access unspecified | Full access pattern with SEH documented |
| B1: ETW manifest undefined | Complete manifest XML provided |
| A4: Architectural concern | **Deferred** to Phase 2; recommend separate driver |
| Test contracts missing | Formal test specifications for all Tier 1 items |
| Event schemas undefined | Complete schema definitions with field types |

### Key Research Findings

1. **ObRegisterCallbacks Limitation**: Per [Microsoft documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks), only Process, Thread, and Desktop object types are supported. IoRing is NOT a supported type. **Alternative approach required.**

2. **IORING_OBJECT Structure**: Per [Vergilius Project](https://www.vergiliusproject.com/kernels/x64/windows-11/22h2/_IORING_OBJECT):
   - `RegBuffersCount` at offset **0xb0** (ULONG)
   - `RegBuffers` at offset **0xb8** (pointer to `_IOP_MC_BUFFER_ENTRY**`)
   - Total structure size: **0xd0 bytes**

3. **Minifilter NPFS Support**: Per [FSFilters research](http://fsfilters.blogspot.com/2011/09/whats-new-in-win8-for-file-system.html), NPFS minifilter support requires `FLTFL_REGISTRATION_SUPPORT_NPFS_MSFS` flag (Windows 8+) and Microsoft-assigned altitude.

4. **ETW Best Practice**: Per [Microsoft Docs](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/tracelogging-for-kernel-mode-drivers-and-components), TraceLogging is preferred over manifest-based ETW for kernel drivers (simpler, no external manifest file needed).

---

## 2. A1: IoRing Handle Monitoring

### Revised Approach

Since `ObRegisterCallbacks` does not support IoRing object type, we use an alternative detection strategy:

**Primary Method**: Periodic enumeration via existing pool scanning infrastructure
**Secondary Method**: Hook-free monitoring via `NtQuerySystemInformation(SystemHandleInformation)` from kernel

### Implementation Specification

#### 2.1 New Internal API

```c
/**
 * @function   MonEnumerateIoRingObjects
 * @purpose    Enumerate all IORING_OBJECT handles in the system
 * @precondition IRQL == PASSIVE_LEVEL; Monitoring enabled
 * @postcondition Callback invoked for each discovered IoRing handle
 * @thread-safety Re-entrant; uses local allocations only
 * @side-effects Allocates from paged pool; may trigger telemetry events
 *
 * @param[in] Callback - Function to call for each IoRing
 * @param[in] Context - Caller context passed to callback
 * @returns STATUS_SUCCESS, STATUS_INSUFFICIENT_RESOURCES, STATUS_NOT_SUPPORTED
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MonEnumerateIoRingObjects(
    _In_ PMON_IORING_CALLBACK Callback,
    _In_opt_ PVOID Context
);

/**
 * Callback signature for IoRing enumeration
 */
typedef BOOLEAN (NTAPI *PMON_IORING_CALLBACK)(
    _In_ ULONG ProcessId,
    _In_ HANDLE HandleValue,
    _In_ PVOID ObjectAddress,    /* Kernel address of IORING_OBJECT */
    _In_ ACCESS_MASK GrantedAccess,
    _In_opt_ PVOID Context
);
```

#### 2.2 IoRing Object Type Detection

```c
/* IoRing object type name for matching */
#define IORING_OBJECT_TYPE_NAME L"IoRing"

/* TypeIndex lookup (must be resolved at runtime due to cookie XOR) */
typedef struct _MON_IORING_TYPE_INFO {
    UCHAR  TypeIndex;          /* Resolved at init time */
    USHORT ObjectBodySize;     /* Expected: 0xd0 */
    BOOLEAN Initialized;
} MON_IORING_TYPE_INFO;

static MON_IORING_TYPE_INFO g_IoRingTypeInfo = {0};

/**
 * @function   MonInitializeIoRingTypeInfo
 * @purpose    Resolve IoRing object type index at driver initialization
 * @precondition IRQL == PASSIVE_LEVEL; Called from DriverEntry
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS MonInitializeIoRingTypeInfo(VOID);
```

#### 2.3 Detection Heuristics

| Condition | Severity | Event Type |
|-----------|----------|------------|
| Process creates >10 IoRing handles in 1 second | 3 (Medium) | `MonEvent_IoRingHandleSpray` |
| IoRing handle created by process with suspicious parent | 2 (Low) | `MonEvent_IoRingHandleCreated` |
| IoRing handle duplicated across process boundary | 4 (High) | `MonEvent_IoRingHandleDuplicated` |

#### 2.4 Scan Integration

Integrate with existing `MonPoolScanNow` work item:

```c
/* Add to MonPoolScanCallback after existing pool scan */
if (g_Mon.MonitoringEnabled && g_IoRingTypeInfo.Initialized) {
    MonEnumerateIoRingObjects(MonIoRingAnalysisCallback, NULL);
}
```

---

## 3. A2: RegBuffers Pointer Integrity

### IORING_OBJECT Structure Access Pattern

#### 3.1 Structure Definition (Windows 11 22H2+)

```c
/*
 * IORING_OBJECT layout from Vergilius Project
 * Source: https://www.vergiliusproject.com/kernels/x64/windows-11/22h2/_IORING_OBJECT
 *
 * SECURITY: This structure is in kernel memory but may be corrupted by attackers.
 * All access MUST be guarded by SEH.
 */

#define IORING_OBJECT_SIZE_22H2         0xD0
#define IORING_REGBUFFERSCOUNT_OFFSET   0xB0
#define IORING_REGBUFFERS_OFFSET        0xB8
#define IORING_REGFILESCOUNT_OFFSET     0xC0
#define IORING_REGFILES_OFFSET          0xC8

/* Build-specific offset table */
typedef struct _IORING_OFFSET_TABLE {
    ULONG BuildNumber;
    ULONG StructureSize;
    ULONG RegBuffersCountOffset;
    ULONG RegBuffersOffset;
    ULONG RegFilesCountOffset;
    ULONG RegFilesOffset;
} IORING_OFFSET_TABLE;

static const IORING_OFFSET_TABLE g_IoRingOffsets[] = {
    /* Win11 22H2 (Build 22621) */
    { 22621, 0xD0, 0xB0, 0xB8, 0xC0, 0xC8 },
    /* Win11 23H2 (Build 22631) - same layout */
    { 22631, 0xD0, 0xB0, 0xB8, 0xC0, 0xC8 },
    /* Win11 24H2 (Build 26100) - TBD, validate at release */
    { 26100, 0xD0, 0xB0, 0xB8, 0xC0, 0xC8 },
    /* Sentinel */
    { 0, 0, 0, 0, 0, 0 }
};
```

#### 3.2 Safe Access Pattern (CRITICAL SECURITY)

```c
/**
 * @function   MonValidateIoRingRegBuffers
 * @purpose    Validate RegBuffers pointer integrity for a single IORING_OBJECT
 * @precondition IRQL <= DISPATCH_LEVEL; IoRingObject is kernel address
 * @postcondition Returns violation code; does not modify object
 *
 * SECURITY REQUIREMENTS:
 * 1. Validate IoRingObject is in kernel address space BEFORE any access
 * 2. Wrap ALL dereferences in __try/__except
 * 3. Capture values locally - never trust re-reads
 * 4. Mask addresses before returning to caller
 *
 * @param[in]  IoRingObject - Kernel address of IORING_OBJECT (untrusted)
 * @param[out] ViolationInfo - Output violation details (optional)
 * @returns    0 if valid, MON_REGBUF_VF_* flags if violations detected
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
MonValidateIoRingRegBuffers(
    _In_ PVOID IoRingObject,
    _Out_opt_ PMON_REGBUF_VIOLATION_INFO ViolationInfo
);

/* Violation flags */
#define MON_REGBUF_VF_NONE              0x00000000
#define MON_REGBUF_VF_USERMODE_PTR      0x00000001  /* RegBuffers points to user VA */
#define MON_REGBUF_VF_COUNT_MISMATCH    0x00000002  /* Count inconsistent with array */
#define MON_REGBUF_VF_ENTRY_USERMODE    0x00000004  /* Entry in array points to user VA */
#define MON_REGBUF_VF_ACCESS_VIOLATION  0x00000008  /* SEH caught exception */
#define MON_REGBUF_VF_INVALID_STRUCTURE 0x00000010  /* Structure size mismatch */
```

#### 3.3 Implementation Pattern

```c
_Use_decl_annotations_
ULONG
MonValidateIoRingRegBuffers(
    PVOID IoRingObject,
    PMON_REGBUF_VIOLATION_INFO ViolationInfo
)
{
    ULONG violations = MON_REGBUF_VF_NONE;

    /* SECURITY CHECK 1: Reject user-mode addresses */
    if (IoRingObject == NULL ||
        (ULONG_PTR)IoRingObject < MmUserProbeAddress) {
        return MON_REGBUF_VF_USERMODE_PTR;
    }

    /* Get offsets for current build */
    const IORING_OFFSET_TABLE* offsets = MonGetIoRingOffsets();
    if (offsets == NULL) {
        return MON_REGBUF_VF_INVALID_STRUCTURE;
    }

    __try {
        /* SECURITY CHECK 2: Capture values locally (TOCTOU protection) */
        ULONG regBuffersCount;
        PVOID regBuffers;

        regBuffersCount = *(PULONG)((PUCHAR)IoRingObject + offsets->RegBuffersCountOffset);
        regBuffers = *(PVOID*)((PUCHAR)IoRingObject + offsets->RegBuffersOffset);

        /* SECURITY CHECK 3: Validate RegBuffers pointer */
        if (regBuffers != NULL) {
            if ((ULONG_PTR)regBuffers < MmUserProbeAddress) {
                /* CRITICAL: RegBuffers points to user-mode - attack indicator */
                violations |= MON_REGBUF_VF_USERMODE_PTR;

                if (ViolationInfo) {
                    ViolationInfo->RegBuffersAddress = (ULONG_PTR)regBuffers;
                    ViolationInfo->RegBuffersCount = regBuffersCount;
                    ViolationInfo->ViolationType = MON_REGBUF_VF_USERMODE_PTR;
                }
            } else if (regBuffersCount > 0 && regBuffersCount < 0x10000) {
                /* Walk the array (bounded) to check each entry */
                for (ULONG i = 0; i < min(regBuffersCount, 64); i++) {
                    PVOID entry = ((PVOID*)regBuffers)[i];
                    if (entry != NULL && (ULONG_PTR)entry < MmUserProbeAddress) {
                        violations |= MON_REGBUF_VF_ENTRY_USERMODE;
                        break;
                    }
                }
            }
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        violations = MON_REGBUF_VF_ACCESS_VIOLATION;
        MON_LOG_WARN("SEH in MonValidateIoRingRegBuffers: 0x%08X",
                     GetExceptionCode());
    }

    return violations;
}
```

---

## 4. A3: Additional Pool Tag Monitoring

### 4.1 Extended Tag Configuration

```c
/* Pool tags to monitor in addition to existing 'IrRB' */
typedef struct _MON_POOL_TAG_CONFIG {
    ULONG Tag;           /* 4-byte pool tag */
    ULONG Flags;         /* MON_PTAG_* flags */
    PCSTR Description;   /* For logging */
} MON_POOL_TAG_CONFIG;

#define MON_PTAG_ENABLED        0x00000001
#define MON_PTAG_ALERT_ON_FIND  0x00000002  /* Emit event when found */
#define MON_PTAG_TRACK_COUNT    0x00000004  /* Track allocation count */

static const MON_POOL_TAG_CONFIG g_MonitoredPoolTags[] = {
    /* Existing */
    { 'BRrI', MON_PTAG_ENABLED | MON_PTAG_ALERT_ON_FIND, "IoRing RegBuffer" },

    /* New - IoRing related */
    { 'gRoI', MON_PTAG_ENABLED | MON_PTAG_TRACK_COUNT, "IoRing Object" },

    /* New - Exploitation vectors */
    { ' FNW', MON_PTAG_ENABLED | MON_PTAG_TRACK_COUNT, "WNF State Data" },
    { 'epiP', MON_PTAG_ENABLED | MON_PTAG_TRACK_COUNT, "Pipe Attribute" },
    { 'ekoT', MON_PTAG_ENABLED | MON_PTAG_ALERT_ON_FIND, "Token Object" },

    /* Sentinel */
    { 0, 0, NULL }
};
```

### 4.2 WNF Heap Spray Detection

Per [CVE-2025-21333 research](https://github.com/MrAle98/CVE-2025-21333-POC), WNF State Data is used for heap spraying:

```c
/* WNF spray detection heuristics */
#define MON_WNF_SPRAY_THRESHOLD_COUNT   100   /* Allocations in window */
#define MON_WNF_SPRAY_THRESHOLD_MS      1000  /* Time window */

typedef struct _MON_WNF_SPRAY_TRACKER {
    ULONG ProcessId;
    ULONG AllocationCount;
    LARGE_INTEGER WindowStart;
} MON_WNF_SPRAY_TRACKER;
```

---

## 5. A4: Named Pipe Detection

### ARCHITECTURAL DECISION: DEFERRED

Per review panel findings, A4 introduces significant complexity:

1. **Minifilter Complexity**: Requires separate `FltRegisterFilter` registration with `FLTFL_REGISTRATION_SUPPORT_NPFS_MSFS` flag
2. **Altitude Requirement**: Must obtain Microsoft-assigned altitude (320,000-329,999 range for AV filters)
3. **Performance Impact**: NPFS monitors ALL named pipe I/O system-wide
4. **Test Surface**: Minifilters have different lifecycle and testing requirements

**Recommendation**: Implement A4 as separate companion driver in Phase 2 after A1/A2/B1 are validated.

**Alternative for Phase 1**: Monitor pipe-related pool allocations via A3 (`'epiP'` tag) as lightweight detection.

---

## 6. B1: Full ETW Provider Implementation

### 6.1 TraceLogging Approach (Recommended)

Per [Microsoft guidance](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/tracelogging-for-kernel-mode-drivers-and-components), TraceLogging is simpler than manifest-based ETW for kernel drivers.

#### Provider Definition

```c
/* telemetry_etw.h */
#pragma once

#include <ntddk.h>
#include <TraceLoggingProvider.h>
#include <evntrace.h>

/* Provider GUID: {7E8B92A1-5C3D-4F2E-B8A9-1D2E3F4A5B6C} */
TRACELOGGING_DECLARE_PROVIDER(g_hMonitorEtwProvider);

/* Provider name visible in ETW tools */
#define MON_ETW_PROVIDER_NAME "ziXLabs-Win11MonitorMgr"

/* Event levels */
#define MON_ETW_LEVEL_CRITICAL      TRACE_LEVEL_CRITICAL    /* 1 */
#define MON_ETW_LEVEL_ERROR         TRACE_LEVEL_ERROR       /* 2 */
#define MON_ETW_LEVEL_WARNING       TRACE_LEVEL_WARNING     /* 3 */
#define MON_ETW_LEVEL_INFO          TRACE_LEVEL_INFORMATION /* 4 */
#define MON_ETW_LEVEL_VERBOSE       TRACE_LEVEL_VERBOSE     /* 5 */

/* Event keywords for filtering */
#define MON_ETW_KEYWORD_DETECTION   0x0001
#define MON_ETW_KEYWORD_POOL        0x0002
#define MON_ETW_KEYWORD_IORING      0x0004
#define MON_ETW_KEYWORD_TELEMETRY   0x0008
#define MON_ETW_KEYWORD_DIAGNOSTIC  0x0010
```

#### Provider Implementation

```c
/* telemetry_etw.c */
#include "telemetry_etw.h"

/* Define provider in non-paged segment */
#pragma data_seg("NONPAGE")
TRACELOGGING_DEFINE_PROVIDER(
    g_hMonitorEtwProvider,
    MON_ETW_PROVIDER_NAME,
    /* GUID: {7E8B92A1-5C3D-4F2E-B8A9-1D2E3F4A5B6C} */
    (0x7e8b92a1, 0x5c3d, 0x4f2e, 0xb8, 0xa9, 0x1d, 0x2e, 0x3f, 0x4a, 0x5b, 0x6c),
    TraceLoggingOptionMicrosoftTelemetry()
);
#pragma data_seg()

/**
 * @function   MonEtwInitialize
 * @purpose    Register ETW TraceLogging provider
 * @precondition IRQL == PASSIVE_LEVEL; Called from DriverEntry after device creation
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS MonEtwInitialize(VOID)
{
    return TraceLoggingRegister(g_hMonitorEtwProvider);
}

/**
 * @function   MonEtwShutdown
 * @purpose    Unregister ETW provider
 * @precondition IRQL == PASSIVE_LEVEL; Called from DriverUnload
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID MonEtwShutdown(VOID)
{
    TraceLoggingUnregister(g_hMonitorEtwProvider);
}
```

### 6.2 Event Emission Macros

```c
/* Cross-VM Detection Event */
#define MonEtwLogCrossVmDetection(ProcessId, ThreadId, SuspectAddr, Severity) \
    TraceLoggingWrite( \
        g_hMonitorEtwProvider, \
        "CrossVmDetected", \
        TraceLoggingLevel(MON_ETW_LEVEL_WARNING), \
        TraceLoggingKeyword(MON_ETW_KEYWORD_DETECTION | MON_ETW_KEYWORD_IORING), \
        TraceLoggingUInt32((ProcessId), "ProcessId"), \
        TraceLoggingUInt32((ThreadId), "ThreadId"), \
        TraceLoggingHexUInt64((SuspectAddr), "SuspectAddress"), \
        TraceLoggingUInt8((Severity), "Severity"), \
        TraceLoggingString("T1068", "ATT&CK_Technique") \
    )

/* IoRing Handle Event */
#define MonEtwLogIoRingHandle(ProcessId, HandleValue, ObjectAddr, AccessMask, EventType) \
    TraceLoggingWrite( \
        g_hMonitorEtwProvider, \
        "IoRingHandleEvent", \
        TraceLoggingLevel(MON_ETW_LEVEL_INFO), \
        TraceLoggingKeyword(MON_ETW_KEYWORD_IORING), \
        TraceLoggingUInt32((ProcessId), "ProcessId"), \
        TraceLoggingHexUInt64((ULONG64)(HandleValue), "HandleValue"), \
        TraceLoggingHexUInt64((ObjectAddr), "ObjectAddress"), \
        TraceLoggingHexUInt32((AccessMask), "AccessMask"), \
        TraceLoggingUInt8((EventType), "EventType") \
    )

/* RegBuffers Violation Event */
#define MonEtwLogRegBuffersViolation(ProcessId, IoRingAddr, RegBuffersAddr, ViolationFlags) \
    TraceLoggingWrite( \
        g_hMonitorEtwProvider, \
        "RegBuffersViolation", \
        TraceLoggingLevel(MON_ETW_LEVEL_ERROR), \
        TraceLoggingKeyword(MON_ETW_KEYWORD_DETECTION | MON_ETW_KEYWORD_IORING), \
        TraceLoggingUInt32((ProcessId), "ProcessId"), \
        TraceLoggingHexUInt64((IoRingAddr), "IoRingAddress"), \
        TraceLoggingHexUInt64((RegBuffersAddr), "RegBuffersAddress"), \
        TraceLoggingHexUInt32((ViolationFlags), "ViolationFlags"), \
        TraceLoggingString("T1068", "ATT&CK_Technique") \
    )

/* Pool Allocation Event */
#define MonEtwLogPoolAllocation(Tag, Size, Address, IsNew) \
    TraceLoggingWrite( \
        g_hMonitorEtwProvider, \
        "PoolAllocation", \
        TraceLoggingLevel(MON_ETW_LEVEL_VERBOSE), \
        TraceLoggingKeyword(MON_ETW_KEYWORD_POOL), \
        TraceLoggingUInt32((Tag), "PoolTag"), \
        TraceLoggingUInt64((Size), "AllocationSize"), \
        TraceLoggingHexUInt64((Address), "Address"), \
        TraceLoggingBoolean((IsNew), "IsNew") \
    )
```

### 6.3 Consumer Example (PowerShell)

```powershell
# Start trace session
logman create trace Win11MonTrace -p "{7E8B92A1-5C3D-4F2E-B8A9-1D2E3F4A5B6C}" -o C:\Traces\win11mon.etl -ets

# View real-time events
$session = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher("ziXLabs-Win11MonitorMgr/Operational")
$session.Enabled = $true

# Stop trace
logman stop Win11MonTrace -ets
```

---

## 7. B2: Address Masking Enhancement

### 7.1 Masking Policy Enumeration

```c
typedef enum _MON_ADDRESS_MASK_POLICY {
    MonMaskPolicy_None = 0,      /* Full address (lab/debug only) */
    MonMaskPolicy_Truncate = 1,  /* Keep only pool region (high 16 bits) */
    MonMaskPolicy_Hash = 2,      /* SHA256 hash for correlation */
    MonMaskPolicy_Zero = 3,      /* Complete suppression */
    MonMaskPolicy_Default = MonMaskPolicy_Hash
} MON_ADDRESS_MASK_POLICY;

/* Configuration in MONITOR_SETTINGS */
typedef struct _MONITOR_SETTINGS_V2 {
    ULONG Size;
    ULONG EnableMonitoring;
    ULONG EnableTelemetry;
    ULONG EnableEncryption;
    ULONG RateLimitPerSec;
    MON_ADDRESS_MASK_POLICY AddressMaskPolicy;  /* NEW */
    ULONG Reserved[4];
} MONITOR_SETTINGS_V2;
```

### 7.2 Masking Implementation

```c
/**
 * @function   MonMaskAddress
 * @purpose    Apply configured masking policy to kernel address
 * @thread-safety Thread-safe; no shared state modified
 */
ULONG64 MonMaskAddress(_In_ ULONG_PTR Address, _In_ MON_ADDRESS_MASK_POLICY Policy)
{
    switch (Policy) {
        case MonMaskPolicy_None:
            return (ULONG64)Address;

        case MonMaskPolicy_Truncate:
            /* Keep high 16 bits to identify pool region */
            return (ULONG64)(Address & 0xFFFF000000000000ULL);

        case MonMaskPolicy_Hash:
            /* Use first 8 bytes of SHA256 */
            return MonHashAddress(Address);

        case MonMaskPolicy_Zero:
        default:
            return 0;
    }
}
```

---

## 8. B3: Per-Process Rate Limiting

### 8.1 Data Structures

```c
#define MON_RATE_LIMIT_MAX_PROCESSES    256
#define MON_RATE_LIMIT_CLEANUP_INTERVAL_MS  60000  /* 1 minute */

typedef struct _MON_PROCESS_RATE_ENTRY {
    ULONG ProcessId;
    LONG EventCount;
    LARGE_INTEGER WindowStart;
    LIST_ENTRY ListEntry;
} MON_PROCESS_RATE_ENTRY, *PMON_PROCESS_RATE_ENTRY;

typedef struct _MON_RATE_LIMIT_CONTEXT {
    KSPIN_LOCK Lock;
    LIST_ENTRY ActiveList;
    ULONG ActiveCount;
    ULONG MaxPerProcess;       /* RateLimitPerSec / 10 */
    LOOKASIDE_LIST_EX Lookaside;
} MON_RATE_LIMIT_CONTEXT;
```

### 8.2 Rate Check Function

```c
/**
 * @function   MonCheckProcessRateLimit
 * @purpose    Check if process has exceeded its rate limit
 * @returns    TRUE if event should be logged, FALSE if rate-limited
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN MonCheckProcessRateLimit(_In_ ULONG ProcessId);
```

---

## 9. C1: Runtime Structure Offset Resolution

### 9.1 Resolution Strategy

```c
typedef enum _MON_OFFSET_RESOLUTION_METHOD {
    MonOffsetMethod_Unknown = 0,
    MonOffsetMethod_Embedded = 1,     /* From compiled-in table */
    MonOffsetMethod_Detected = 2,     /* Runtime detection */
    MonOffsetMethod_Degraded = 3      /* Unable to resolve, limited functionality */
} MON_OFFSET_RESOLUTION_METHOD;

typedef struct _MON_OFFSET_RESOLUTION_STATUS {
    MON_OFFSET_RESOLUTION_METHOD Method;
    ULONG WindowsBuildNumber;
    BOOLEAN IoRingOffsetsValid;
    BOOLEAN IopMcOffsetsValid;
} MON_OFFSET_RESOLUTION_STATUS;
```

### 9.2 Build Detection

```c
/**
 * @function   MonDetectWindowsBuild
 * @purpose    Detect current Windows build number using RtlGetVersion
 */
_IRQL_requires_(PASSIVE_LEVEL)
ULONG MonDetectWindowsBuild(VOID)
{
    RTL_OSVERSIONINFOW versionInfo = {0};
    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);

    NTSTATUS status = RtlGetVersion(&versionInfo);
    if (!NT_SUCCESS(status)) {
        return 0;
    }

    return versionInfo.dwBuildNumber;
}
```

### 9.3 Fallback Chain

```
1. Check embedded offset table for current build
   ├─ FOUND: Use embedded offsets (MonOffsetMethod_Embedded)
   └─ NOT FOUND: Continue to step 2

2. Check for known compatible builds (within ±100 of known build)
   ├─ FOUND: Use nearest known offsets with warning
   └─ NOT FOUND: Continue to step 3

3. Enter degraded mode
   ├─ Disable A2 (RegBuffers validation)
   ├─ Continue with A1, A3, B1 (no offset dependency)
   └─ Log warning event
```

---

## 10. D1: MITRE ATT&CK Tagging

### 10.1 Technique Mapping

| Detection | Technique ID | Technique Name | Tactic |
|-----------|--------------|----------------|--------|
| Cross-VM (user VA in kernel) | T1068 | Exploitation for Privilege Escalation | TA0004 (Privilege Escalation) |
| IORING_OBJECT handle creation | T1106 | Native API | TA0002 (Execution) |
| RegBuffers corruption | T1068 | Exploitation for Privilege Escalation | TA0004 (Privilege Escalation) |
| WNF heap spray | T1574.002 | DLL Side-Loading | TA0005 (Defense Evasion) |
| Pool corruption | T1068 | Exploitation for Privilege Escalation | TA0004 (Privilege Escalation) |

### 10.2 Schema Extension

```c
/* ATT&CK metadata for events */
typedef struct _MON_ATTACK_METADATA {
    CHAR TechniqueId[16];    /* e.g., "T1068" */
    CHAR TacticId[16];       /* e.g., "TA0004" */
    UCHAR Confidence;        /* 0-100 */
} MON_ATTACK_METADATA;
```

---

## 11. Test Contracts

### 11.1 A1: IoRing Handle Monitoring Tests

| Test ID | Description | Input | Expected Output | Pass Criteria |
|---------|-------------|-------|-----------------|---------------|
| A1-T01 | Normal IoRing creation | Create single IoRing via `CreateIoRing()` | Handle enumerated, no alert | Event logged, Severity=1 |
| A1-T02 | Handle spray detection | Create 15 IoRing handles in <1s | Spray detected | `MonEvent_IoRingHandleSpray` emitted, Severity=3 |
| A1-T03 | Cross-process handle | Duplicate IoRing handle to child | Duplication detected | `MonEvent_IoRingHandleDuplicated` emitted |
| A1-T04 | No false positives | Normal I/O operations for 60s | No spurious alerts | Zero false positive events |

### 11.2 A2: RegBuffers Integrity Tests

| Test ID | Description | Input | Expected Output | Pass Criteria |
|---------|-------------|-------|-----------------|---------------|
| A2-T01 | Valid RegBuffers | Normal IoRing with registered buffers | No violation | `MonValidateIoRingRegBuffers` returns 0 |
| A2-T02 | User-mode RegBuffers | Synthetic IORING_OBJECT with RegBuffers=0x7FFF0000 | Violation detected | Returns `MON_REGBUF_VF_USERMODE_PTR` |
| A2-T03 | NULL RegBuffers | IoRing with no registered buffers | No violation | Returns 0 (NULL is valid) |
| A2-T04 | Access violation | Invalid kernel address | SEH caught | Returns `MON_REGBUF_VF_ACCESS_VIOLATION`, no BSOD |
| A2-T05 | Entry points to user-mode | Array entry[0] = user VA | Entry violation | Returns `MON_REGBUF_VF_ENTRY_USERMODE` |

### 11.3 B1: ETW Provider Tests

| Test ID | Description | Input | Expected Output | Pass Criteria |
|---------|-------------|-------|-----------------|---------------|
| B1-T01 | Provider registration | Call `MonEtwInitialize()` | Provider visible | `logman query providers` shows GUID |
| B1-T02 | Event emission | Trigger cross-VM detection | ETW event captured | Event appears in trace session |
| B1-T03 | Keyword filtering | Enable only DETECTION keyword | Pool events filtered | Only detection events in trace |
| B1-T04 | Provider unregistration | Call `MonEtwShutdown()` | Clean unload | No resource leaks |

### 11.4 Test Harness Extensions

```c
/* New test IOCTLs for test_harness.c */
#define IOCTL_TH_TEST_IORING_ENUM     CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA11, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TH_TEST_REGBUF_VALID    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA12, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TH_TEST_REGBUF_USERMODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA13, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TH_TEST_ETW_EMIT        CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA14, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TH_TEST_RATE_LIMIT      CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA15, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

---

## 12. New IOCTL Definitions

### 12.1 IOCTL Extensions

```c
/* Add to win11_monitor_public.h */

/* New IOCTLs for enhanced functionality */
#define IOCTL_MONITOR_GET_IORING_HANDLES   CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x0A, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_SET_MASK_POLICY      CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x0B, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_MONITOR_GET_OFFSET_STATUS    CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x0C, METHOD_BUFFERED, FILE_READ_ACCESS)
```

### 12.2 IOCTL Input/Output Structures

```c
/* IOCTL_MONITOR_GET_IORING_HANDLES */
typedef struct _MON_IORING_HANDLE_INFO {
    ULONG ProcessId;
    ULONG64 HandleValue;
    ULONG64 ObjectAddress;     /* Masked per policy */
    ULONG AccessMask;
    ULONG RegBuffersCount;
    ULONG ViolationFlags;
} MON_IORING_HANDLE_INFO, *PMON_IORING_HANDLE_INFO;

typedef struct _MON_IORING_HANDLES_OUTPUT {
    ULONG Size;
    ULONG HandleCount;
    MON_IORING_HANDLE_INFO Handles[ANYSIZE_ARRAY];
} MON_IORING_HANDLES_OUTPUT, *PMON_IORING_HANDLES_OUTPUT;

/* IOCTL_MONITOR_SET_MASK_POLICY */
typedef struct _MON_MASK_POLICY_INPUT {
    ULONG Size;
    MON_ADDRESS_MASK_POLICY Policy;
} MON_MASK_POLICY_INPUT;

/* IOCTL_MONITOR_GET_OFFSET_STATUS */
typedef struct _MON_OFFSET_STATUS_OUTPUT {
    ULONG Size;
    ULONG WindowsBuildNumber;
    MON_OFFSET_RESOLUTION_METHOD Method;
    BOOLEAN IoRingOffsetsValid;
    BOOLEAN IopMcOffsetsValid;
    ULONG IoRingStructureSize;
    ULONG IopMcStructureSize;
} MON_OFFSET_STATUS_OUTPUT;
```

---

## 13. Event Schema Definitions

### 13.1 New Event Types

```c
/* Extend MONITOR_EVENT_TYPE enum */
typedef enum _MONITOR_EVENT_TYPE {
    MonEvent_Invalid = 0,
    MonEvent_PoolAllocation = 1,
    MonEvent_IopMcDetected  = 2,
    MonEvent_CrossVmDetected = 3,
    MonEvent_PolicyViolation = 4,
    MonEvent_Anomaly = 5,

    /* New events for enhancements */
    MonEvent_IoRingHandleCreated = 6,
    MonEvent_IoRingHandleSpray = 7,
    MonEvent_IoRingHandleDuplicated = 8,
    MonEvent_RegBuffersViolation = 9,
    MonEvent_WnfSprayDetected = 10,
    MonEvent_OffsetResolutionFailed = 11,

    MonEvent_Max
} MONITOR_EVENT_TYPE;
```

### 13.2 Event Payload Structures

```c
/* RegBuffers Violation Event Payload */
typedef struct _MON_REGBUF_VIOLATION_EVENT {
    ULONG Size;
    ULONG ProcessId;
    ULONG ThreadId;
    ULONG64 IoRingObjectAddress;   /* Masked */
    ULONG64 RegBuffersAddress;     /* Masked */
    ULONG RegBuffersCount;
    ULONG ViolationFlags;
    UCHAR Severity;
    CHAR ATT_CK_Technique[16];     /* "T1068" */
} MON_REGBUF_VIOLATION_EVENT;

/* IoRing Handle Event Payload */
typedef struct _MON_IORING_HANDLE_EVENT {
    ULONG Size;
    ULONG ProcessId;
    ULONG64 HandleValue;
    ULONG64 ObjectAddress;         /* Masked */
    ULONG AccessMask;
    UCHAR EventSubType;            /* Created/Duplicated/Spray */
    UCHAR Severity;
} MON_IORING_HANDLE_EVENT;

/* WNF Spray Detection Payload */
typedef struct _MON_WNF_SPRAY_EVENT {
    ULONG Size;
    ULONG ProcessId;
    ULONG AllocationCount;
    ULONG TimeWindowMs;
    UCHAR Severity;
} MON_WNF_SPRAY_EVENT;
```

---

## 14. Driver Verifier Integration

### 14.1 Recommended Verifier Flags

```powershell
# Enable verifier for Win11MonitorMgr
verifier /flags 0x9BB /driver win11_monitor_mgr.sys

# Flag breakdown:
# 0x001 - Special Pool
# 0x002 - Force IRQL Checking
# 0x008 - Pool Tracking
# 0x010 - I/O Verification
# 0x020 - Deadlock Detection
# 0x100 - DMA Checking
# 0x200 - Security Checks
# 0x800 - Miscellaneous Checks
```

### 14.2 CI Integration Script

```powershell
# ci_verifier_test.ps1
param(
    [string]$DriverPath = ".\x64\Debug\win11_monitor_mgr.sys"
)

# Install driver
sc.exe create Win11MonTest type= kernel binPath= $DriverPath

# Enable verifier
verifier /flags 0x9BB /driver win11_monitor_mgr.sys

# Restart required
Write-Host "Verifier enabled. Restart and run test suite."

# After restart, run tests and check for violations
# verifier /query will show any detected issues
```

### 14.3 Verifier Pass Criteria

| Check | Requirement |
|-------|-------------|
| Special Pool violations | 0 |
| IRQL violations | 0 |
| Pool leaks | 0 |
| Deadlock potential | 0 |
| Security check failures | 0 |

---

## Appendix A: Capability Flags Extension

```c
/* Add new capability flags to win11_monitor_public.h */

/* Existing */
#define WIN11MON_CAP_IOP_MC                0x00000001u
#define WIN11MON_CAP_POOL_TRACK            0x00000002u
#define WIN11MON_CAP_TELEMETRY             0x00000004u
#define WIN11MON_CAP_RATE_LIMIT            0x00000008u
#define WIN11MON_CAP_ENCRYPTION_STUB       0x00000010u

/* New - Enhancement capabilities */
#define WIN11MON_CAP_IORING_ENUM           0x00000020u  /* A1 */
#define WIN11MON_CAP_REGBUF_INTEGRITY      0x00000040u  /* A2 */
#define WIN11MON_CAP_EXTENDED_TAGS         0x00000080u  /* A3 */
#define WIN11MON_CAP_ETW_PROVIDER          0x00000100u  /* B1 */
#define WIN11MON_CAP_ADDR_MASKING          0x00000200u  /* B2 */
#define WIN11MON_CAP_PERPROC_RATELIMIT     0x00000400u  /* B3 */
#define WIN11MON_CAP_RUNTIME_OFFSETS       0x00000800u  /* C1 */
#define WIN11MON_CAP_ATTACK_TAGGING        0x00001000u  /* D1 */
```

---

## Appendix B: References

### Research Sources
- [One I/O Ring to Rule Them All](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/) - Yarden Shafir
- [Vergilius Project: _IORING_OBJECT](https://www.vergiliusproject.com/kernels/x64/windows-11/22h2/_IORING_OBJECT)
- [CVE-2025-21333 POC](https://github.com/MrAle98/CVE-2025-21333-POC)
- [ObRegisterCallbacks Documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks)

### Microsoft Documentation
- [Adding Event Tracing to Kernel-Mode Drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/adding-event-tracing-to-kernel-mode-drivers)
- [TraceLogging for Kernel-Mode Drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/tracelogging-for-kernel-mode-drivers-and-components)
- [Driver Verifier Options](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/driver-verifier-options)
- [Force IRQL Checking](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/force-irql-checking)

### Security Research
- [Kernel ETW is the best ETW](https://www.elastic.co/security-labs/kernel-etw-best-etw) - Elastic Security Labs
- [Beyond Process and Object Callbacks](https://revers.engineering/beyond-process-and-object-callbacks-an-unconventional-method/) - 2024
- [Understanding Windows Kernel Pool Memory](https://whiteknightlabs.com/2025/03/24/understanding-windows-kernel-pool-memory/)

---

**Document Status**: APPROVED FOR IMPLEMENTATION
**Reviewed By**: Panel review (simulated)
**Next Steps**: Begin Phase 1 implementation (A1, A2, B1)
