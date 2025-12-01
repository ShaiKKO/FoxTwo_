# Phase 5 Implementation Plan: Ring Buffer Telemetry, Dynamic Offsets, and Usermode Client

**Author:** Colin MacRitchie | ziX Labs
**Date:** 2025-12-01
**Version:** 1.0

---

## Overview

This plan details the implementation of three major features:
1. **Ring Buffer Telemetry System** - Circular buffer for efficient event storage
2. **Dynamic Offset Resolution** - Runtime PDB parsing for cross-version compatibility
3. **Usermode Client Library** - Clean C API wrapper for driver interaction

---

## Feature 1: Ring Buffer Telemetry System

### 1.1 Problem Statement

The current SLIST-based event queue has limitations:
- Unbounded memory growth under heavy event load
- No ability to retrieve historical events after consumption
- Memory fragmentation from individual allocations
- No snapshot capability for diagnostics

### 1.2 Design Goals

- **Fixed memory footprint** (configurable, default 1MB)
- **Lock-free producer** (single writer from pool scan context)
- **Snapshot capability** for diagnostics without draining
- **Automatic overwrite** of oldest events when full
- **IRQL-safe** up to DISPATCH_LEVEL

### 1.3 Architecture

```
+-------------------+
|   Ring Buffer     |
|   Control Block   |
+-------------------+
| Base              | --> Allocated NonPaged memory
| End               | --> Base + BufferSize
| WriteOffset (vol) | --> Next write position (atomic)
| ReadOffset (vol)  | --> Consumer read position (atomic)
| WrapCount (vol)   | --> Full cycle count for overflow detection
| BufferSize        | --> Total bytes allocated
| EventCount (vol)  | --> Current event count
| SpinLock          | --> For multi-reader serialization
+-------------------+
```

### 1.4 Data Structures

```c
/* telemetry_ringbuf.h */

#define MON_RINGBUF_DEFAULT_SIZE    (1024 * 1024)   /* 1MB default */
#define MON_RINGBUF_MIN_SIZE        (64 * 1024)     /* 64KB minimum */
#define MON_RINGBUF_MAX_SIZE        (16 * 1024 * 1024) /* 16MB maximum */
#define MON_RINGBUF_ALIGNMENT       64              /* Cache line alignment */

/* Ring buffer event header (stored in ring) */
typedef struct _MON_RING_EVENT_HEADER {
    ULONG           Magic;          /* 'REVT' validation */
    ULONG           TotalSize;      /* Including header and padding */
    ULONG           PayloadSize;    /* Actual data size */
    MONITOR_EVENT_TYPE EventType;
    LARGE_INTEGER   Timestamp;
    ULONG           ProcessId;
    ULONG           ThreadId;
    /* Payload follows */
} MON_RING_EVENT_HEADER, *PMON_RING_EVENT_HEADER;

/* Ring buffer control structure */
typedef struct _MON_RING_BUFFER {
    PUCHAR          Base;           /* Buffer start */
    PUCHAR          End;            /* Buffer end (Base + Size) */
    volatile LONG64 WriteOffset;    /* Next write position */
    volatile LONG64 ReadOffset;     /* Consumer read position */
    volatile LONG   WrapCount;      /* Overflow detection */
    volatile LONG   EventCount;     /* Current event count */
    volatile LONG   DroppedEvents;  /* Events dropped due to size */
    ULONG           BufferSize;     /* Total allocation size */
    KSPIN_LOCK      ReadLock;       /* Multi-reader serialization */
    BOOLEAN         Initialized;
} MON_RING_BUFFER, *PMON_RING_BUFFER;

/* Snapshot for export */
typedef struct _MON_RING_SNAPSHOT {
    ULONG           Size;           /* Structure size */
    ULONG           EventCount;     /* Events in snapshot */
    ULONG           TotalBytes;     /* Bytes used */
    LARGE_INTEGER   OldestTimestamp;
    LARGE_INTEGER   NewestTimestamp;
    ULONG           DroppedSinceSnapshot;
} MON_RING_SNAPSHOT, *PMON_RING_SNAPSHOT;
```

### 1.5 API Design

```c
/* Initialization/Shutdown */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS MonRingBufferInitialize(_In_ ULONG BufferSizeBytes);

_IRQL_requires_(PASSIVE_LEVEL)
VOID MonRingBufferShutdown(VOID);

/* Producer (single writer, lock-free) */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS MonRingBufferWrite(
    _In_ MONITOR_EVENT_TYPE EventType,
    _In_reads_bytes_opt_(PayloadSize) const VOID* Payload,
    _In_ ULONG PayloadSize
);

/* Consumer (multi-reader safe) */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS MonRingBufferRead(
    _Out_writes_bytes_to_(BufferSize, *BytesRead) PVOID OutputBuffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG BytesRead,
    _Out_ PULONG EventCount
);

/* Snapshot (non-destructive read) */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS MonRingBufferSnapshot(
    _Out_writes_bytes_to_(BufferSize, *BytesWritten) PVOID OutputBuffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG BytesWritten,
    _Out_ PMON_RING_SNAPSHOT SnapshotInfo
);

/* Statistics */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID MonRingBufferGetStats(_Out_ PMON_RING_BUFFER_STATS Stats);
```

### 1.6 Implementation Notes

1. **Wrap-around handling**: Use modulo arithmetic with buffer size
2. **Event alignment**: Align all events to 8-byte boundaries
3. **Overwrite policy**: When full, advance ReadOffset to skip oldest event
4. **Magic validation**: Each event has `'REVT'` magic for corruption detection
5. **Memory ordering**: Use `InterlockedCompareExchange64` for atomic updates

### 1.7 New IOCTLs

```c
/* Ring buffer IOCTLs */
#define IOCTL_MONITOR_RINGBUF_CONFIGURE  CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x10, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_MONITOR_RINGBUF_SNAPSHOT   CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x11, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_RINGBUF_STATS      CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x12, METHOD_BUFFERED, FILE_READ_ACCESS)
```

### 1.8 Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `telemetry_ringbuf.h` | Create | Public header with structures and API |
| `telemetry_ringbuf.c` | Create | Ring buffer implementation |
| `monitor_internal.h` | Modify | Add ring buffer context field |
| `win11_monitor_public.h` | Modify | Add new IOCTLs and structures |
| `win11_monitor_mgr.c` | Modify | Integrate ring buffer init/shutdown |
| `telemetry.c` | Modify | Dual-write to SLIST and ring buffer |
| `test_harness.c` | Modify | Add ring buffer tests |

---

## Feature 2: Dynamic Offset Resolution

### 2.1 Problem Statement

Current approach uses hardcoded offset tables:
- Requires driver updates for each new Windows build
- Risk of BSOD if offsets change unexpectedly
- No support for insider/preview builds

### 2.2 Design Goals

- **Runtime PDB download** from Microsoft Symbol Server
- **Offline PDB cache** for air-gapped systems
- **Graceful fallback** to embedded tables if PDB unavailable
- **Signature-based validation** before using resolved offsets

### 2.3 Architecture

```
+------------------+     +------------------+     +------------------+
|  Embedded Table  | --> |  PDB Resolution  | --> |  Signature Check |
|  (Fallback)      |     |  (Optional)      |     |  (Validation)    |
+------------------+     +------------------+     +------------------+
         |                       |                        |
         v                       v                        v
+------------------------------------------------------------------+
|                     Offset Resolution Manager                      |
|  - MonResolveRuntimeOffsets()                                     |
|  - MonGetResolvedOffset(StructName, FieldName)                    |
|  - MonValidateOffsets(TestAddress)                                |
+------------------------------------------------------------------+
```

### 2.4 Data Structures

```c
/* offset_resolver.h */

/* Resolution sources */
typedef enum _MON_OFFSET_SOURCE {
    MonOffsetSource_Unknown = 0,
    MonOffsetSource_Embedded = 1,    /* From compiled-in table */
    MonOffsetSource_PdbCache = 2,    /* From local PDB cache */
    MonOffsetSource_PdbDownload = 3, /* Downloaded at runtime */
    MonOffsetSource_Signature = 4    /* From memory signature scan */
} MON_OFFSET_SOURCE;

/* Resolved offset entry */
typedef struct _MON_RESOLVED_OFFSET {
    CHAR            StructureName[64];
    CHAR            FieldName[64];
    ULONG           Offset;
    ULONG           Size;           /* Field size in bytes */
    MON_OFFSET_SOURCE Source;
    BOOLEAN         Validated;      /* Passed runtime validation */
} MON_RESOLVED_OFFSET, *PMON_RESOLVED_OFFSET;

/* Resolution configuration */
typedef struct _MON_OFFSET_CONFIG {
    ULONG           Size;
    BOOLEAN         EnablePdbDownload;      /* Allow internet access */
    BOOLEAN         EnableSignatureScan;    /* Fall back to signatures */
    WCHAR           PdbCachePath[260];      /* Local cache directory */
    ULONG           DownloadTimeoutMs;      /* Symbol server timeout */
} MON_OFFSET_CONFIG, *PMON_OFFSET_CONFIG;

/* Structure offset table */
typedef struct _MON_STRUCTURE_OFFSETS {
    CHAR            StructureName[64];
    ULONG           StructureSize;
    MON_RESOLVED_OFFSET Offsets[16]; /* Max fields per structure */
    ULONG           OffsetCount;
} MON_STRUCTURE_OFFSETS, *PMON_STRUCTURE_OFFSETS;
```

### 2.5 API Design

```c
/* Initialization */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS MonOffsetResolverInitialize(
    _In_opt_ PMON_OFFSET_CONFIG Config
);

_IRQL_requires_(PASSIVE_LEVEL)
VOID MonOffsetResolverShutdown(VOID);

/* Resolution */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS MonResolveStructureOffsets(
    _In_z_ const CHAR* StructureName,
    _Out_ PMON_STRUCTURE_OFFSETS Offsets
);

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS MonGetResolvedOffset(
    _In_z_ const CHAR* StructureName,
    _In_z_ const CHAR* FieldName,
    _Out_ PULONG Offset
);

/* Validation */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS MonValidateResolvedOffsets(
    _In_z_ const CHAR* StructureName,
    _In_ PVOID TestObject
);

/* Status */
_IRQL_requires_max_(DISPATCH_LEVEL)
MON_OFFSET_SOURCE MonGetOffsetSource(_In_z_ const CHAR* StructureName);
```

### 2.6 Implementation Strategy

#### Phase A: Enhanced Embedded Tables (Low Risk)
1. Expand `g_IoRingOffsets[]` with more builds
2. Add tolerance-based matching with signature validation
3. Add build-number ranges instead of exact matches

#### Phase B: Signature-Based Resolution (Medium Risk)
1. Define byte patterns for structure identification
2. Scan kernel memory to locate type descriptors
3. Derive offsets from runtime structure inspection

#### Phase C: PDB Integration (Higher Complexity)
1. Port/adapt [KPDB](https://github.com/GetRektBoy724/KPDB) for parsing
2. Implement symbol server HTTP client (WinHTTP kernel wrapper)
3. Cache parsed offsets in registry or file

### 2.7 Safety Measures

1. **Dual validation**: Resolved offsets tested against known-good memory
2. **Rollback capability**: Instant fallback to embedded on failure
3. **Audit logging**: ETW events for all resolution attempts
4. **Admin control**: IOCTL to force embedded-only mode

### 2.8 Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `offset_resolver.h` | Create | Public header with API |
| `offset_resolver.c` | Create | Core resolution logic |
| `offset_embedded.c` | Create | Expanded embedded tables |
| `offset_signature.c` | Create | Signature-based fallback |
| `ioring_enum.h` | Modify | Use resolver API |
| `ioring_enum.c` | Modify | Call MonGetResolvedOffset |
| `win11_monitor_public.h` | Modify | New IOCTLs and structures |
| `win11_monitor_mgr.c` | Modify | Init/shutdown integration |

---

## Feature 3: Usermode Client Library

### 3.1 Problem Statement

Current usermode interaction requires:
- Manual IOCTL code assembly
- Direct structure serialization
- Error handling duplication
- No abstraction for common patterns

### 3.2 Design Goals

- **Single header + static library** for easy integration
- **Synchronous and asynchronous** API variants
- **Type-safe wrappers** for all IOCTLs
- **Automatic versioning** with driver compatibility check
- **Comprehensive error handling** with human-readable messages

### 3.3 Architecture

```
+------------------------------------------------------------------+
|                    win11mon_client.h                              |
|  - Public API declarations                                        |
|  - Structure definitions (mirrors kernel public.h)                |
+------------------------------------------------------------------+
                               |
                               v
+------------------------------------------------------------------+
|                    win11mon_client.c                              |
|  - Device handle management                                       |
|  - IOCTL wrappers                                                 |
|  - Error translation                                              |
+------------------------------------------------------------------+
                               |
                               v
+------------------------------------------------------------------+
|                    win11mon_async.c                               |
|  - Overlapped I/O support                                         |
|  - Callback-based event polling                                   |
|  - Thread pool integration                                        |
+------------------------------------------------------------------+
```

### 3.4 API Design

```c
/* win11mon_client.h */

#ifndef WIN11MON_CLIENT_H
#define WIN11MON_CLIENT_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------
 * Handle Management
 *-------------------------------------------------------------------------*/

/* Opaque handle to driver connection */
typedef struct _WIN11MON_HANDLE* HWIN11MON;

/* Open connection to driver */
WIN11MON_API HRESULT Win11MonOpen(
    _Out_ HWIN11MON* Handle
);

/* Close connection */
WIN11MON_API VOID Win11MonClose(
    _In_ HWIN11MON Handle
);

/* Check if driver is loaded and responsive */
WIN11MON_API BOOL Win11MonIsAvailable(VOID);

/*--------------------------------------------------------------------------
 * Version and Capabilities
 *-------------------------------------------------------------------------*/

typedef struct _WIN11MON_VERSION {
    DWORD Major;
    DWORD Minor;
    DWORD Build;
    DWORD Capabilities;
} WIN11MON_VERSION, *PWIN11MON_VERSION;

WIN11MON_API HRESULT Win11MonGetVersion(
    _In_ HWIN11MON Handle,
    _Out_ PWIN11MON_VERSION Version
);

WIN11MON_API BOOL Win11MonHasCapability(
    _In_ HWIN11MON Handle,
    _In_ DWORD CapabilityFlag
);

/*--------------------------------------------------------------------------
 * Monitoring Control
 *-------------------------------------------------------------------------*/

typedef struct _WIN11MON_CONFIG {
    DWORD Size;
    BOOL EnableMonitoring;
    BOOL EnableTelemetry;
    BOOL EnableEncryption;
    DWORD RateLimitPerSec;
    DWORD MaskPolicy;           /* MON_ADDRESS_MASK_POLICY_PUBLIC */
} WIN11MON_CONFIG, *PWIN11MON_CONFIG;

WIN11MON_API HRESULT Win11MonEnable(
    _In_ HWIN11MON Handle,
    _In_ const WIN11MON_CONFIG* Config
);

WIN11MON_API HRESULT Win11MonDisable(
    _In_ HWIN11MON Handle
);

WIN11MON_API HRESULT Win11MonTriggerScan(
    _In_ HWIN11MON Handle
);

/*--------------------------------------------------------------------------
 * Statistics and Events
 *-------------------------------------------------------------------------*/

typedef struct _WIN11MON_STATS {
    DWORD Size;
    DWORD64 TotalAllocations;
    DWORD64 IopMcDetections;
    DWORD64 CrossVmDetections;
    DWORD64 PolicyViolations;
    DWORD64 DroppedEvents;
    DWORD PoolEntryCount;
    DWORD TelemetryEventCount;
    DWORD CurrentRateLimit;
} WIN11MON_STATS, *PWIN11MON_STATS;

WIN11MON_API HRESULT Win11MonGetStats(
    _In_ HWIN11MON Handle,
    _Out_ PWIN11MON_STATS Stats
);

/* Event fetching with automatic buffer management */
WIN11MON_API HRESULT Win11MonFetchEvents(
    _In_ HWIN11MON Handle,
    _Out_writes_bytes_to_(BufferSize, *BytesFetched) PVOID Buffer,
    _In_ DWORD BufferSize,
    _Out_ DWORD* BytesFetched,
    _Out_ DWORD* EventCount
);

/*--------------------------------------------------------------------------
 * IoRing Handle Enumeration
 *-------------------------------------------------------------------------*/

typedef struct _WIN11MON_IORING_INFO {
    DWORD ProcessId;
    DWORD64 HandleValue;
    DWORD64 ObjectAddress;      /* Masked per policy */
    DWORD AccessMask;
    DWORD RegBuffersCount;
    DWORD ViolationFlags;
} WIN11MON_IORING_INFO, *PWIN11MON_IORING_INFO;

WIN11MON_API HRESULT Win11MonEnumerateIoRings(
    _In_ HWIN11MON Handle,
    _Out_writes_to_(MaxEntries, *EntriesFound) PWIN11MON_IORING_INFO Buffer,
    _In_ DWORD MaxEntries,
    _Out_ DWORD* EntriesFound
);

/*--------------------------------------------------------------------------
 * Ring Buffer Access (New)
 *-------------------------------------------------------------------------*/

typedef struct _WIN11MON_RINGBUF_CONFIG {
    DWORD Size;
    DWORD BufferSizeBytes;      /* 0 = use default */
} WIN11MON_RINGBUF_CONFIG, *PWIN11MON_RINGBUF_CONFIG;

WIN11MON_API HRESULT Win11MonConfigureRingBuffer(
    _In_ HWIN11MON Handle,
    _In_ const WIN11MON_RINGBUF_CONFIG* Config
);

WIN11MON_API HRESULT Win11MonSnapshotRingBuffer(
    _In_ HWIN11MON Handle,
    _Out_writes_bytes_to_(BufferSize, *BytesWritten) PVOID Buffer,
    _In_ DWORD BufferSize,
    _Out_ DWORD* BytesWritten,
    _Out_ DWORD* EventCount
);

/*--------------------------------------------------------------------------
 * Offset Resolution Status (New)
 *-------------------------------------------------------------------------*/

typedef enum _WIN11MON_OFFSET_STATUS {
    Win11MonOffset_Unknown = 0,
    Win11MonOffset_Embedded = 1,
    Win11MonOffset_Detected = 2,
    Win11MonOffset_Degraded = 3
} WIN11MON_OFFSET_STATUS;

typedef struct _WIN11MON_OFFSET_INFO {
    DWORD Size;
    DWORD WindowsBuild;
    WIN11MON_OFFSET_STATUS Method;
    BOOL IoRingOffsetsValid;
    BOOL IopMcOffsetsValid;
    DWORD IoRingStructureSize;
    DWORD IopMcStructureSize;
} WIN11MON_OFFSET_INFO, *PWIN11MON_OFFSET_INFO;

WIN11MON_API HRESULT Win11MonGetOffsetInfo(
    _In_ HWIN11MON Handle,
    _Out_ PWIN11MON_OFFSET_INFO Info
);

/*--------------------------------------------------------------------------
 * Rate Limiting (B3)
 *-------------------------------------------------------------------------*/

typedef struct _WIN11MON_RATE_STATS {
    DWORD Size;
    DWORD ActiveProcessCount;
    DWORD64 TotalEventsAllowed;
    DWORD64 TotalEventsDropped;
    DWORD64 ProcessDropCount;
    DWORD64 GlobalDropCount;
    DWORD CurrentGlobalRate;
    DWORD PeakGlobalRate;
    DWORD GlobalLimitPerSec;
    DWORD PerProcessLimitPerSec;
} WIN11MON_RATE_STATS, *PWIN11MON_RATE_STATS;

WIN11MON_API HRESULT Win11MonGetRateStats(
    _In_ HWIN11MON Handle,
    _Out_ PWIN11MON_RATE_STATS Stats
);

/*--------------------------------------------------------------------------
 * Asynchronous Operations
 *-------------------------------------------------------------------------*/

/* Callback for async event notification */
typedef VOID (CALLBACK *WIN11MON_EVENT_CALLBACK)(
    _In_ PVOID Context,
    _In_reads_bytes_(EventSize) const PVOID EventData,
    _In_ DWORD EventSize
);

/* Start async event monitoring */
WIN11MON_API HRESULT Win11MonStartEventMonitor(
    _In_ HWIN11MON Handle,
    _In_ WIN11MON_EVENT_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _In_ DWORD PollIntervalMs
);

/* Stop async event monitoring */
WIN11MON_API HRESULT Win11MonStopEventMonitor(
    _In_ HWIN11MON Handle
);

/*--------------------------------------------------------------------------
 * Error Handling
 *-------------------------------------------------------------------------*/

/* Get human-readable error message */
WIN11MON_API const WCHAR* Win11MonGetErrorMessage(
    _In_ HRESULT ErrorCode
);

#ifdef __cplusplus
}
#endif

#endif /* WIN11MON_CLIENT_H */
```

### 3.5 Implementation Notes

1. **Handle structure**: Contains device handle, version info, async state
2. **Thread safety**: All functions are thread-safe via internal synchronization
3. **Overlapped I/O**: Uses thread pool for async event delivery
4. **Version check**: `Win11MonOpen` validates driver version compatibility
5. **Error mapping**: NTSTATUS to HRESULT with detailed messages

### 3.6 Files to Create

| File | Action | Description |
|------|--------|-------------|
| `client/win11mon_client.h` | Create | Public API header |
| `client/win11mon_client.c` | Create | Core client implementation |
| `client/win11mon_async.c` | Create | Async/callback support |
| `client/win11mon_errors.c` | Create | Error message table |
| `client/win11mon_client.vcxproj` | Create | VS project for static lib |
| `client/test_client.c` | Create | Client library unit tests |

### 3.7 Build Output

- `win11mon_client.lib` - Static library for linking
- `win11mon_client.h` - Single header for inclusion
- `win11mon_client.pdb` - Debug symbols

---

## Implementation Order

### Phase 5A: Ring Buffer Telemetry (Priority 1)
1. Create `telemetry_ringbuf.h` with structures
2. Implement `telemetry_ringbuf.c` core functions
3. Integrate into `telemetry.c` dual-write path
4. Add ring buffer IOCTLs to manager
5. Create test harness tests
6. **Web search verification** at each step

### Phase 5B: Dynamic Offset Resolution (Priority 2)
1. Create `offset_resolver.h` with API
2. Implement `offset_embedded.c` with expanded tables
3. Implement `offset_signature.c` fallback
4. Integrate into `ioring_enum.c`
5. Add IOCTLs for status/configuration
6. **Web search verification** at each step

### Phase 5C: Usermode Client Library (Priority 3)
1. Create `client/` directory structure
2. Implement `win11mon_client.c` sync API
3. Implement `win11mon_async.c` async support
4. Create VS project and build
5. Write comprehensive tests
6. **Web search verification** at each step

---

## Test Contracts

### Ring Buffer Tests
| ID | Test | Expected |
|----|------|----------|
| RB-T01 | Write single event | Event retrievable with correct data |
| RB-T02 | Fill buffer exactly | All events present, no overflow |
| RB-T03 | Overflow buffer | Oldest events overwritten |
| RB-T04 | Snapshot non-destructive | Same data on re-read |
| RB-T05 | DISPATCH_LEVEL write | No deadlock or BSOD |
| RB-T06 | Concurrent read/write | No corruption |

### Offset Resolution Tests
| ID | Test | Expected |
|----|------|----------|
| OR-T01 | Known build lookup | Correct offsets returned |
| OR-T02 | Unknown build fallback | Nearest build used |
| OR-T03 | Validation pass | Offsets work on live object |
| OR-T04 | Validation fail | Graceful fallback, no crash |
| OR-T05 | Source reporting | Correct MON_OFFSET_SOURCE |

### Client Library Tests
| ID | Test | Expected |
|----|------|----------|
| CL-T01 | Open/Close | No leaks, clean shutdown |
| CL-T02 | Version check | Correct version returned |
| CL-T03 | Enable/Disable | Driver state changes |
| CL-T04 | Fetch events | Events match kernel queue |
| CL-T05 | Async callback | Callback invoked on event |
| CL-T06 | Error handling | HRESULT codes meaningful |

---

## References

- [Microsoft Ring Buffer Sample](https://github.com/microsoft/Windows-driver-samples/blob/main/serial/VirtualSerial2/ringbuffer.h)
- [ETW Circular Buffer Best Practices](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties)
- [KPDB - Kernel PDB Parser](https://github.com/GetRektBoy724/KPDB)
- [Offset-Free DSE Research](https://blog.cryptoplague.net/main/research/windows-research/offset-free-dse-bypass-across-windows-11-and-10-utilising-ntkrnlmp.pdb)
- [DeviceIoControl API](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol)

---

## Approval

This plan implements three major enhancements to the Windows 11 Monitor Manager. Implementation follows the established workflow with web search verification at each step.

**Ready for implementation upon approval.**
