# Phase 11: Forensic Snapshot Export

## Implementation Plan

**Author:** Colin MacRitchie | ziX Labs
**Version:** 1.0
**Date:** 2025-11-30
**Status:** Planning

---

## 1. Executive Summary

This phase implements comprehensive forensic snapshot export capabilities, allowing complete state capture of all IoRing handles, process profiles, memory regions, and event history. The export supports timeline reconstruction and integration with standard DFIR tools through JSON/CSV output formats.

---

## 2. Research Findings

### 2.1 Forensic Data Requirements

**Core Export Data:**
1. IoRing handles with full metadata
2. Process tree with relationships
3. Memory region mappings
4. Event timeline from ring buffer
5. Anomaly/alert history
6. System context (OS version, time, etc.)

### 2.2 Industry Standard Formats

| Format | Use Case | Tool Support |
|--------|----------|--------------|
| JSON | SIEM integration, API consumption | ELK, Splunk, custom tools |
| JSONL | Streaming, large datasets | Log management systems |
| CSV | Timeline Explorer, Excel | EZ Tools, KAPE, Axiom |
| Binary | Compact storage, replay | Custom analysis tools |

### 2.3 Timeline Reconstruction Approach

**Key Correlation Fields:**
- Timestamp (nanosecond precision)
- Sequence number (ordering)
- Process ID
- Event type
- Causation chain (parent event)

**Super Timeline Integration:**
- Compatible with Plaso/Log2Timeline
- Merge with EVTX, Prefetch, MFT
- Forensic-Timeliner compatible output

### 2.4 Existing Forensic Tool Patterns

**Volatility-Style Output:**
- Process list with tree structure
- Handle enumeration
- Kernel module information
- Timeline plugin format

**KAPE-Style Artifacts:**
- Structured directory output
- Manifest file with metadata
- Hash verification

---

## 3. Architecture Design

### 3.1 Component Overview

```
+------------------------------------------------------------------+
|                    Forensic Export Subsystem                      |
|  +----------------------------+  +-----------------------------+  |
|  | Snapshot Coordinator       |  | Format Handlers             |  |
|  | - Atomic state capture     |  | - JSON serializer           |  |
|  | - Consistency guarantee    |  | - CSV serializer            |  |
|  | - Versioned snapshots      |  | - Binary serializer         |  |
|  +----------------------------+  +-----------------------------+  |
|  +----------------------------+  +-----------------------------+  |
|  | Timeline Builder           |  | Export Package Manager      |  |
|  | - Event ordering           |  | - Directory structure       |  |
|  | - Causation linking        |  | - Manifest generation       |  |
|  | - Gap detection            |  | - Hash verification         |  |
|  +----------------------------+  +-----------------------------+  |
+------------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------------+
|                    Data Sources (Previous Phases)                 |
|  +---------------+  +---------------+  +---------------+          |
|  | ioring_enum   |  | process_prof  |  | mem_monitor   |          |
|  | - Handles     |  | - Profiles    |  | - MDL/VAD     |          |
|  +---------------+  +---------------+  +---------------+          |
|  +---------------+  +---------------+  +---------------+          |
|  | cross_process |  | kernel_cb     |  | ring_buffer   |          |
|  | - Relations   |  | - Events      |  | - History     |          |
|  +---------------+  +---------------+  +---------------+          |
+------------------------------------------------------------------+
```

### 3.2 Snapshot Capture Flow

```
1. IOCTL_MONITOR_FORENSIC_SNAPSHOT received

2. Acquire global snapshot lock (prevent concurrent modifications)

3. Capture system context:
   - Timestamp (KeQuerySystemTime)
   - Boot time
   - OS version info
   - Driver version

4. Capture IoRing state:
   - All tracked handles
   - Object metadata
   - RegBuffers info

5. Capture process state:
   - All profiles
   - Process tree
   - Handle correlations

6. Capture memory state:
   - MDL tracking info
   - VAD scan results
   - Sharing detection results

7. Capture event history:
   - Ring buffer snapshot
   - Callback statistics
   - Alert history

8. Release snapshot lock

9. Serialize to requested format

10. Return to caller (or write to file)
```

### 3.3 Output Directory Structure

```
win11mon_snapshot_20251130_143022/
├── manifest.json                 # Snapshot metadata
├── system_context.json           # OS/driver info
├── ioring/
│   ├── handles.json              # All IoRing handles
│   ├── handles.csv               # CSV format
│   └── regbuffers.json           # RegBuffers detail
├── processes/
│   ├── tree.json                 # Process tree
│   ├── profiles.json             # All profiles
│   ├── profiles.csv              # CSV format
│   └── ml_features.csv           # ML-ready export
├── memory/
│   ├── mdl_tracking.json         # MDL info
│   ├── vad_scans.json            # VAD results
│   └── sharing.json              # Cross-process sharing
├── events/
│   ├── timeline.json             # Full timeline
│   ├── timeline.csv              # CSV timeline
│   ├── alerts.json               # Alerts only
│   └── anomalies.json            # Anomaly events
├── cross_process/
│   ├── shared_objects.json       # Shared objects
│   └── relationships.json        # Process relationships
└── checksums.sha256              # File verification
```

---

## 4. Data Structures

### 4.1 Snapshot Container

```c
// New file: forensic_export.h

#define MON_FORENSIC_MAGIC          0x464F5245  /* 'FORE' */
#define MON_FORENSIC_VERSION        1

/* Export format options */
typedef enum _MON_EXPORT_FORMAT {
    MonExportFormat_JSON = 0,
    MonExportFormat_JSONL = 1,
    MonExportFormat_CSV = 2,
    MonExportFormat_Binary = 3,
    MonExportFormat_All = 0xFF      /* Generate all formats */
} MON_EXPORT_FORMAT;

/* Export scope flags */
typedef enum _MON_EXPORT_SCOPE {
    MonExportScope_IoRing = 0x0001,
    MonExportScope_Processes = 0x0002,
    MonExportScope_Memory = 0x0004,
    MonExportScope_Events = 0x0008,
    MonExportScope_CrossProcess = 0x0010,
    MonExportScope_Callbacks = 0x0020,
    MonExportScope_All = 0xFFFF
} MON_EXPORT_SCOPE;

/* Snapshot request input */
typedef struct _MON_SNAPSHOT_REQUEST {
    ULONG               Size;
    MON_EXPORT_FORMAT   Format;
    ULONG               ScopeFlags;     /* MON_EXPORT_SCOPE bitmask */
    ULONG64             TimeRangeStart; /* 0 = no filter */
    ULONG64             TimeRangeEnd;   /* 0 = current time */
    ULONG               MaxEvents;      /* 0 = unlimited */
    WCHAR               OutputPath[260]; /* Empty = return in buffer */
} MON_SNAPSHOT_REQUEST, *PMON_SNAPSHOT_REQUEST;

/* Snapshot metadata (manifest) */
typedef struct _MON_SNAPSHOT_MANIFEST {
    ULONG       Magic;
    ULONG       Version;
    ULONG64     SnapshotTime;
    ULONG64     BootTime;

    /* System info */
    ULONG       OsBuildNumber;
    ULONG       OsServicePack;
    WCHAR       OsVersionString[64];

    /* Driver info */
    ULONG       DriverVersionMajor;
    ULONG       DriverVersionMinor;
    ULONG       DriverCapabilities;

    /* Content summary */
    ULONG       IoRingHandleCount;
    ULONG       ProcessProfileCount;
    ULONG       EventCount;
    ULONG       AlertCount;

    /* Timing */
    ULONG64     CaptureStartTime;
    ULONG64     CaptureEndTime;
    ULONG       CaptureDurationMs;

    /* Integrity */
    UCHAR       ContentHash[32];    /* SHA-256 */

} MON_SNAPSHOT_MANIFEST, *PMON_SNAPSHOT_MANIFEST;
```

### 4.2 Timeline Event Format

```c
/* Timeline event for export (JSON-friendly) */
typedef struct _MON_TIMELINE_EVENT {
    ULONG64     Timestamp;          /* 100ns units since 1601 */
    ULONG64     SequenceNumber;     /* Monotonic ordering */
    ULONG       ProcessId;
    ULONG       ThreadId;

    /* Event classification */
    UCHAR       EventCategory;      /* IoRing, Process, Memory, etc. */
    UCHAR       EventType;          /* Specific event type */
    UCHAR       Severity;           /* 0-5 */
    UCHAR       Flags;

    /* Correlation */
    ULONG64     ParentSequence;     /* Related event, 0 if none */
    ULONG64     CorrelationId;      /* For multi-event activities */

    /* Content */
    ULONG       PayloadSize;
    UCHAR       PayloadType;        /* JSON, Binary, etc. */
    /* Payload follows */

} MON_TIMELINE_EVENT, *PMON_TIMELINE_EVENT;

/* Event categories */
typedef enum _MON_EVENT_CATEGORY {
    MonCategory_System = 0,
    MonCategory_IoRing = 1,
    MonCategory_Process = 2,
    MonCategory_Memory = 3,
    MonCategory_CrossProcess = 4,
    MonCategory_Anomaly = 5,
    MonCategory_Callback = 6,
} MON_EVENT_CATEGORY;
```

### 4.3 IoRing Export Record

```c
/* Comprehensive IoRing handle export */
typedef struct _MON_IORING_EXPORT_RECORD {
    /* Identification */
    ULONG64     ExportId;           /* Unique ID in this export */
    ULONG       ProcessId;
    WCHAR       ProcessName[64];
    ULONG64     HandleValue;
    ULONG64     ObjectAddress;      /* Masked */

    /* Configuration */
    ULONG       Version;
    ULONG       SubmissionQueueSize;
    ULONG       CompletionQueueSize;
    ULONG       Flags;

    /* RegBuffers */
    ULONG       RegBuffersCount;
    ULONG64     TotalRegBufferBytes;
    BOOLEAN     RegBuffersValid;
    ULONG       RegBufferViolations;

    /* RegFiles */
    ULONG       RegFilesCount;

    /* State */
    ULONG64     FirstSeenTime;
    ULONG64     LastSeenTime;
    ULONG64     TotalOperations;

    /* Anomaly info */
    ULONG       AnomalyScore;
    ULONG       AlertCount;

} MON_IORING_EXPORT_RECORD, *PMON_IORING_EXPORT_RECORD;
```

### 4.4 Process Export Record

```c
/* Comprehensive process profile export */
typedef struct _MON_PROCESS_EXPORT_RECORD {
    /* Identification */
    ULONG       ProcessId;
    ULONG       ParentProcessId;
    WCHAR       ProcessName[64];
    WCHAR       ImagePath[260];
    WCHAR       CommandLine[512];

    /* Timing */
    ULONG64     CreateTime;
    ULONG64     ExitTime;           /* 0 if still running */
    ULONG       SessionId;

    /* Security context */
    ULONG       IntegrityLevel;
    BOOLEAN     IsElevated;
    BOOLEAN     IsService;
    BOOLEAN     IsInteractive;

    /* IoRing metrics */
    ULONG       IoRingHandleCount;
    ULONG64     TotalIoRingOps;
    float       OpsPerSecond;
    ULONG64     TotalBufferBytes;

    /* Anomaly info */
    ULONG       AnomalyScore;
    ULONG       ViolationCount;
    ULONG       AlertCount;

    /* Relationships */
    ULONG       ChildCount;
    ULONG       SharedObjectCount;

} MON_PROCESS_EXPORT_RECORD, *PMON_PROCESS_EXPORT_RECORD;
```

---

## 5. JSON Schema Definitions

### 5.1 Manifest Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Win11Mon Forensic Snapshot Manifest",
  "type": "object",
  "properties": {
    "magic": { "type": "string", "const": "FORE" },
    "version": { "type": "integer" },
    "snapshot_time": { "type": "string", "format": "date-time" },
    "boot_time": { "type": "string", "format": "date-time" },
    "system": {
      "type": "object",
      "properties": {
        "os_build": { "type": "integer" },
        "os_version": { "type": "string" },
        "hostname": { "type": "string" }
      }
    },
    "driver": {
      "type": "object",
      "properties": {
        "version": { "type": "string" },
        "capabilities": { "type": "integer" }
      }
    },
    "summary": {
      "type": "object",
      "properties": {
        "ioring_handles": { "type": "integer" },
        "process_profiles": { "type": "integer" },
        "events": { "type": "integer" },
        "alerts": { "type": "integer" }
      }
    },
    "integrity": {
      "type": "object",
      "properties": {
        "sha256": { "type": "string" }
      }
    }
  }
}
```

### 5.2 Timeline Event Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Win11Mon Timeline Event",
  "type": "object",
  "properties": {
    "timestamp": { "type": "string", "format": "date-time" },
    "timestamp_raw": { "type": "integer" },
    "sequence": { "type": "integer" },
    "process_id": { "type": "integer" },
    "thread_id": { "type": "integer" },
    "category": { "type": "string" },
    "event_type": { "type": "string" },
    "severity": { "type": "integer", "minimum": 0, "maximum": 5 },
    "correlation_id": { "type": "string" },
    "parent_sequence": { "type": "integer" },
    "mitre_technique": { "type": "string" },
    "payload": { "type": "object" }
  },
  "required": ["timestamp", "sequence", "category", "event_type"]
}
```

---

## 6. Implementation Tasks

### 6.1 Kernel-Mode Components

**File: forensic_export.h**
- Export structures and schemas
- Format definitions
- IOCTL definitions

**File: forensic_export.c**
- `MonForensicInitialize()` - Initialize export subsystem
- `MonForensicCreateSnapshot()` - Main snapshot function
- `MonForensicCaptureIoRing()` - Capture IoRing state
- `MonForensicCaptureProcesses()` - Capture process profiles
- `MonForensicCaptureMemory()` - Capture memory state
- `MonForensicCaptureEvents()` - Capture event history
- `MonForensicBuildTimeline()` - Build ordered timeline

**File: format_json.c**
- `MonJsonSerialize()` - Generic JSON serialization
- `MonJsonSerializeManifest()` - Manifest export
- `MonJsonSerializeTimeline()` - Timeline export
- `MonJsonSerializeIoRing()` - IoRing record export
- `MonJsonSerializeProcess()` - Process record export

**File: format_csv.c**
- `MonCsvSerializeTimeline()` - CSV timeline
- `MonCsvSerializeProfiles()` - CSV profiles
- `MonCsvSerializeMLFeatures()` - ML feature export

**IOCTL Definitions:**
```c
#define IOCTL_MONITOR_FORENSIC_SNAPSHOT  CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x70, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_FORENSIC_TIMELINE  CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x71, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_FORENSIC_EXPORT_ML CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x72, METHOD_BUFFERED, FILE_READ_ACCESS)
```

### 6.2 User-Mode Components

**File: client/win11mon_forensic.h**
- Forensic export APIs
- Timeline query APIs
- ML export APIs

**File: client/win11mon_forensic.c**
- `Mon_ForensicSnapshot()` - Create full snapshot
- `Mon_ForensicExportTimeline()` - Export timeline
- `Mon_ForensicExportML()` - Export ML features
- `Mon_ForensicWriteToFile()` - Write to disk
- `Mon_ForensicValidateSnapshot()` - Verify integrity

### 6.3 Integration Points

1. **All previous phases**: Data source for export
2. **telemetry_ringbuf.c**: Event history source
3. **offset_resolver.c**: OS version for context

---

## 7. CSV Column Definitions

### 7.1 Timeline CSV

```
Timestamp,TimestampRaw,Sequence,ProcessId,ProcessName,ThreadId,Category,EventType,Severity,MitreTechnique,Description
```

### 7.2 IoRing Handles CSV

```
ExportId,ProcessId,ProcessName,Handle,ObjectAddr,Version,SQSize,CQSize,RegBufCount,RegFileCount,FirstSeen,LastSeen,TotalOps,AnomalyScore,AlertCount
```

### 7.3 Process Profiles CSV

```
ProcessId,ParentPid,ProcessName,ImagePath,CreateTime,ExitTime,Session,Integrity,IsElevated,IoRingHandles,TotalOps,OpsPerSec,BufferBytes,AnomalyScore,ViolationCount
```

### 7.4 ML Features CSV (Phase 7 integration)

```
ProcessId,Timestamp,OpsPerSec,SubmitsPerMin,HandleCount,AvgBufferKB,MaxBufferMB,TotalMemMB,ReadWriteRatio,RegFiles,ActiveDurationMin,BurstFreq,ViolationRate,ProcessAgeMin,Elevated,Interactive,Label
```

---

## 8. Testing Plan

### 8.1 Unit Tests

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| FE-T01 | Empty snapshot creation | Valid manifest |
| FE-T02 | JSON serialization | Valid JSON output |
| FE-T03 | CSV serialization | Valid CSV output |
| FE-T04 | Timeline ordering | Correct sequence |
| FE-T05 | Hash verification | SHA-256 matches |
| FE-T06 | Large snapshot (10K events) | Success <10s |
| FE-T07 | Concurrent snapshot requests | Proper locking |

### 8.2 Integration Tests

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| FE-I01 | Full scope snapshot | All data present |
| FE-I02 | Filtered time range | Only matching events |
| FE-I03 | IoRing-only export | IoRing data only |
| FE-I04 | File output | Files created |
| FE-I05 | Directory structure | Correct layout |

### 8.3 Compatibility Tests

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| FE-C01 | JSON validates schema | No errors |
| FE-C02 | CSV loads in Excel | Proper columns |
| FE-C03 | Timeline Explorer import | Data displays |
| FE-C04 | ELK Stack ingest | Events indexed |

---

## 9. Performance Considerations

### 9.1 Memory Usage

- Snapshot buffer: Configurable, default 64MB
- Streaming for large exports
- Memory-mapped file output option

### 9.2 Capture Time

- Target: <5 seconds for typical system
- Parallel capture where possible
- Minimize lock duration

### 9.3 Output Size

| Data Type | Estimated Size (typical) |
|-----------|-------------------------|
| Manifest | ~1KB |
| IoRing (100 handles) | ~50KB JSON |
| Processes (500) | ~200KB JSON |
| Timeline (10K events) | ~5MB JSON |
| Full snapshot | ~10-50MB |

---

## 10. Security Considerations

### 10.1 Data Sensitivity

- Object addresses masked (ASLR protection)
- Command lines may contain credentials
- Consider redaction options

### 10.2 Export Access Control

- Admin-only by default
- Configurable access policy
- Audit log of exports

### 10.3 Integrity Protection

- SHA-256 hash of content
- Signed manifest option
- Tamper detection

---

## 11. Dependencies

- All previous phases (data sources)
- Phase 5A: Ring Buffer (event history)
- Phase 5B: Offset Resolver (OS context)
- Phase 7: Process Profiling (ML features)

---

## 12. File Deliverables

| File | Type | Description |
|------|------|-------------|
| `forensic_export.h` | Header | Export structures |
| `forensic_export.c` | Source | Snapshot capture |
| `format_json.c` | Source | JSON serialization |
| `format_csv.c` | Source | CSV serialization |
| `client/win11mon_forensic.h` | Header | Client forensic APIs |
| `client/win11mon_forensic.c` | Source | Client implementation |
| `test_forensic.c` | Test | Unit tests |

---

## 13. Research Sources

- [Memory Forensics for Incident Response - Varonis](https://www.varonis.com/blog/memory-forensics)
- [Forensic-Timeliner - CyberPress](https://cyberpress.org/forensic-timeline-dfir-professionals/)
- [Windows 10 Timeline Forensics - Group-IB](https://blog.group-ib.com/windows10_timeline_for_forensics)
- [Windows Forensic Artifacts - GitHub](https://github.com/Psmths/windows-forensic-artifacts)
- [AmCache Forensic Artifact - Kaspersky](https://securelist.com/amcache-forensic-artifact/117622/)
- [DFIR Memory Forensics - Awesome List](https://github.com/digitalisx/awesome-memory-forensics)
- [Volatility Framework Documentation](https://www.volatilityfoundation.org/)
- [SANS Memory Forensics 101](https://www.sans.org/blog/memory-forensic-acquisition-and-analysis-101)

---

## 14. Sample Output

### 14.1 Manifest Example

```json
{
  "magic": "FORE",
  "version": 1,
  "snapshot_time": "2025-11-30T14:30:22.123456Z",
  "boot_time": "2025-11-30T08:15:00.000000Z",
  "system": {
    "os_build": 22631,
    "os_version": "Windows 11 23H2",
    "hostname": "WORKSTATION01"
  },
  "driver": {
    "version": "1.2.2025",
    "capabilities": 8191
  },
  "summary": {
    "ioring_handles": 12,
    "process_profiles": 487,
    "events": 15632,
    "alerts": 3
  },
  "capture": {
    "duration_ms": 1247,
    "start_time": "2025-11-30T14:30:20.876321Z",
    "end_time": "2025-11-30T14:30:22.123456Z"
  },
  "integrity": {
    "sha256": "a1b2c3d4e5f6..."
  }
}
```

### 14.2 Timeline Event Example

```json
{
  "timestamp": "2025-11-30T14:25:15.789123Z",
  "timestamp_raw": 133456789012345678,
  "sequence": 15001,
  "process_id": 4892,
  "process_name": "malware.exe",
  "thread_id": 7234,
  "category": "IoRing",
  "event_type": "RegBuffersViolation",
  "severity": 4,
  "mitre_technique": "T1068",
  "correlation_id": "abc123",
  "parent_sequence": 14998,
  "payload": {
    "ioring_handle": "0x1234",
    "violation_type": "KernelAddressInBuffer",
    "buffer_index": 2,
    "anomaly_score": 85
  }
}
```

---

## 15. Approval

- [ ] Architecture review completed
- [ ] Security review completed
- [ ] Implementation approved

---

*End of Phase 11 Plan*
