# Phase 7: Process Behavior Profiling

## Implementation Plan

**Author:** Colin MacRitchie | ziX Labs
**Version:** 1.0
**Date:** 2025-11-30
**Status:** Planning

---

## 1. Executive Summary

This phase implements IoRing-specific process behavior profiling to track usage patterns, detect anomalies, and extract ML-ready features. The profiling system establishes behavioral baselines and identifies deviations indicative of exploitation or abuse.

---

## 2. Research Findings

### 2.1 IoRing Security Landscape

**The io_uring Problem (Linux parallels):**
- io_uring creates a blind spot for syscall-based monitoring (Sysdig, ARMO research)
- Malicious operations via ring buffers bypass traditional hooks
- Detection requires behavioral analysis, not just syscall interception

**IoRing on Windows (same challenges):**
- NtSubmitIoRing queues operations processed asynchronously
- Traditional API hooks miss ring-submitted operations
- Behavioral profiling fills this visibility gap

### 2.2 EDR Behavioral Detection Patterns

**Key Techniques from EDR Research:**
1. **Process Creation Patterns** - Parent-child relationships
2. **API Call Frequency** - Operations per second anomalies
3. **Resource Consumption** - Buffer sizes, memory allocation
4. **Temporal Patterns** - Time-of-day, burst detection
5. **Cross-Process Correlation** - Synchronized suspicious activity

### 2.3 ML-Based Anomaly Detection Approaches

| Approach | Strengths | Weaknesses | Fit for IoRing |
|----------|-----------|------------|----------------|
| **Statistical N-gram** | Platform-independent | High false positives | Medium |
| **Autoencoder** | Learns "normal" | Requires training data | High |
| **Kernel Density** | No threshold tuning | Computational cost | Medium |
| **Gradient Boosting** | Interpretable | Labeled data needed | Medium |
| **Baseline Deviation** | Simple, effective | Manual threshold | High |

### 2.4 Feature Extraction for IoRing

**Recommended Features (ML-Ready):**

| Category | Feature | Type | Description |
|----------|---------|------|-------------|
| **Frequency** | ops_per_second | float | IoRing operations per second |
| **Frequency** | submits_per_minute | uint32 | NtSubmitIoRing calls per minute |
| **Frequency** | handle_count | uint16 | Active IoRing handles per process |
| **Size** | avg_buffer_size | uint32 | Average registered buffer size |
| **Size** | max_buffer_size | uint32 | Largest buffer registered |
| **Size** | total_memory | uint64 | Total IoRing memory footprint |
| **Operation** | read_write_ratio | float | Read ops / Write ops |
| **Operation** | registered_file_count | uint16 | Pre-registered file handles |
| **Temporal** | first_seen_epoch | uint64 | When process first used IoRing |
| **Temporal** | active_duration_sec | uint32 | Time with active IoRing |
| **Temporal** | burst_count | uint16 | Operations bursts detected |
| **Integrity** | violation_count | uint16 | RegBuffers violations |
| **Integrity** | corruption_events | uint16 | Detected memory corruptions |
| **Context** | parent_pid | uint32 | Parent process ID |
| **Context** | process_elevation | uint8 | Is elevated/admin |
| **Context** | process_age_sec | uint32 | Process lifetime |

---

## 3. Architecture Design

### 3.1 Component Overview

```
+------------------------------------------------------------------+
|                    Process Profile Storage                        |
|  +----------------------------+  +-----------------------------+  |
|  | MON_PROCESS_PROFILE        |  | Baseline Database           |  |
|  | - Per-process IoRing stats |  | - "Normal" profile template |  |
|  | - Historical metrics       |  | - Per-application baselines |  |
|  | - Anomaly scores           |  | - Global thresholds         |  |
|  +----------------------------+  +-----------------------------+  |
+------------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------------+
|                    Analysis Engine                                |
|  +----------------------------+  +-----------------------------+  |
|  | Anomaly Detector           |  | Feature Extractor           |  |
|  | - Threshold-based          |  | - Real-time aggregation     |  |
|  | - Statistical deviation    |  | - Sliding window            |  |
|  | - Burst detection          |  | - ML-ready export           |  |
|  +----------------------------+  +-----------------------------+  |
+------------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------------+
|                    Data Sources                                   |
|  +----------------------------+  +-----------------------------+  |
|  | ioring_enum.c (existing)   |  | Event Ring Buffer (existing)|  |
|  | - Handle enumeration       |  | - Historical events         |  |
|  | - Object inspection        |  | - Timestamp correlation     |  |
|  +----------------------------+  +-----------------------------+  |
+------------------------------------------------------------------+
```

### 3.2 Profile Lifecycle

```
1. Process creates first IoRing handle
   -> ProfileCreate() allocates MON_PROCESS_PROFILE
   -> Initialize metrics, start timers

2. IoRing operations detected
   -> ProfileUpdate() increments counters
   -> Sliding window aggregation
   -> Real-time anomaly check

3. Anomaly threshold exceeded
   -> Generate MonEvent_ProcessAnomalyDetected
   -> Update anomaly_score in profile
   -> Optional: trigger interception (Phase 6)

4. Process terminates / IoRing handles closed
   -> ProfileExport() for ML training data
   -> ProfileDestroy() cleanup
```

### 3.3 Anomaly Detection Rules

```c
// Built-in heuristic rules

typedef struct _MON_ANOMALY_RULE {
    ULONG   RuleId;
    PCWSTR  RuleName;
    ULONG   Threshold;
    ULONG   WindowSeconds;
    ULONG   Severity;
} MON_ANOMALY_RULE;

// Example rules:
// RULE_HIGH_OPS_FREQUENCY: >1000 ops/sec for >5 seconds
// RULE_LARGE_BUFFER_REGISTRATION: Single buffer >100MB
// RULE_RAPID_HANDLE_CREATION: >10 IoRing handles in 1 second
// RULE_ELEVATED_IORING_ABUSE: Non-interactive elevated process using IoRing
// RULE_BURST_PATTERN: >500 ops in <100ms repeated 3+ times
// RULE_CONCURRENT_TARGETS: Same process IoRing operations on >50 files
```

---

## 4. Data Structures

### 4.1 Process Profile

```c
// New file: process_profile.h

#define MON_PROFILE_MAGIC           0x50524F46  /* 'PROF' */
#define MON_PROFILE_HISTORY_SLOTS   60          /* 1 minute at 1-second granularity */
#define MON_PROFILE_MAX_PROCESSES   1024

typedef struct _MON_PROCESS_PROFILE {
    ULONG       Magic;
    ULONG       ProcessId;
    ULONG64     ProcessStartTime;       /* System time when profiling started */

    /* Handle tracking */
    volatile LONG   ActiveHandleCount;
    ULONG           TotalHandlesCreated;
    ULONG           TotalHandlesClosed;

    /* Operation counters (lifetime) */
    volatile LONG64 TotalOperations;
    ULONG64         TotalReads;
    ULONG64         TotalWrites;
    ULONG64         TotalCancels;

    /* Buffer statistics */
    ULONG64         TotalBufferBytesRegistered;
    ULONG           MaxBufferSize;
    ULONG           AvgBufferSize;
    ULONG           TotalBuffersRegistered;

    /* File statistics */
    ULONG           TotalFilesRegistered;
    ULONG           MaxConcurrentFiles;

    /* Timing statistics */
    ULONG           OpsLastSecond;
    ULONG           OpsHistory[MON_PROFILE_HISTORY_SLOTS];
    ULONG           HistoryIndex;
    LARGE_INTEGER   LastUpdateTime;

    /* Anomaly tracking */
    volatile LONG   AnomalyScore;       /* 0-100, higher = more suspicious */
    ULONG           AnomalyEventCount;
    ULONG           ViolationCount;
    ULONG           BurstCount;

    /* Flags */
    ULONG           Flags;
    #define MON_PROFILE_FLAG_ELEVATED       0x0001
    #define MON_PROFILE_FLAG_SERVICE        0x0002
    #define MON_PROFILE_FLAG_NON_INTERACTIVE 0x0004
    #define MON_PROFILE_FLAG_SYSTEM         0x0008
    #define MON_PROFILE_FLAG_BLACKLISTED    0x0010
    #define MON_PROFILE_FLAG_WHITELISTED    0x0020

    /* Export timestamp */
    ULONG64         LastExportTime;

    /* List linkage (for profile storage) */
    LIST_ENTRY      ListEntry;

} MON_PROCESS_PROFILE, *PMON_PROCESS_PROFILE;

/* Aggregated statistics for export/reporting */
typedef struct _MON_PROFILE_SUMMARY {
    ULONG   Size;
    ULONG   ProcessId;
    WCHAR   ProcessName[64];

    /* Key metrics */
    ULONG   ActiveHandles;
    ULONG64 TotalOperations;
    float   OpsPerSecond;
    ULONG64 TotalMemoryBytes;

    /* Anomaly info */
    ULONG   AnomalyScore;
    ULONG   AnomalyEventCount;
    ULONG   ViolationCount;

    /* Timestamps */
    ULONG64 FirstSeen;
    ULONG64 LastSeen;
    ULONG   ActiveDurationSec;

} MON_PROFILE_SUMMARY, *PMON_PROFILE_SUMMARY;
```

### 4.2 ML Feature Export Format

```c
/* ML-ready feature vector for export */
typedef struct _MON_ML_FEATURE_VECTOR {
    ULONG   Size;
    ULONG   Version;            /* Feature schema version */
    ULONG   ProcessId;
    ULONG64 Timestamp;

    /* Normalized features (0.0 - 1.0 where applicable) */
    float   OpsPerSecond;       /* Operations per second */
    float   SubmitsPerMinute;   /* NtSubmitIoRing calls per minute */
    float   HandleCount;        /* Active handle count */
    float   AvgBufferSizeKB;    /* Average buffer size in KB */
    float   MaxBufferSizeMB;    /* Max buffer size in MB */
    float   TotalMemoryMB;      /* Total memory footprint in MB */
    float   ReadWriteRatio;     /* Read ops / (Read + Write ops) */
    float   RegisteredFiles;    /* Pre-registered file count */
    float   ActiveDurationMin;  /* Time with active IoRing in minutes */
    float   BurstFrequency;     /* Bursts per minute */
    float   ViolationRate;      /* Violations per 1000 ops */
    float   ProcessAgeMin;      /* Process lifetime in minutes */
    ULONG   ProcessElevation;   /* 0=standard, 1=elevated */
    ULONG   ProcessInteractive; /* 0=no, 1=yes */

    /* Label (for supervised learning, 0=benign, 1=suspicious) */
    ULONG   Label;

} MON_ML_FEATURE_VECTOR, *PMON_ML_FEATURE_VECTOR;
```

---

## 5. Implementation Tasks

### 5.1 Kernel-Mode Components

**File: process_profile.h**
- Profile structures and constants
- Feature vector format
- Anomaly rule definitions

**File: process_profile.c**
- `MonProfileInitialize()` - Initialize profile subsystem
- `MonProfileShutdown()` - Cleanup all profiles
- `MonProfileCreate()` - Allocate profile for process
- `MonProfileDestroy()` - Free profile
- `MonProfileUpdate()` - Update metrics on IoRing activity
- `MonProfileGetByPid()` - Lookup profile by PID
- `MonProfileCheckAnomaly()` - Run anomaly detection rules
- `MonProfileExportFeatures()` - Generate ML feature vector
- `MonProfileGetSummary()` - Get summary for IOCTL response

**File: anomaly_rules.c**
- `MonAnomalyEvaluate()` - Run all rules against profile
- `MonAnomalyAddRule()` - Register custom rule
- `MonAnomalySetThreshold()` - Configure rule threshold

**IOCTL Additions:**
```c
#define IOCTL_MONITOR_PROFILE_GET        CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x30, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_PROFILE_LIST       CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x31, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_PROFILE_EXPORT_ML  CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x32, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_PROFILE_RESET      CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x33, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_MONITOR_ANOMALY_CONFIG     CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x34, METHOD_BUFFERED, FILE_WRITE_ACCESS)
```

### 5.2 User-Mode Components

**File: client/win11mon_profile.h**
- Profile query APIs
- ML export APIs
- Anomaly configuration

**File: client/win11mon_profile.c**
- `Mon_ProfileGet()` - Get profile for specific PID
- `Mon_ProfileList()` - Enumerate all profiles
- `Mon_ProfileExportML()` - Export feature vectors
- `Mon_ProfileSetAnomaly()` - Configure anomaly rules

### 5.3 Integration Points

1. **ioring_enum.c**: Call `MonProfileUpdate()` on handle discovery
2. **regbuf_integrity.c**: Update violation counts in profile
3. **telemetry_ringbuf.c**: Log anomaly events
4. **win11_monitor_mgr.c**: Add IOCTL dispatch

---

## 6. Event Types

### 6.1 New Event Definitions

```c
/* Add to MONITOR_EVENT_TYPE enum */
MonEvent_ProcessAnomalyDetected = 11,
MonEvent_ProfileCreated = 12,
MonEvent_ProfileDestroyed = 13,
MonEvent_BurstDetected = 14,

/* Anomaly event payload */
typedef struct _MON_ANOMALY_EVENT {
    ULONG   Size;
    ULONG   ProcessId;
    ULONG   RuleId;
    WCHAR   RuleName[32];
    ULONG   AnomalyScore;
    ULONG   ThresholdExceeded;
    ULONG   ActualValue;
    ULONG64 Timestamp;
    CHAR    ATT_CK_Technique[16];   /* e.g., "T1055" for process injection */
} MON_ANOMALY_EVENT, *PMON_ANOMALY_EVENT;
```

---

## 7. Testing Plan

### 7.1 Unit Tests

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| PRF-T01 | Profile creation on first IoRing | Profile allocated |
| PRF-T02 | Profile update on operations | Counters incremented |
| PRF-T03 | Ops-per-second calculation | Accurate within 5% |
| PRF-T04 | History sliding window | Oldest data evicted |
| PRF-T05 | Anomaly rule threshold | Event generated |
| PRF-T06 | ML feature export | Valid vector format |
| PRF-T07 | Profile cleanup on exit | No memory leaks |
| PRF-T08 | Max process limit | Graceful rejection |

### 7.2 Integration Tests

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| PRF-I01 | Profile persists across enum cycles | State maintained |
| PRF-I02 | Violation count from regbuf_integrity | Count incremented |
| PRF-I03 | Anomaly event to ring buffer | Event captured |
| PRF-I04 | IOCTL profile list | All profiles returned |
| PRF-I05 | ML export with normalization | Values 0.0-1.0 |

### 7.3 Behavioral Tests

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| PRF-B01 | Normal application IoRing use | Low anomaly score |
| PRF-B02 | High-frequency operations | Anomaly triggered |
| PRF-B03 | Large buffer registration | Anomaly triggered |
| PRF-B04 | Burst pattern detection | Burst event logged |
| PRF-B05 | Elevated process IoRing | Flag set correctly |

---

## 8. Performance Considerations

### 8.1 Memory Budget

- Per-profile: ~512 bytes + history buffer
- Max 1024 profiles: ~1MB total
- ML feature vectors: ~256 bytes each (temporary)

### 8.2 CPU Impact

- Profile update: O(1) - simple counter increments
- Anomaly check: O(R) where R = rule count (typically <20)
- Feature export: O(1) per profile

### 8.3 Locking Strategy

- Profile list: Reader-writer lock (ERESOURCE)
- Individual profiles: Interlocked operations for counters
- Anomaly evaluation: Snapshot-based (no locks during check)

---

## 9. Dependencies

- Phase 5A: Ring Buffer Telemetry (event logging)
- A1: IoRing Handle Enumeration (data source)
- A2: RegBuffers Integrity Validation (violation counts)
- B3: Rate Limiting (per-process tracking infrastructure)

---

## 10. File Deliverables

| File | Type | Description |
|------|------|-------------|
| `process_profile.h` | Header | Profile structures and APIs |
| `process_profile.c` | Source | Profile management |
| `anomaly_rules.c` | Source | Rule evaluation engine |
| `client/win11mon_profile.h` | Header | Client profile APIs |
| `client/win11mon_profile.c` | Source | Client implementation |
| `test_profile.c` | Test | Unit tests |

---

## 11. Research Sources

- [io_uring Security Concerns - Sysdig](https://www.sysdig.com/blog/detecting-and-mitigating-io-uring-abuse-for-malware-evasion)
- [io_uring Rootkit - ARMO](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/)
- [EDR Internals - WhiteFlag](https://blog.whiteflag.io/blog/from-windows-drivers-to-a-almost-fully-working-edr/)
- [Process Anomaly Detection with ML - Medium](https://medium.com/@myth7672/windows-process-anomaly-detection-with-ai-ml-ed58163b8272)
- [eBPF Autoencoder Anomaly Detection - EvilSocket](https://www.evilsocket.net/2022/08/15/Process-behaviour-anomaly-detection-using-eBPF-and-unsupervised-learning-Autoencoders/)
- [Statistical Pattern Feature Extraction - ScienceDirect](https://www.sciencedirect.com/science/article/abs/pii/S0950584920301154)
- [Kernel Rootkit Behavior Profiling - arXiv](https://arxiv.org/pdf/2304.00473)
- [Process Monitor - Microsoft](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)

---

## 12. Approval

- [ ] Architecture review completed
- [ ] Security review completed
- [ ] Implementation approved

---

*End of Phase 7 Plan*
