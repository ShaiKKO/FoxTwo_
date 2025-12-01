#pragma once

/*
 * Author: Colin MacRitchie
 * Organization: ziX Performance Labs
 * File: win11_monitor_mgr.h
 * Version: 1.2
 * Date: 2025-12-01
 * Copyright:
 *   © 2025 ziX Performance Labs. All rights reserved. Proprietary and confidential.
 *   Redistribution or disclosure without prior written consent is prohibited.

 * Summary:
 * Windows 11 Monitor Manager – Shared Public Contracts
 *
 * Exposes device naming, IOCTL-visible structures, and telemetry schemas used
 * by both kernel-mode components and privileged user-mode tooling. This header
 * is safe to include from either environment; it selects the appropriate base
 * definitions automatically.
 
 */

#ifdef _KERNEL_MODE
# include <ntddk.h>
#else
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
# include <winioctl.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------*/
/* Device Identity                                                          */
/*--------------------------------------------------------------------------*/
#define WIN11MON_DEVICE_NAME_U   L"\\Device\\Win11MonitorMgr"
#define WIN11MON_SYMLINK_NAME_U  L"\\DosDevices\\Win11MonitorMgr"
#define WIN11MON_DOSLINK_U       L"\\\\.\\Win11MonitorMgr"

/*--------------------------------------------------------------------------*/
/* Versioning & Capabilities                                                */
/*--------------------------------------------------------------------------*/
#define WIN11MON_VERSION_MAJOR   1
#define WIN11MON_VERSION_MINOR   1
#define WIN11MON_VERSION_BUILD   2025

#define WIN11MON_CAP_IOP_MC                0x00000001u
#define WIN11MON_CAP_POOL_TRACK            0x00000002u
#define WIN11MON_CAP_TELEMETRY             0x00000004u
#define WIN11MON_CAP_RATE_LIMIT            0x00000008u
#define WIN11MON_CAP_ENCRYPTION_STUB       0x00000010u

/* Enhancement capabilities (v1.1+) */
#define WIN11MON_CAP_IORING_ENUM           0x00000020u  /* A1: IoRing enumeration */
#define WIN11MON_CAP_REGBUF_INTEGRITY      0x00000040u  /* A2: RegBuffers validation */
#define WIN11MON_CAP_EXTENDED_TAGS         0x00000080u  /* A3: Extended pool tag monitoring */
#define WIN11MON_CAP_ETW_PROVIDER          0x00000100u  /* B1: ETW TraceLogging */
#define WIN11MON_CAP_ADDR_MASKING          0x00000200u  /* B2: Address masking */
#define WIN11MON_CAP_PERPROC_RATELIMIT     0x00000400u  /* B3: Per-process rate limiting */
#define WIN11MON_CAP_RUNTIME_OFFSETS       0x00000800u  /* C1: Runtime offset resolution */
#define WIN11MON_CAP_ATTACK_TAGGING        0x00001000u  /* D1: MITRE ATT&CK tagging */
#define WIN11MON_CAP_RING_BUFFER           0x00002000u  /* E1: Ring buffer telemetry */
#define WIN11MON_CAP_IORING_INTERCEPT      0x00004000u  /* Phase 6: IoRing interception */
#define WIN11MON_CAP_PROCESS_PROFILE       0x00008000u  /* Phase 7: Process profiling */
#define WIN11MON_CAP_ANOMALY_RULES         0x00010000u  /* Phase 7: Anomaly rule engine */
#define WIN11MON_CAP_MEM_MONITOR           0x00020000u  /* Phase 8: Memory region monitoring */
#define WIN11MON_CAP_CROSS_PROCESS         0x00040000u  /* Phase 9: Cross-process detection */

/* IOCTL Contracts (METHOD_BUFFERED, FILE_DEVICE_UNKNOWN) ----------------- */

#define WIN11MON_IOCTL_BASE  0x800

#define IOCTL_MONITOR_GET_VERSION      CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x00, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_GET_CAPABILITIES CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x01, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_ENABLE           CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x02, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_MONITOR_DISABLE          CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x03, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_MONITOR_GET_STATS        CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x04, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_FETCH_EVENTS     CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x05, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_SET_TELEMETRY    CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x06, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_MONITOR_SET_ENCRYPTION   CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x07, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_MONITOR_SCAN_NOW         CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x08, METHOD_BUFFERED, FILE_WRITE_ACCESS)
/* IOCTL_MONITOR_PARSE_IOP_MC
 *  - Parses an internal IOP_MC buffer entry and returns sanitized metadata.
 *  - SECURITY: No raw kernel addresses are returned; the Address field is masked.
 */
#define IOCTL_MONITOR_PARSE_IOP_MC     CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x09, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Enhancement IOCTLs (v1.1+) ------------------------------------------------*/

/* IOCTL_MONITOR_GET_IORING_HANDLES
 *  - Enumerates all IoRing handles in the system with validation status.
 *  - Output: MON_IORING_HANDLES_OUTPUT
 */
#define IOCTL_MONITOR_GET_IORING_HANDLES   CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x0A, METHOD_BUFFERED, FILE_READ_ACCESS)

/* IOCTL_MONITOR_GET_OFFSET_STATUS
 *  - Returns current structure offset resolution status.
 *  - Output: MON_OFFSET_STATUS_OUTPUT
 */
#define IOCTL_MONITOR_GET_OFFSET_STATUS    CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x0C, METHOD_BUFFERED, FILE_READ_ACCESS)

/* IOCTL_MONITOR_SET_MASK_POLICY
 *  - Configure address masking policy (B2).
 *  - Input: MON_MASK_POLICY_INPUT
 */
#define IOCTL_MONITOR_SET_MASK_POLICY      CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x0D, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/* IOCTL_MONITOR_GET_RATE_STATS
 *  - Get per-process rate limiting statistics (B3).
 *  - Output: MON_RATE_LIMIT_STATS
 */
#define IOCTL_MONITOR_GET_RATE_STATS       CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x0E, METHOD_BUFFERED, FILE_READ_ACCESS)

/* Ring Buffer IOCTLs (v1.2+) -------------------------------------------------*/

/* IOCTL_MONITOR_RINGBUF_CONFIGURE
 *  - Configure ring buffer size (requires restart to apply new size).
 *  - Input: MON_RINGBUF_CONFIG_INPUT
 */
#define IOCTL_MONITOR_RINGBUF_CONFIGURE    CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x10, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/* IOCTL_MONITOR_RINGBUF_SNAPSHOT
 *  - Non-destructive copy of ring buffer contents.
 *  - Output: MON_RINGBUF_SNAPSHOT_OUTPUT (header + events)
 */
#define IOCTL_MONITOR_RINGBUF_SNAPSHOT     CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x11, METHOD_BUFFERED, FILE_READ_ACCESS)

/* IOCTL_MONITOR_RINGBUF_GET_STATS
 *  - Get ring buffer statistics.
 *  - Output: MON_RINGBUF_STATS_OUTPUT
 */
#define IOCTL_MONITOR_RINGBUF_GET_STATS    CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x12, METHOD_BUFFERED, FILE_READ_ACCESS)

/* IOCTL_MONITOR_RINGBUF_CLEAR
 *  - Clear all events from the ring buffer.
 *  - No input/output.
 */
#define IOCTL_MONITOR_RINGBUF_CLEAR        CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x13, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/* Interception IOCTLs (v1.2+) ------------------------------------------------*/

/* IOCTL_MONITOR_INTERCEPT_VALIDATE
 *  - Pre-submit validation of IoRing operations.
 *  - Input: MON_INTERCEPT_REQUEST (variable-length with SQE array)
 *  - Output: MON_INTERCEPT_RESPONSE
 */
#define IOCTL_MONITOR_INTERCEPT_VALIDATE   CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x20, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* IOCTL_MONITOR_INTERCEPT_SET_POLICY
 *  - Configure interception policy.
 *  - Input: MON_INTERCEPT_POLICY
 */
#define IOCTL_MONITOR_INTERCEPT_SET_POLICY CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x21, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/* IOCTL_MONITOR_INTERCEPT_GET_POLICY
 *  - Get current interception policy.
 *  - Output: MON_INTERCEPT_POLICY
 */
#define IOCTL_MONITOR_INTERCEPT_GET_POLICY CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x22, METHOD_BUFFERED, FILE_READ_ACCESS)

/* IOCTL_MONITOR_INTERCEPT_GET_STATS
 *  - Get interception statistics.
 *  - Output: MON_INTERCEPT_STATS
 */
#define IOCTL_MONITOR_INTERCEPT_GET_STATS  CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x23, METHOD_BUFFERED, FILE_READ_ACCESS)

/* IOCTL_MONITOR_INTERCEPT_RESET_STATS
 *  - Reset interception statistics to zero.
 *  - No input/output.
 */
#define IOCTL_MONITOR_INTERCEPT_RESET_STATS CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x24, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/* IOCTL_MONITOR_INTERCEPT_ENABLE
 *  - Enable or disable interception.
 *  - Input: ULONG (0 = disable, 1 = enable)
 */
#define IOCTL_MONITOR_INTERCEPT_ENABLE     CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x25, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/* IOCTL_MONITOR_INTERCEPT_ADD_BLACKLIST
 *  - Add a process to the IoRing blacklist.
 *  - Input: MON_INTERCEPT_BLACKLIST_ADD_INPUT
 */
#define IOCTL_MONITOR_INTERCEPT_ADD_BL     CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x26, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/* IOCTL_MONITOR_INTERCEPT_REMOVE_BLACKLIST
 *  - Remove a process from the blacklist.
 *  - Input: ULONG (ProcessId)
 */
#define IOCTL_MONITOR_INTERCEPT_REMOVE_BL  CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x27, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/* IOCTL_MONITOR_INTERCEPT_GET_BLACKLIST
 *  - Enumerate all blacklisted processes.
 *  - Input: ULONG (MaxEntries)
 *  - Output: MON_BLACKLIST_ENTRY array
 */
#define IOCTL_MONITOR_INTERCEPT_GET_BL     CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x28, METHOD_BUFFERED, FILE_READ_ACCESS)

/* Profile IOCTLs (v1.2+ Phase 7) ---------------------------------------------*/

/* IOCTL_MONITOR_PROFILE_GET
 *  - Get profile summary for a specific process.
 *  - Input: ULONG (ProcessId)
 *  - Output: MON_PROFILE_SUMMARY
 */
#define IOCTL_MONITOR_PROFILE_GET          CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x30, METHOD_BUFFERED, FILE_READ_ACCESS)

/* IOCTL_MONITOR_PROFILE_LIST
 *  - Enumerate all active profiles.
 *  - Input: ULONG (MaxCount)
 *  - Output: MON_PROFILE_SUMMARY array
 */
#define IOCTL_MONITOR_PROFILE_LIST         CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x31, METHOD_BUFFERED, FILE_READ_ACCESS)

/* IOCTL_MONITOR_PROFILE_EXPORT_ML
 *  - Export ML feature vector for a process.
 *  - Input: ULONG (ProcessId)
 *  - Output: MON_ML_FEATURE_VECTOR
 */
#define IOCTL_MONITOR_PROFILE_EXPORT_ML    CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x32, METHOD_BUFFERED, FILE_READ_ACCESS)

/* IOCTL_MONITOR_PROFILE_GET_STATS
 *  - Get global profile statistics.
 *  - Output: MON_PROFILE_STATS
 */
#define IOCTL_MONITOR_PROFILE_GET_STATS    CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x33, METHOD_BUFFERED, FILE_READ_ACCESS)

/* IOCTL_MONITOR_PROFILE_GET_CONFIG
 *  - Get current profile configuration.
 *  - Output: MON_PROFILE_CONFIG
 */
#define IOCTL_MONITOR_PROFILE_GET_CONFIG   CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x34, METHOD_BUFFERED, FILE_READ_ACCESS)

/* IOCTL_MONITOR_PROFILE_SET_CONFIG
 *  - Set profile configuration.
 *  - Input: MON_PROFILE_CONFIG
 */
#define IOCTL_MONITOR_PROFILE_SET_CONFIG   CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x35, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/* IOCTL_MONITOR_PROFILE_RESET
 *  - Reset all profile counters (keeps profiles).
 *  - No input/output.
 */
#define IOCTL_MONITOR_PROFILE_RESET        CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x36, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/* Anomaly Rule IOCTLs (v1.2+ Phase 7) ----------------------------------------*/

/* IOCTL_MONITOR_ANOMALY_GET_RULES
 *  - Enumerate all anomaly rules.
 *  - Input: ULONG (MaxCount)
 *  - Output: MON_ANOMALY_RULE_PUBLIC array
 */
#define IOCTL_MONITOR_ANOMALY_GET_RULES    CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x38, METHOD_BUFFERED, FILE_READ_ACCESS)

/* IOCTL_MONITOR_ANOMALY_SET_THRESHOLD
 *  - Configure threshold for an anomaly rule.
 *  - Input: MON_ANOMALY_THRESHOLD_INPUT
 */
#define IOCTL_MONITOR_ANOMALY_SET_THRESHOLD CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x39, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/* IOCTL_MONITOR_ANOMALY_ENABLE_RULE
 *  - Enable or disable an anomaly rule.
 *  - Input: MON_ANOMALY_ENABLE_INPUT
 */
#define IOCTL_MONITOR_ANOMALY_ENABLE_RULE  CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x3A, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/* IOCTL_MONITOR_ANOMALY_GET_STATS
 *  - Get anomaly detection statistics.
 *  - Output: MON_ANOMALY_STATS_PUBLIC
 */
#define IOCTL_MONITOR_ANOMALY_GET_STATS    CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x3B, METHOD_BUFFERED, FILE_READ_ACCESS)

/* IOCTL_MONITOR_ANOMALY_RESET_STATS
 *  - Reset anomaly detection statistics.
 *  - No input/output.
 */
#define IOCTL_MONITOR_ANOMALY_RESET_STATS  CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x3C, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/* Memory Monitoring IOCTLs (v1.4+ Phase 8) ----------------------------------*/

/* IOCTL_MONITOR_MEM_SCAN_VAD
 *  - Scan VAD tree for a process.
 *  - Input: ULONG (ProcessId)
 *  - Output: MON_VAD_SCAN_RESULT_PUBLIC (variable length with VAD array)
 */
#define IOCTL_MONITOR_MEM_SCAN_VAD         CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x40, METHOD_BUFFERED, FILE_READ_ACCESS)

/* IOCTL_MONITOR_MEM_GET_MDLS
 *  - Get tracked MDLs for a process.
 *  - Input: ULONG (ProcessId)
 *  - Output: MON_MDL_TRACKER_PUBLIC
 */
#define IOCTL_MONITOR_MEM_GET_MDLS         CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x41, METHOD_BUFFERED, FILE_READ_ACCESS)

/* IOCTL_MONITOR_MEM_SCAN_PHYSICAL
 *  - Analyze physical page mappings for a process.
 *  - Input: ULONG (ProcessId)
 *  - Output: MON_PHYSICAL_SCAN_RESULT_PUBLIC
 */
#define IOCTL_MONITOR_MEM_SCAN_PHYSICAL    CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x42, METHOD_BUFFERED, FILE_READ_ACCESS)

/* IOCTL_MONITOR_MEM_GET_SHARING
 *  - Detect cross-process memory sharing.
 *  - Input: ULONG (ProcessId)
 *  - Output: MON_SHARING_SCAN_RESULT_PUBLIC (variable length)
 */
#define IOCTL_MONITOR_MEM_GET_SHARING      CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x43, METHOD_BUFFERED, FILE_READ_ACCESS)

/* IOCTL_MONITOR_MEM_GET_STATS
 *  - Get memory monitoring statistics.
 *  - Output: MON_MEM_STATS_PUBLIC
 */
#define IOCTL_MONITOR_MEM_GET_STATS        CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x44, METHOD_BUFFERED, FILE_READ_ACCESS)

/* Cross-Process Detection IOCTLs (v1.5+ Phase 9) -----------------------------*/

/* IOCTL_MONITOR_XP_GET_SHARED
 *  - Query shared IoRing objects (optionally filtered by process).
 *  - Input: ULONG (ProcessId, 0 = all)
 *  - Output: MON_XP_SHARED_OBJECT_PUBLIC array
 */
#define IOCTL_MONITOR_XP_GET_SHARED        CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x50, METHOD_BUFFERED, FILE_READ_ACCESS)

/* IOCTL_MONITOR_XP_GET_TREE
 *  - Get process relationship tree snapshot.
 *  - Output: MON_XP_PROCESS_ENTRY_PUBLIC array
 */
#define IOCTL_MONITOR_XP_GET_TREE          CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x51, METHOD_BUFFERED, FILE_READ_ACCESS)

/* IOCTL_MONITOR_XP_SCAN_SECTIONS
 *  - Enumerate section objects for cross-process correlation.
 *  - Input: ULONG (ProcessId)
 *  - Output: MON_XP_SECTION_INFO_PUBLIC array
 */
#define IOCTL_MONITOR_XP_SCAN_SECTIONS     CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x52, METHOD_BUFFERED, FILE_READ_ACCESS)

/* IOCTL_MONITOR_XP_GET_ALERTS
 *  - Retrieve pending cross-process alerts.
 *  - Output: MON_XP_ALERT_EVENT_PUBLIC array
 */
#define IOCTL_MONITOR_XP_GET_ALERTS        CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x53, METHOD_BUFFERED, FILE_READ_ACCESS)

/* IOCTL_MONITOR_XP_GET_STATS
 *  - Get cross-process detection statistics.
 *  - Output: MON_XP_STATS_PUBLIC
 */
#define IOCTL_MONITOR_XP_GET_STATS         CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x54, METHOD_BUFFERED, FILE_READ_ACCESS)

/* IOCTL_MONITOR_XP_GET_CONFIG
 *  - Get cross-process detection configuration.
 *  - Output: MON_XP_CONFIG_PUBLIC
 */
#define IOCTL_MONITOR_XP_GET_CONFIG        CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x55, METHOD_BUFFERED, FILE_READ_ACCESS)

/* IOCTL_MONITOR_XP_SET_CONFIG
 *  - Set cross-process detection configuration.
 *  - Input: MON_XP_CONFIG_PUBLIC
 */
#define IOCTL_MONITOR_XP_SET_CONFIG        CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x56, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/* IOCTL_MONITOR_XP_SCAN_NOW
 *  - Trigger immediate cross-process scan.
 *  - No input/output.
 */
#define IOCTL_MONITOR_XP_SCAN_NOW          CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x57, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/*--------------------------------------------------------------------------*/
/* Public Data Schemas                                                      */
/*--------------------------------------------------------------------------*/

typedef struct _MONITOR_SETTINGS {
    ULONG Size;
    ULONG EnableMonitoring;     /* 0/1 */
    ULONG EnableTelemetry;      /* 0/1 */
    ULONG EnableEncryption;     /* 0/1 (stub in current release) */
    ULONG RateLimitPerSec;      /* Max events/sec per process (0 = default) */
} MONITOR_SETTINGS, *PMONITOR_SETTINGS;

typedef struct _MONITOR_STATS {
    ULONG   Size;
    ULONG64 TotalAllocations;
    ULONG64 IopMcDetections;
    ULONG64 CrossVmDetections;
    ULONG64 PolicyViolations;
    ULONG64 DroppedEvents;
    ULONG   PoolEntryCount;
    ULONG   TelemetryEventCount;
    ULONG   CurrentRateLimit;
} MONITOR_STATS, *PMONITOR_STATS;

typedef enum _MONITOR_EVENT_TYPE {
    MonEvent_Invalid = 0,
    MonEvent_PoolAllocation = 1,
    MonEvent_IopMcDetected  = 2,
    MonEvent_CrossVmDetected = 3,
    MonEvent_PolicyViolation = 4,
    MonEvent_Anomaly = 5,

    /* Enhancement event types (v1.1+) */
    MonEvent_IoRingHandleCreated = 6,
    MonEvent_IoRingHandleSpray = 7,
    MonEvent_IoRingHandleDuplicated = 8,
    MonEvent_RegBuffersViolation = 9,
    MonEvent_OffsetResolutionFailed = 10,

    MonEvent_Max
} MONITOR_EVENT_TYPE;

typedef struct _CROSS_VM_EVENT_INFO {
    ULONG              Size;
    MONITOR_EVENT_TYPE Type;
    ULONG              ProcessId;
    ULONG              ThreadId;
    ULONG              PoolTag;
    ULONG              Severity;        /* 1..5 */
    ULONG_PTR          SuspectAddress;
    ULONG              Reserved;
} CROSS_VM_EVENT_INFO, *PCROSS_VM_EVENT_INFO;

typedef struct _EVENT_BLOB {
    ULONG              Size;           /* sizeof(EVENT_BLOB) + PayloadLength */
    MONITOR_EVENT_TYPE Type;
    ULONG              PayloadLength;  /* Bytes following this header */
    UCHAR              Payload[ANYSIZE_ARRAY];
} EVENT_BLOB, *PEVENT_BLOB;

/*--------------------------------------------------------------------------*/
/* Enhancement Schemas (v1.1+)                                              */
/*--------------------------------------------------------------------------*/

/* Offset resolution methods */
typedef enum _MON_OFFSET_RESOLUTION_METHOD {
    MonOffsetMethod_Unknown = 0,
    MonOffsetMethod_Embedded = 1,     /* From compiled-in table */
    MonOffsetMethod_Detected = 2,     /* Runtime detection */
    MonOffsetMethod_Degraded = 3      /* Unable to resolve */
} MON_OFFSET_RESOLUTION_METHOD;

/* IOCTL_MONITOR_GET_OFFSET_STATUS output */
typedef struct _MON_OFFSET_STATUS_OUTPUT {
    ULONG Size;
    ULONG WindowsBuildNumber;
    MON_OFFSET_RESOLUTION_METHOD Method;
    ULONG IoRingOffsetsValid;         /* BOOLEAN as ULONG for alignment */
    ULONG IopMcOffsetsValid;          /* BOOLEAN as ULONG for alignment */
    ULONG IoRingStructureSize;
    ULONG IopMcStructureSize;
} MON_OFFSET_STATUS_OUTPUT, *PMON_OFFSET_STATUS_OUTPUT;

/* RegBuffers violation event payload */
typedef struct _MON_REGBUF_VIOLATION_EVENT {
    ULONG     Size;
    ULONG     ProcessId;
    ULONG     ThreadId;
    ULONG64   IoRingObjectAddress;    /* Masked */
    ULONG64   RegBuffersAddress;      /* Masked */
    ULONG     RegBuffersCount;
    ULONG     ViolationFlags;
    UCHAR     Severity;
    CHAR      ATT_CK_Technique[16];   /* e.g., "T1068" */
} MON_REGBUF_VIOLATION_EVENT, *PMON_REGBUF_VIOLATION_EVENT;

/* IoRing handle event payload */
typedef struct _MON_IORING_HANDLE_EVENT {
    ULONG     Size;
    ULONG     ProcessId;
    ULONG64   HandleValue;
    ULONG64   ObjectAddress;          /* Masked */
    ULONG     AccessMask;
    UCHAR     EventSubType;           /* Created/Duplicated/Spray */
    UCHAR     Severity;
    UCHAR     Reserved[2];
} MON_IORING_HANDLE_EVENT, *PMON_IORING_HANDLE_EVENT;

/* Address masking policy (mirrors kernel enum for user-mode use) */
typedef enum _MON_ADDRESS_MASK_POLICY_PUBLIC {
    MonMaskPolicy_None_Public = 0,      /* No masking (debug only) */
    MonMaskPolicy_Truncate_Public = 1,  /* Keep high 16 bits */
    MonMaskPolicy_Hash_Public = 2,      /* SipHash transformation (default) */
    MonMaskPolicy_Zero_Public = 3       /* Complete removal */
} MON_ADDRESS_MASK_POLICY_PUBLIC;

/* IOCTL_MONITOR_SET_MASK_POLICY input */
typedef struct _MON_MASK_POLICY_INPUT {
    ULONG Size;                         /* Must be sizeof(MON_MASK_POLICY_INPUT) */
    MON_ADDRESS_MASK_POLICY_PUBLIC Policy;
} MON_MASK_POLICY_INPUT, *PMON_MASK_POLICY_INPUT;

/* IOCTL_MONITOR_GET_RATE_STATS output */
typedef struct _MON_RATE_LIMIT_STATS {
    ULONG     Size;
    ULONG     ActiveProcessCount;       /* Processes currently tracked */
    ULONG64   TotalEventsAllowed;       /* Events that passed rate limiting */
    ULONG64   TotalEventsDropped;       /* Events dropped due to rate limiting */
    ULONG64   ProcessDropCount;         /* Dropped due to per-process limit */
    ULONG64   GlobalDropCount;          /* Dropped due to global limit */
    ULONG     CurrentGlobalRate;        /* Events/sec in current window */
    ULONG     PeakGlobalRate;           /* Highest events/sec observed */
    ULONG     GlobalLimitPerSec;        /* Configured global limit */
    ULONG     PerProcessLimitPerSec;    /* Configured per-process limit */
} MON_RATE_LIMIT_STATS, *PMON_RATE_LIMIT_STATS;

/* IoRing handle info for IOCTL_MONITOR_GET_IORING_HANDLES */
typedef struct _MON_IORING_HANDLE_INFO {
    ULONG   ProcessId;
    ULONG64 HandleValue;
    ULONG64 ObjectAddress;              /* Masked per policy */
    ULONG   AccessMask;
    ULONG   RegBuffersCount;
    ULONG   ViolationFlags;
} MON_IORING_HANDLE_INFO, *PMON_IORING_HANDLE_INFO;

/*--------------------------------------------------------------------------*/
/* Ring Buffer Schemas (v1.2+)                                              */
/*--------------------------------------------------------------------------*/

/* Ring buffer configuration input */
typedef struct _MON_RINGBUF_CONFIG_INPUT {
    ULONG   Size;                       /* Must be sizeof(MON_RINGBUF_CONFIG_INPUT) */
    ULONG   BufferSizeBytes;            /* 0 = use default (1MBP) */
    ULONG   Flags;                      /* Reserved, must be 0 */
} MON_RINGBUF_CONFIG_INPUT, *PMON_RINGBUF_CONFIG_INPUT;

/* Ring buffer statistics output */
typedef struct _MON_RINGBUF_STATS_OUTPUT {
    ULONG   Size;                       /* sizeof(MON_RINGBUF_STATS_OUTPUT) */
    ULONG   BufferSizeBytes;            /* Total buffer allocation */
    ULONG   UsedBytes;                  /* Bytes currently used */
    ULONG   FreeBytes;                  /* Bytes available */
    ULONG   EventCount;                 /* Events in buffer */
    ULONG   TotalEventsWritten;         /* Lifetime event count */
    ULONG   EventsOverwritten;          /* Events lost to overwrite */
    ULONG   EventsDropped;              /* Events dropped (too large) */
    ULONG   WrapCount;                  /* Buffer wrap-around count */
    ULONG64 OldestTimestamp;            /* Oldest event timestamp */
    ULONG64 NewestTimestamp;            /* Newest event timestamp */
} MON_RINGBUF_STATS_OUTPUT, *PMON_RINGBUF_STATS_OUTPUT;

/* Ring buffer snapshot header (returned at start of snapshot) */
typedef struct _MON_RINGBUF_SNAPSHOT_OUTPUT {
    ULONG   Size;                       /* sizeof(MON_RINGBUF_SNAPSHOT_OUTPUT) */
    ULONG   EventCount;                 /* Events in snapshot */
    ULONG   TotalBytes;                 /* Total bytes including header */
    ULONG   Flags;                      /* Reserved */
    ULONG64 SnapshotTime;               /* When snapshot was taken */
    ULONG64 OldestEventTime;            /* Oldest event timestamp */
    ULONG64 NewestEventTime;            /* Newest event timestamp */
    ULONG   FirstSequence;              /* First event sequence number */
    ULONG   LastSequence;               /* Last event sequence number */
    /* Events follow immediately after this header */
} MON_RINGBUF_SNAPSHOT_OUTPUT, *PMON_RINGBUF_SNAPSHOT_OUTPUT;

/* Ring buffer event header (stored in ring and returned in snapshot) */
typedef struct _MON_RING_EVENT {
    ULONG              Magic;           /* 'REVT' (0x54564552) for validation */
    ULONG              TotalSize;       /* Total bytes including header and padding */
    ULONG              PayloadSize;     /* Actual payload bytes */
    MONITOR_EVENT_TYPE EventType;       /* Event type enum */
    ULONG64            Timestamp;       /* System time in 100ns units */
    ULONG              ProcessId;       /* Source process ID */
    ULONG              ThreadId;        /* Source thread ID */
    ULONG              SequenceNumber;  /* Monotonic sequence for ordering */
    ULONG              Reserved;        /* Alignment padding */
    /* Payload follows immediately */
} MON_RING_EVENT, *PMON_RING_EVENT;

/*--------------------------------------------------------------------------*/
/* Interception Schemas (v1.2+ Phase 6)                                     */
/*--------------------------------------------------------------------------*/

/* Interception action result */
typedef enum _MON_INTERCEPT_ACTION_PUBLIC {
    MonIntercept_Allow_Public = 0,      /* Operation permitted */
    MonIntercept_Block_Public = 1,      /* Operation blocked */
    MonIntercept_LogOnly_Public = 2     /* Audit mode: log but permit */
} MON_INTERCEPT_ACTION_PUBLIC;

/* Interception violation reasons */
typedef enum _MON_INTERCEPT_REASON_PUBLIC {
    MonReason_None_Public = 0,
    MonReason_RegBuffersCorrupted_Public = 1,
    MonReason_KernelAddressInBuffer_Public = 2,
    MonReason_ExcessiveOperations_Public = 3,
    MonReason_SuspiciousOpCode_Public = 4,
    MonReason_ProcessBlacklisted_Public = 5,
    MonReason_RateLimitExceeded_Public = 6,
    MonReason_InvalidHandle_Public = 7,
    MonReason_PolicyDisabled_Public = 8,
    MonReason_ValidationError_Public = 9,
    MonReason_BufferSizeTooLarge_Public = 10,
    MonReason_MalformedRequest_Public = 11
} MON_INTERCEPT_REASON_PUBLIC;

/* Blacklist add input structure */
typedef struct _MON_INTERCEPT_BLACKLIST_ADD_INPUT {
    ULONG ProcessId;
    CHAR  Reason[64];
} MON_INTERCEPT_BLACKLIST_ADD_INPUT, *PMON_INTERCEPT_BLACKLIST_ADD_INPUT;

/*--------------------------------------------------------------------------*/
/* Profile Schemas (v1.2+ Phase 7)                                          */
/*--------------------------------------------------------------------------*/

/* Profile flags */
#define MON_PROFILE_FLAG_ELEVATED_PUB        0x0001
#define MON_PROFILE_FLAG_SERVICE_PUB         0x0002
#define MON_PROFILE_FLAG_NON_INTERACTIVE_PUB 0x0004
#define MON_PROFILE_FLAG_SYSTEM_PUB          0x0008
#define MON_PROFILE_FLAG_BLACKLISTED_PUB     0x0010
#define MON_PROFILE_FLAG_WHITELISTED_PUB     0x0020
#define MON_PROFILE_FLAG_EXPORTED_PUB        0x0040

/* Anomaly rule IDs */
typedef enum _MON_ANOMALY_RULE_ID_PUBLIC {
    MonAnomalyRule_None_Pub = 0,
    MonAnomalyRule_HighOpsFrequency_Pub = 1,
    MonAnomalyRule_LargeBufferRegistration_Pub = 2,
    MonAnomalyRule_RapidHandleCreation_Pub = 3,
    MonAnomalyRule_ElevatedIoRingAbuse_Pub = 4,
    MonAnomalyRule_BurstPattern_Pub = 5,
    MonAnomalyRule_ConcurrentTargets_Pub = 6,
    MonAnomalyRule_ViolationAccumulation_Pub = 7,
    MonAnomalyRule_Max_Pub = 8
} MON_ANOMALY_RULE_ID_PUBLIC;

/* Anomaly severity levels */
typedef enum _MON_ANOMALY_SEVERITY_PUBLIC {
    MonSeverity_Info_Pub = 0,
    MonSeverity_Low_Pub = 1,
    MonSeverity_Medium_Pub = 2,
    MonSeverity_High_Pub = 3,
    MonSeverity_Critical_Pub = 4
} MON_ANOMALY_SEVERITY_PUBLIC;

/* Profile summary (IOCTL_MONITOR_PROFILE_GET/LIST output) */
typedef struct _MON_PROFILE_SUMMARY_PUBLIC {
    ULONG       Size;                       /* sizeof(MON_PROFILE_SUMMARY_PUBLIC) */
    ULONG       ProcessId;
    WCHAR       ProcessName[64];

    /* Key metrics */
    ULONG       ActiveHandles;
    ULONG64     TotalOperations;
    ULONG       OpsPerSecond;
    ULONG64     TotalMemoryBytes;

    /* Anomaly info */
    ULONG       AnomalyScore;               /* 0-100 */
    ULONG       AnomalyEventCount;
    ULONG       ViolationCount;
    ULONG       TriggeredRules;             /* Bitmask */

    /* Timestamps */
    ULONG64     FirstSeenTime;
    ULONG64     LastActivityTime;
    ULONG       ActiveDurationSec;

    /* Flags */
    ULONG       Flags;

} MON_PROFILE_SUMMARY_PUBLIC, *PMON_PROFILE_SUMMARY_PUBLIC;

/* ML Feature vector (IOCTL_MONITOR_PROFILE_EXPORT_ML output) */
typedef struct _MON_ML_FEATURE_VECTOR_PUBLIC {
    ULONG       Size;                       /* sizeof(MON_ML_FEATURE_VECTOR_PUBLIC) */
    ULONG       Version;
    ULONG       ProcessId;
    ULONG       Reserved1;
    ULONG64     Timestamp;

    /* Normalized features */
    float       OpsPerSecond;
    float       SubmitsPerMinute;
    float       HandleCount;
    float       AvgBufferSizeKB;
    float       MaxBufferSizeMB;
    float       TotalMemoryMB;
    float       ReadWriteRatio;
    float       RegisteredFiles;
    float       ActiveDurationMin;
    float       BurstFrequency;
    float       ViolationRate;
    float       ProcessAgeMin;

    /* Categorical features */
    ULONG       ProcessElevation;
    ULONG       ProcessInteractive;
    ULONG       ProcessIsService;
    ULONG       AnomalyScore;

    /* Label */
    ULONG       Label;
    ULONG       Reserved2;

} MON_ML_FEATURE_VECTOR_PUBLIC, *PMON_ML_FEATURE_VECTOR_PUBLIC;

/* Profile statistics (IOCTL_MONITOR_PROFILE_GET_STATS output) */
typedef struct _MON_PROFILE_STATS_PUBLIC {
    ULONG       Size;
    ULONG       Reserved;
    ULONG       ActiveProfiles;
    ULONG       TotalProfilesCreated;
    ULONG       TotalProfilesDestroyed;
    ULONG       TotalAnomaliesDetected;
    ULONG64     TotalUpdates;
    ULONG64     TotalExports;
} MON_PROFILE_STATS_PUBLIC, *PMON_PROFILE_STATS_PUBLIC;

/* Profile configuration (IOCTL_MONITOR_PROFILE_GET/SET_CONFIG) */
typedef struct _MON_PROFILE_CONFIG_PUBLIC {
    ULONG       Size;
    ULONG       Enabled;                    /* BOOLEAN as ULONG for alignment */
    ULONG       AutoExport;
    ULONG       AutoBlacklist;
    ULONG       AnomalyThreshold;           /* Score threshold for events (0-100) */
    ULONG       BlacklistThreshold;         /* Score for auto-blacklist (0-100) */
    ULONG       HistoryWindowSec;
    ULONG       Reserved;
} MON_PROFILE_CONFIG_PUBLIC, *PMON_PROFILE_CONFIG_PUBLIC;

/* Anomaly rule definition (IOCTL_MONITOR_ANOMALY_GET_RULES output) */
typedef struct _MON_ANOMALY_RULE_PUBLIC {
    MON_ANOMALY_RULE_ID_PUBLIC RuleId;
    WCHAR       RuleName[32];
    ULONG       Threshold;
    ULONG       WindowSeconds;
    MON_ANOMALY_SEVERITY_PUBLIC Severity;
    ULONG       ScoreImpact;
    ULONG       Enabled;                    /* BOOLEAN as ULONG */
    CHAR        MitreTechnique[16];
} MON_ANOMALY_RULE_PUBLIC, *PMON_ANOMALY_RULE_PUBLIC;

/* Anomaly threshold input (IOCTL_MONITOR_ANOMALY_SET_THRESHOLD) */
typedef struct _MON_ANOMALY_THRESHOLD_INPUT {
    ULONG       RuleId;
    ULONG       Threshold;
} MON_ANOMALY_THRESHOLD_INPUT, *PMON_ANOMALY_THRESHOLD_INPUT;

/* Anomaly enable input (IOCTL_MONITOR_ANOMALY_ENABLE_RULE) */
typedef struct _MON_ANOMALY_ENABLE_INPUT {
    ULONG       RuleId;
    ULONG       Enable;                     /* BOOLEAN as ULONG */
} MON_ANOMALY_ENABLE_INPUT, *PMON_ANOMALY_ENABLE_INPUT;

/* Anomaly statistics (IOCTL_MONITOR_ANOMALY_GET_STATS output) */
typedef struct _MON_ANOMALY_STATS_PUBLIC {
    ULONG       Size;
    ULONG       TotalRules;
    ULONG       EnabledRules;
    ULONG       TotalEvaluations;
    ULONG       TotalMatches;
    ULONG       Reserved;
} MON_ANOMALY_STATS_PUBLIC, *PMON_ANOMALY_STATS_PUBLIC;

/* Process anomaly event (ring buffer event payload) */
typedef struct _MON_ANOMALY_EVENT_PUBLIC {
    ULONG       Size;
    ULONG       ProcessId;
    ULONG       RuleId;
    ULONG       Reserved;
    WCHAR       RuleName[32];
    ULONG       AnomalyScore;
    ULONG       ThresholdExceeded;
    ULONG       ActualValue;
    ULONG       Severity;
    ULONG64     Timestamp;
    CHAR        MitreTechnique[16];
} MON_ANOMALY_EVENT_PUBLIC, *PMON_ANOMALY_EVENT_PUBLIC;

/*--------------------------------------------------------------------------*/
/* Memory Monitoring Schemas (v1.4+ Phase 8)                                 */
/*--------------------------------------------------------------------------*/

/* VAD type enumeration (public) */
typedef enum _MON_VAD_TYPE_PUBLIC {
    MonVadType_Private_Pub = 0,
    MonVadType_Mapped_Pub = 1,
    MonVadType_Image_Pub = 2,
    MonVadType_Physical_Pub = 3,
    MonVadType_WriteWatch_Pub = 4,
    MonVadType_LargePages_Pub = 5,
    MonVadType_Rotate_Pub = 6,
    MonVadType_Unknown_Pub = 7
} MON_VAD_TYPE_PUBLIC;

/* Memory anomaly types (public) */
typedef enum _MON_MEM_ANOMALY_PUBLIC {
    MonMemAnomaly_None_Pub = 0,
    MonMemAnomaly_ExecutableHeap_Pub = 1,      /* Private + Executable */
    MonMemAnomaly_WritableCode_Pub = 2,        /* Image + Writable + Executable */
    MonMemAnomaly_UnbackedExecutable_Pub = 3,  /* No file backing, executable */
    MonMemAnomaly_HiddenRegion_Pub = 4,        /* VAD present, no PTE */
    MonMemAnomaly_DoubleMapped_Pub = 5,        /* Same physical in multiple VA */
    MonMemAnomaly_CrossProcessSharing_Pub = 6, /* Unexpected sharing */
    MonMemAnomaly_KernelAddressInUser_Pub = 7, /* Kernel address in user VAD */
    MonMemAnomaly_GuardPageMissing_Pub = 8,    /* Stack without guard */
    MonMemAnomaly_SuspiciousProtection_Pub = 9,/* Unusual protection combo */
    MonMemAnomaly_LargePrivateRegion_Pub = 10, /* Unusually large private */
    MonMemAnomaly_RWXRegion_Pub = 11,          /* Read-Write-Execute */
    MonMemAnomaly_MdlLocked_Pub = 12,          /* MDL locked pages */
    MonMemAnomaly_Max_Pub = 13
} MON_MEM_ANOMALY_PUBLIC;

/* Single VAD info (public) */
typedef struct _MON_VAD_INFO_PUBLIC {
    ULONG64     StartAddress;       /* Masked */
    ULONG64     EndAddress;         /* Masked */
    ULONG64     Size;
    MON_VAD_TYPE_PUBLIC VadType;
    ULONG       Protection;
    ULONG       InitialProtection;
    ULONG       IsExecutable;       /* BOOLEAN as ULONG */
    ULONG       IsWritable;         /* BOOLEAN as ULONG */
    ULONG       IsPrivate;          /* BOOLEAN as ULONG */
    ULONG       IsCommitted;        /* BOOLEAN as ULONG */
    ULONG       HasFileBackingStore; /* BOOLEAN as ULONG */
    ULONG       AnomalyFlags;       /* Bitmask of MON_MEM_ANOMALY_PUBLIC */
} MON_VAD_INFO_PUBLIC, *PMON_VAD_INFO_PUBLIC;

/* VAD scan result (IOCTL_MONITOR_MEM_SCAN_VAD output) */
typedef struct _MON_VAD_SCAN_RESULT_PUBLIC {
    ULONG       Size;               /* sizeof(MON_VAD_SCAN_RESULT_PUBLIC) */
    ULONG       ProcessId;
    ULONG       VadCount;           /* Total VADs found */
    ULONG       DetailedInfoCount;  /* Number of MON_VAD_INFO_PUBLIC following */
    ULONG64     TotalPrivateBytes;
    ULONG64     TotalMappedBytes;
    ULONG64     TotalExecutableBytes;
    ULONG64     TotalCommittedBytes;
    ULONG       SuspiciousVadCount;
    ULONG       AnomalyFlags;       /* Aggregate bitmask */
    ULONG64     ScanStartTime;
    ULONG64     ScanEndTime;
    ULONG       ScanDurationUs;
    ULONG       Reserved;
    /* MON_VAD_INFO_PUBLIC array follows */
} MON_VAD_SCAN_RESULT_PUBLIC, *PMON_VAD_SCAN_RESULT_PUBLIC;

/* MDL info (public) */
typedef struct _MON_MDL_INFO_PUBLIC {
    ULONG64     VirtualAddress;     /* Masked */
    ULONG64     ByteCount;
    ULONG64     ByteOffset;
    ULONG       ProcessId;
    ULONG       Flags;
    ULONG       PageCount;
    ULONG       IsLocked;           /* BOOLEAN as ULONG */
    ULONG       IsMapped;           /* BOOLEAN as ULONG */
    ULONG       IsNonPagedPool;     /* BOOLEAN as ULONG */
    ULONG64     CreationTime;
    ULONG       AnomalyFlags;
    ULONG       Reserved;
} MON_MDL_INFO_PUBLIC, *PMON_MDL_INFO_PUBLIC;

/* MDL tracker output (IOCTL_MONITOR_MEM_GET_MDLS output) */
typedef struct _MON_MDL_TRACKER_PUBLIC {
    ULONG       Size;
    ULONG       ProcessId;
    ULONG       TrackedMdlCount;
    ULONG       MaxMdlsReturned;
    ULONG64     TotalLockedBytes;
    ULONG64     TotalMappedBytes;
    ULONG       SuspiciousMdlCount;
    ULONG       Reserved;
    /* MON_MDL_INFO_PUBLIC array follows */
} MON_MDL_TRACKER_PUBLIC, *PMON_MDL_TRACKER_PUBLIC;

/* Physical scan result (IOCTL_MONITOR_MEM_SCAN_PHYSICAL output) */
typedef struct _MON_PHYSICAL_SCAN_RESULT_PUBLIC {
    ULONG       Size;
    ULONG       ProcessId;
    ULONG64     TotalPhysicalBytes;
    ULONG64     WorkingSetBytes;
    ULONG       PageCount;
    ULONG       SharedPageCount;
    ULONG       PrivatePageCount;
    ULONG       ModifiedPageCount;
    ULONG       DoubleMappedCount;  /* Same PFN in multiple VAs */
    ULONG       SuspiciousCount;
    ULONG       AnomalyFlags;
    ULONG       ScanDurationUs;
} MON_PHYSICAL_SCAN_RESULT_PUBLIC, *PMON_PHYSICAL_SCAN_RESULT_PUBLIC;

/* Shared region info (public) */
typedef struct _MON_SHARED_REGION_PUBLIC {
    ULONG64     VirtualAddress;     /* Masked */
    ULONG64     Size;
    ULONG       ProcessIdOwner;
    ULONG       ProcessIdSharer;
    ULONG       ShareType;          /* Section, mapped file, etc. */
    ULONG       IsExecutable;       /* BOOLEAN as ULONG */
    ULONG       AnomalyFlags;
    ULONG       Reserved;
} MON_SHARED_REGION_PUBLIC, *PMON_SHARED_REGION_PUBLIC;

/* Sharing scan result (IOCTL_MONITOR_MEM_GET_SHARING output) */
typedef struct _MON_SHARING_SCAN_RESULT_PUBLIC {
    ULONG       Size;
    ULONG       ProcessId;
    ULONG       SharedRegionCount;
    ULONG       SuspiciousShareCount;
    ULONG64     TotalSharedBytes;
    ULONG       CrossProcessShareCount;
    ULONG       Reserved;
    /* MON_SHARED_REGION_PUBLIC array follows */
} MON_SHARING_SCAN_RESULT_PUBLIC, *PMON_SHARING_SCAN_RESULT_PUBLIC;

/* Memory monitoring statistics (IOCTL_MONITOR_MEM_GET_STATS output) */
typedef struct _MON_MEM_STATS_PUBLIC {
    ULONG       Size;
    ULONG       Reserved;
    ULONG64     VadScansPerformed;
    ULONG64     MdlScansPerformed;
    ULONG64     PhysicalScansPerformed;
    ULONG64     SharingScansPerformed;
    ULONG64     TotalAnomaliesDetected;
    ULONG       TrackedMdlCount;
    ULONG       TrackedProcessCount;
    ULONG64     TotalBytesScanned;
    ULONG       AverageVadScanTimeUs;
    ULONG       PeakVadScanTimeUs;
    ULONG       AnomaliesByType[16]; /* Count per MON_MEM_ANOMALY_PUBLIC */
} MON_MEM_STATS_PUBLIC, *PMON_MEM_STATS_PUBLIC;

/* Memory anomaly event (ring buffer event payload) */
typedef struct _MON_MEM_ANOMALY_EVENT_PUBLIC {
    ULONG       Size;
    ULONG       ProcessId;
    ULONG       AnomalyType;
    ULONG       Severity;
    ULONG64     Address;            /* Masked */
    ULONG64     Size_Region;
    ULONG64     Timestamp;
    CHAR        MitreTechnique[16];
    WCHAR       Description[64];
} MON_MEM_ANOMALY_EVENT_PUBLIC, *PMON_MEM_ANOMALY_EVENT_PUBLIC;

/* Phase 8 event types (extend MONITOR_EVENT_TYPE) */
#ifndef MON_EVENT_PHASE8_DEFINED
#define MON_EVENT_PHASE8_DEFINED
#define MonEvent_MemoryAnomalyDetected   15
#define MonEvent_VadScanCompleted        16
#define MonEvent_MdlTracked              17
#define MonEvent_SuspiciousSharingFound  18
#endif

/* Add MonEvent types for Phase 7 */
#ifndef MON_EVENT_PHASE7_DEFINED
#define MON_EVENT_PHASE7_DEFINED
/* These extend MONITOR_EVENT_TYPE enum */
#define MonEvent_ProcessAnomalyDetected  11
#define MonEvent_ProfileCreated          12
#define MonEvent_ProfileDestroyed        13
#define MonEvent_BurstDetected           14
#endif

/*--------------------------------------------------------------------------*/
/* Cross-Process Detection Schemas (v1.5+ Phase 9)                           */
/*--------------------------------------------------------------------------*/

/* Cross-process alert types (public) */
typedef enum _MON_XP_ALERT_TYPE_PUBLIC {
    MonXpAlert_None_Pub = 0,
    MonXpAlert_SharedIoRing_Pub = 1,            /* IoRing in multiple processes */
    MonXpAlert_UnrelatedSharing_Pub = 2,        /* Non-parent/child sharing */
    MonXpAlert_CrossIntegrityShare_Pub = 3,    /* Different integrity levels */
    MonXpAlert_SystemIoRingAccess_Pub = 4,     /* SYSTEM has user IoRing */
    MonXpAlert_HandleDuplication_Pub = 5,       /* DuplicateHandle detected */
    MonXpAlert_SectionSharing_Pub = 6,          /* Section shared with IoRing */
    MonXpAlert_InheritanceAnomaly_Pub = 7,      /* Unexpected inheritance */
    MonXpAlert_Max_Pub = 8
} MON_XP_ALERT_TYPE_PUBLIC;

/* Cross-process severity (public, aligned with anomaly severity) */
typedef enum _MON_XP_SEVERITY_PUBLIC {
    MonXpSeverity_Info_Pub = 0,
    MonXpSeverity_Low_Pub = 1,
    MonXpSeverity_Medium_Pub = 2,
    MonXpSeverity_High_Pub = 3,
    MonXpSeverity_Critical_Pub = 4
} MON_XP_SEVERITY_PUBLIC;

/* Cross-process rule IDs (100-105 range, public) */
typedef enum _MON_XP_RULE_ID_PUBLIC {
    MonXpRule_None_Pub = 0,
    MonXpRule_UnrelatedIoRingSharing_Pub = 100,
    MonXpRule_SystemIoRingFromUser_Pub = 101,
    MonXpRule_CrossIntegrityIoRing_Pub = 102,
    MonXpRule_SectionIoRingBuffer_Pub = 103,
    MonXpRule_UnexpectedInheritance_Pub = 104,
    MonXpRule_RapidDuplication_Pub = 105,
    MonXpRule_Max_Pub = 106
} MON_XP_RULE_ID_PUBLIC;

/* Shared object flags (public) */
#define MON_XP_FLAG_CROSS_INTEGRITY_PUB     0x0001
#define MON_XP_FLAG_CROSS_SESSION_PUB       0x0002
#define MON_XP_FLAG_SYSTEM_INVOLVED_PUB     0x0004
#define MON_XP_FLAG_SERVICE_INVOLVED_PUB    0x0008
#define MON_XP_FLAG_UNRELATED_PUB           0x0010
#define MON_XP_FLAG_SUSPICIOUS_PUB          0x0020
#define MON_XP_FLAG_INHERITED_PUB           0x0040
#define MON_XP_FLAG_WHITELISTED_PUB         0x0080

/* Process cache flags (public) */
#define MON_XP_PROC_FLAG_ELEVATED_PUB       0x0001
#define MON_XP_PROC_FLAG_SERVICE_PUB        0x0002
#define MON_XP_PROC_FLAG_SYSTEM_PUB         0x0004
#define MON_XP_PROC_FLAG_INTERACTIVE_PUB    0x0008
#define MON_XP_PROC_FLAG_TERMINATED_PUB     0x0010

/* Handle entry within shared object (public) */
typedef struct _MON_XP_HANDLE_ENTRY_PUBLIC {
    ULONG       ProcessId;
    ULONG64     HandleValue;
    ULONG       AccessMask;
    ULONG       IntegrityLevel;
    ULONG       SessionId;
    ULONG       IsInherited;            /* BOOLEAN as ULONG */
    ULONG64     FirstSeenTime;
} MON_XP_HANDLE_ENTRY_PUBLIC, *PMON_XP_HANDLE_ENTRY_PUBLIC;

/* Shared object record (IOCTL_MONITOR_XP_GET_SHARED output element) */
typedef struct _MON_XP_SHARED_OBJECT_PUBLIC {
    ULONG64     ObjectAddressMasked;
    ULONG       ObjectTypeIndex;
    ULONG       ProcessCount;
    ULONG       Flags;                  /* MON_XP_FLAG_*_PUB */
    ULONG       RiskScore;              /* 0-100 */
    ULONG       TriggeredRules;         /* Bitmask */
    ULONG       HasParentChildRelation; /* BOOLEAN as ULONG */
    ULONG       CommonAncestorPid;
    ULONG64     FirstDetectedTime;
    ULONG64     LastUpdatedTime;
    ULONG       HasSectionBacking;      /* BOOLEAN as ULONG */
    ULONG       Reserved;
    /* Up to 8 processes inline (variable count) */
    MON_XP_HANDLE_ENTRY_PUBLIC Processes[8];
} MON_XP_SHARED_OBJECT_PUBLIC, *PMON_XP_SHARED_OBJECT_PUBLIC;

/* Process tree entry (IOCTL_MONITOR_XP_GET_TREE output element) */
typedef struct _MON_XP_PROCESS_ENTRY_PUBLIC {
    ULONG       ProcessId;
    ULONG       ParentProcessId;
    ULONG       SessionId;
    ULONG       IntegrityLevel;
    ULONG       Flags;                  /* MON_XP_PROC_FLAG_*_PUB */
    ULONG       Reserved;
    ULONG64     CreateTime;
    WCHAR       ImageName[32];
} MON_XP_PROCESS_ENTRY_PUBLIC, *PMON_XP_PROCESS_ENTRY_PUBLIC;

/* Section info (IOCTL_MONITOR_XP_SCAN_SECTIONS output element) */
typedef struct _MON_XP_SECTION_INFO_PUBLIC {
    ULONG64     SectionAddressMasked;
    WCHAR       SectionName[64];
    ULONG       IsNamed;                /* BOOLEAN as ULONG */
    ULONG       MappingCount;
    ULONG64     MaximumSize;
    ULONG       AllocationAttributes;
    ULONG       RelatedToIoRing;        /* BOOLEAN as ULONG */
    ULONG       RelatedIoRingPid;
    ULONG       Reserved;
} MON_XP_SECTION_INFO_PUBLIC, *PMON_XP_SECTION_INFO_PUBLIC;

/* Alert event (IOCTL_MONITOR_XP_GET_ALERTS output / ring buffer event) */
typedef struct _MON_XP_ALERT_EVENT_PUBLIC {
    ULONG       Size;
    MON_XP_ALERT_TYPE_PUBLIC AlertType;
    MON_XP_SEVERITY_PUBLIC Severity;
    ULONG       RuleId;
    ULONG64     Timestamp;
    ULONG64     ObjectAddressMasked;
    ULONG       ObjectTypeIndex;
    ULONG       SourceProcessId;
    ULONG       TargetProcessId;
    WCHAR       SourceProcessName[32];
    WCHAR       TargetProcessName[32];
    ULONG64     SourceHandle;
    ULONG64     TargetHandle;
    ULONG       SourceAccess;
    ULONG       TargetAccess;
    ULONG       IsParentChild;          /* BOOLEAN as ULONG */
    ULONG       SourceIntegrity;
    ULONG       TargetIntegrity;
    ULONG       RiskScore;
    CHAR        MitreTechnique[16];
    CHAR        Description[64];
} MON_XP_ALERT_EVENT_PUBLIC, *PMON_XP_ALERT_EVENT_PUBLIC;

/* Statistics (IOCTL_MONITOR_XP_GET_STATS output) */
typedef struct _MON_XP_STATS_PUBLIC {
    ULONG       Size;
    ULONG       Reserved;
    ULONG       ActiveSharedObjects;
    ULONG       TotalSharedObjectsDetected;
    ULONG       TotalAlertsGenerated;
    ULONG       AlertsSuppressedByWhitelist;
    ULONG       TotalScans;
    ULONG       CachedProcessCount;
    ULONG64     LastScanTime;
    ULONG64     LastTreeRefreshTime;
    ULONG       RuleHits[8];
} MON_XP_STATS_PUBLIC, *PMON_XP_STATS_PUBLIC;

/* Configuration (IOCTL_MONITOR_XP_GET/SET_CONFIG) */
typedef struct _MON_XP_CONFIG_PUBLIC {
    ULONG       Size;
    ULONG       Enabled;                /* BOOLEAN as ULONG */
    ULONG       WhitelistEnabled;       /* BOOLEAN as ULONG */
    ULONG       AutoBlockCritical;      /* BOOLEAN as ULONG */
    ULONG       ScanIntervalMs;
    ULONG       TreeRefreshIntervalMs;
    ULONG       AlertThreshold;         /* Score threshold (default 40) */
    ULONG       CriticalThreshold;      /* Critical score (default 80) */
    ULONG       MaxAlertsPerMinute;
    ULONG       Reserved;
} MON_XP_CONFIG_PUBLIC, *PMON_XP_CONFIG_PUBLIC;

/* Phase 9 event types (extend MONITOR_EVENT_TYPE) */
#ifndef MON_EVENT_PHASE9_DEFINED
#define MON_EVENT_PHASE9_DEFINED
#define MonEvent_CrossProcess            19
#define MonEvent_SharedObjectDetected    20
#define MonEvent_ProcessTreeUpdated      21
#define MonEvent_CrossProcessAlert       22
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif
