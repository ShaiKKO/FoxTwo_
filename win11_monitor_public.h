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
    ULONG   BufferSizeBytes;            /* 0 = use default (1MB) */
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

#ifdef __cplusplus
} /* extern "C" */
#endif
