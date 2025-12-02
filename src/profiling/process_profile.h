/*
 * Process Behavior Profiling Module - Public Header
 *
 * Author: Colin MacRitchie | ziX Labs
 * Organization: ziX Labs - Security Research Division
 * File: process_profile.h
 * Version: 1.0
 * Date: 2025-11-30
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and
 * confidential. Redistribution or disclosure without prior written consent is
 * prohibited.
 *
 * Summary
 * -------
 * IoRing-specific process behavior profiling for tracking usage patterns,
 * detecting anomalies, and extracting ML-ready features. Establishes behavioral
 * baselines and identifies deviations indicative of exploitation or abuse.
 *
 * SECURITY PROPERTIES:
 * - Input: All process IDs validated before profile access
 * - Output: No kernel pointers disclosed; sanitized metrics only
 * - Memory Safety: Interlocked operations for counters; ERESOURCE for list
 * - IRQL: Most functions PASSIVE_LEVEL; counters DISPATCH_LEVEL safe
 *
 * Architecture:
 * - Per-process profile storage with fixed capacity
 * - Sliding window for ops-per-second calculation
 * - Built-in anomaly rules with configurable thresholds
 * - ML feature vector export for training pipelines
 *
 * References:
 * - PLAN_phase7_process_profiling.md
 * - io_uring rootkit evasion (ARMO, Sysdig research)
 */

#ifndef _ZIX_LABS_PROCESS_PROFILE_H_
#define _ZIX_LABS_PROCESS_PROFILE_H_

#ifndef _KERNEL_MODE
#error "This header is for kernel-mode only."
#endif

#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------
 * Pool Tags
 *-------------------------------------------------------------------------*/
#define MON_PROFILE_TAG      'frPM' /* 'MPrf' - Monitor Profile */
#define MON_PROFILE_LIST_TAG 'lPrM' /* 'MPrl' - Profile List */

/*--------------------------------------------------------------------------
 * Configuration Constants
 *-------------------------------------------------------------------------*/
#define MON_PROFILE_MAGIC         0x50524F46 /* 'PROF' */
#define MON_PROFILE_HISTORY_SLOTS 60         /* 1 minute at 1-second granularity */
#define MON_PROFILE_MAX_PROCESSES                                               \
  1024                                   /* Max simultaneous profiled processes \
                                          */
#define MON_PROFILE_ML_FEATURE_VERSION 1 /* Feature schema version */

/*--------------------------------------------------------------------------
 * Profile Flags
 *-------------------------------------------------------------------------*/
#define MON_PROFILE_FLAG_ELEVATED        0x0001 /* Process is elevated/admin */
#define MON_PROFILE_FLAG_SERVICE         0x0002 /* Running as service */
#define MON_PROFILE_FLAG_NON_INTERACTIVE 0x0004 /* No interactive session */
#define MON_PROFILE_FLAG_SYSTEM          0x0008 /* SYSTEM account */
#define MON_PROFILE_FLAG_BLACKLISTED     0x0010 /* On interception blacklist */
#define MON_PROFILE_FLAG_WHITELISTED     0x0020 /* Exempt from anomaly rules */
#define MON_PROFILE_FLAG_EXPORTED        0x0040 /* ML features exported */

/*--------------------------------------------------------------------------
 * Anomaly Rule IDs
 *-------------------------------------------------------------------------*/
typedef enum _MON_ANOMALY_RULE_ID {
  MonAnomalyRule_None = 0,
  MonAnomalyRule_HighOpsFrequency = 1,        /* >1000 ops/sec sustained */
  MonAnomalyRule_LargeBufferRegistration = 2, /* Single buffer >100MB */
  MonAnomalyRule_RapidHandleCreation = 3,     /* >10 handles in 1 second */
  MonAnomalyRule_ElevatedIoRingAbuse = 4,     /* Non-interactive elevated process */
  MonAnomalyRule_BurstPattern = 5,            /* >500 ops in <100ms repeated */
  MonAnomalyRule_ConcurrentTargets = 6,       /* >50 distinct files */
  MonAnomalyRule_ViolationAccumulation = 7,   /* RegBuf violations accumulating */
  MonAnomalyRule_Max = 8
} MON_ANOMALY_RULE_ID;

/*--------------------------------------------------------------------------
 * Anomaly Severity Levels
 *-------------------------------------------------------------------------*/
typedef enum _MON_ANOMALY_SEVERITY {
  MonSeverity_Info = 0,
  MonSeverity_Low = 1,
  MonSeverity_Medium = 2,
  MonSeverity_High = 3,
  MonSeverity_Critical = 4
} MON_ANOMALY_SEVERITY;

/*--------------------------------------------------------------------------
 * Anomaly Rule Definition
 *-------------------------------------------------------------------------*/
typedef struct _MON_ANOMALY_RULE {
  MON_ANOMALY_RULE_ID RuleId;
  WCHAR RuleName[32];
  ULONG Threshold;     /* Rule-specific threshold */
  ULONG WindowSeconds; /* Evaluation window */
  MON_ANOMALY_SEVERITY Severity;
  BOOLEAN Enabled;
  BOOLEAN Reserved[3];
  CHAR MitreTechnique[16]; /* e.g., "T1055" */
} MON_ANOMALY_RULE, *PMON_ANOMALY_RULE;

C_ASSERT(sizeof(MON_ANOMALY_RULE) == 80);

/*--------------------------------------------------------------------------
 * Process Profile Structure
 *
 * Stores per-process IoRing usage metrics and anomaly tracking.
 * Allocated on first IoRing activity, freed on process termination.
 *-------------------------------------------------------------------------*/
typedef struct _MON_PROCESS_PROFILE {
  ULONG Magic; /* MON_PROFILE_MAGIC */
  ULONG ProcessId;
  ULONG64 ProcessStartTime; /* System time when profiling started */

  /* Handle tracking */
  volatile LONG ActiveHandleCount;
  ULONG TotalHandlesCreated;
  ULONG TotalHandlesClosed;

  /* Operation counters (lifetime) */
  volatile LONG64 TotalOperations;
  ULONG64 TotalReads;
  ULONG64 TotalWrites;
  ULONG64 TotalCancels;
  ULONG64 TotalOther; /* RegisterFiles, RegisterBuffers, etc. */

  /* Buffer statistics */
  ULONG64 TotalBufferBytesRegistered;
  ULONG MaxBufferSize;
  ULONG AvgBufferSize;
  ULONG TotalBuffersRegistered;

  /* File statistics */
  ULONG TotalFilesRegistered;
  ULONG MaxConcurrentFiles;

  /* Sliding window for ops/second (1-second resolution) */
  ULONG OpsCurrentSecond; /* Accumulator for current second */
  ULONG OpsHistory[MON_PROFILE_HISTORY_SLOTS];
  ULONG HistoryIndex;               /* Circular buffer index */
  LARGE_INTEGER LastSecondBoundary; /* Start of current second */
  LARGE_INTEGER LastUpdateTime;

  /* Anomaly tracking */
  volatile LONG AnomalyScore; /* 0-100, higher = more suspicious */
  ULONG AnomalyEventCount;
  ULONG ViolationCount; /* RegBuffer violations */
  ULONG BurstCount;     /* Detected operation bursts */
  ULONG TriggeredRules; /* Bitmask of triggered rule IDs */

  /* Process context flags */
  ULONG Flags;

  /* Process image name (cached) */
  WCHAR ImageName[64];

  /* Timestamps */
  ULONG64 FirstSeenTime;
  ULONG64 LastActivityTime;
  ULONG64 LastExportTime;

  /* List linkage (internal use) */
  LIST_ENTRY ListEntry;

  /* Padding for cache alignment */
  ULONG Reserved[4];

} MON_PROCESS_PROFILE, *PMON_PROCESS_PROFILE;

C_ASSERT(FIELD_OFFSET(MON_PROCESS_PROFILE, ListEntry) == 360);

/*--------------------------------------------------------------------------
 * Profile Summary (for IOCTL response)
 *
 * Sanitized subset of profile data safe for user-mode consumption.
 *-------------------------------------------------------------------------*/
typedef struct _MON_PROFILE_SUMMARY {
  ULONG Size; /* sizeof(MON_PROFILE_SUMMARY) */
  ULONG ProcessId;
  WCHAR ProcessName[64];

  /* Key metrics */
  ULONG ActiveHandles;
  ULONG64 TotalOperations;
  ULONG OpsPerSecond; /* Average over history window */
  ULONG64 TotalMemoryBytes;

  /* Anomaly info */
  ULONG AnomalyScore;
  ULONG AnomalyEventCount;
  ULONG ViolationCount;
  ULONG TriggeredRules;

  /* Timestamps (relative to boot) */
  ULONG64 FirstSeenTime;
  ULONG64 LastActivityTime;
  ULONG ActiveDurationSec;

  /* Flags */
  ULONG Flags;

} MON_PROFILE_SUMMARY, *PMON_PROFILE_SUMMARY;

C_ASSERT(sizeof(MON_PROFILE_SUMMARY) == 200);

/*--------------------------------------------------------------------------
 * ML Feature Vector
 *
 * Normalized features for machine learning pipelines.
 * Designed for export to training/inference systems.
 *-------------------------------------------------------------------------*/
typedef struct _MON_ML_FEATURE_VECTOR {
  ULONG Size;    /* sizeof(MON_ML_FEATURE_VECTOR) */
  ULONG Version; /* MON_PROFILE_ML_FEATURE_VERSION */
  ULONG ProcessId;
  ULONG Reserved1;
  ULONG64 Timestamp; /* System time of extraction */

  /* Normalized features (scaled for ML consumption) */
  float OpsPerSecond;      /* Operations per second */
  float SubmitsPerMinute;  /* NtSubmitIoRing calls per minute */
  float HandleCount;       /* Active handle count */
  float AvgBufferSizeKB;   /* Average buffer size in KB */
  float MaxBufferSizeMB;   /* Max buffer size in MB */
  float TotalMemoryMB;     /* Total memory footprint in MB */
  float ReadWriteRatio;    /* Read ops / (Read + Write ops) */
  float RegisteredFiles;   /* Pre-registered file count */
  float ActiveDurationMin; /* Time with active IoRing in minutes */
  float BurstFrequency;    /* Bursts per minute */
  float ViolationRate;     /* Violations per 1000 ops */
  float ProcessAgeMin;     /* Process lifetime in minutes */

  /* Categorical features */
  ULONG ProcessElevation;   /* 0=standard, 1=elevated */
  ULONG ProcessInteractive; /* 0=no, 1=yes */
  ULONG ProcessIsService;   /* 0=no, 1=yes */
  ULONG AnomalyScore;       /* 0-100 */

  /* Label (for supervised learning) */
  ULONG Label; /* 0=benign, 1=suspicious, user-assigned */
  ULONG Reserved2;

} MON_ML_FEATURE_VECTOR, *PMON_ML_FEATURE_VECTOR;

C_ASSERT(sizeof(MON_ML_FEATURE_VECTOR) == 96);

/*--------------------------------------------------------------------------
 * Anomaly Event Payload (for ring buffer)
 *-------------------------------------------------------------------------*/
typedef struct _MON_ANOMALY_EVENT_DATA {
  ULONG Size;
  ULONG ProcessId;
  ULONG RuleId;
  ULONG Reserved;
  WCHAR RuleName[32];
  ULONG AnomalyScore;
  ULONG ThresholdExceeded;
  ULONG ActualValue;
  ULONG Severity;
  ULONG64 Timestamp;
  CHAR MitreTechnique[16];
} MON_ANOMALY_EVENT_DATA, *PMON_ANOMALY_EVENT_DATA;

C_ASSERT(sizeof(MON_ANOMALY_EVENT_DATA) == 120);

/*--------------------------------------------------------------------------
 * Profile Statistics (global counters)
 *-------------------------------------------------------------------------*/
typedef struct _MON_PROFILE_STATS {
  ULONG Size;
  ULONG Reserved;
  ULONG ActiveProfiles; /* Current profile count */
  ULONG TotalProfilesCreated;
  ULONG TotalProfilesDestroyed;
  ULONG TotalAnomaliesDetected;
  ULONG64 TotalUpdates;
  ULONG64 TotalExports;
} MON_PROFILE_STATS, *PMON_PROFILE_STATS;

C_ASSERT(sizeof(MON_PROFILE_STATS) == 40);

/*--------------------------------------------------------------------------
 * Profile Configuration
 *-------------------------------------------------------------------------*/
typedef struct _MON_PROFILE_CONFIG {
  ULONG Size;
  BOOLEAN Enabled;       /* Profile collection enabled */
  BOOLEAN AutoExport;    /* Auto-export on anomaly */
  BOOLEAN AutoBlacklist; /* Auto-add to blacklist on high score */
  BOOLEAN Reserved1;
  ULONG AnomalyThreshold;   /* Score threshold for events (0-100) */
  ULONG BlacklistThreshold; /* Score for auto-blacklist (0-100) */
  ULONG HistoryWindowSec;   /* Ops/sec window (default 60) */
  ULONG Reserved2;
} MON_PROFILE_CONFIG, *PMON_PROFILE_CONFIG;

C_ASSERT(sizeof(MON_PROFILE_CONFIG) == 24);

/*==========================================================================
 * Public API Function Prototypes
 *=========================================================================*/

/**
 * @function   MonProfileInitialize
 * @purpose    Initialize the process profiling subsystem
 * @precondition IRQL == PASSIVE_LEVEL; Called from DriverEntry
 * @postcondition Profile list and rules initialized
 * @returns    STATUS_SUCCESS on success
 *             STATUS_INSUFFICIENT_RESOURCES if allocation fails
 * @thread-safety Single-threaded init
 * @side-effects Allocates profile storage; initializes locks
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS MonProfileInitialize(VOID);

/**
 * @function   MonProfileShutdown
 * @purpose    Shutdown profiling and free all resources
 * @precondition IRQL == PASSIVE_LEVEL; Called from DriverUnload
 * @postcondition All profiles freed; subsystem unavailable
 * @thread-safety Single-threaded shutdown
 * @side-effects Frees all profile memory
 */
_IRQL_requires_(PASSIVE_LEVEL) VOID MonProfileShutdown(VOID);

/**
 * @function   MonProfileIsInitialized
 * @purpose    Check if profiling subsystem is ready
 * @precondition IRQL <= DISPATCH_LEVEL
 * @returns    TRUE if initialized and ready
 * @thread-safety Lock-free read
 */
_IRQL_requires_max_(DISPATCH_LEVEL) BOOLEAN MonProfileIsInitialized(VOID);

/**
 * @function   MonProfileCreate
 * @purpose    Create profile for a process on first IoRing activity
 * @precondition IRQL == PASSIVE_LEVEL
 * @postcondition New profile allocated and linked
 *
 * @param[in]  ProcessId - Target process ID
 * @param[in]  ImageName - Optional process image name (may be NULL)
 * @returns    STATUS_SUCCESS if created or already exists
 *             STATUS_INSUFFICIENT_RESOURCES if at capacity
 *             STATUS_NOT_SUPPORTED if not initialized
 *
 * @thread-safety ERESOURCE-synchronized
 * @side-effects Allocates profile; logs ProfileCreated event
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS
    MonProfileCreate(_In_ ULONG ProcessId, _In_opt_ PCWSTR ImageName);

/**
 * @function   MonProfileDestroy
 * @purpose    Destroy profile for a terminated process
 * @precondition IRQL == PASSIVE_LEVEL
 *
 * @param[in]  ProcessId - Process whose profile to destroy
 * @returns    TRUE if profile found and destroyed
 *
 * @thread-safety ERESOURCE-synchronized
 * @side-effects Exports ML features if configured; logs ProfileDestroyed
 */
_IRQL_requires_(PASSIVE_LEVEL) BOOLEAN MonProfileDestroy(_In_ ULONG ProcessId);

/**
 * @function   MonProfileGetByPid
 * @purpose    Retrieve profile for a specific process
 * @precondition IRQL == PASSIVE_LEVEL
 *
 * @param[in]  ProcessId - Target process
 * @returns    Pointer to profile (valid until next destroy) or NULL
 *
 * @thread-safety Returns shared reference; caller must not store long-term
 * @side-effects None
 */
_IRQL_requires_(PASSIVE_LEVEL) PMON_PROCESS_PROFILE MonProfileGetByPid(_In_ ULONG ProcessId);

/**
 * @function   MonProfileRecordOperation
 * @purpose    Record an IoRing operation for a process
 * @precondition IRQL <= DISPATCH_LEVEL
 *
 * @param[in]  ProcessId - Process performing operation
 * @param[in]  OpCode - IoRing operation code
 * @param[in]  BufferSize - Buffer size (if applicable)
 *
 * @thread-safety Interlocked counters; ERESOURCE for profile lookup
 * @side-effects Updates counters; may trigger anomaly check
 */
_IRQL_requires_max_(DISPATCH_LEVEL) VOID
    MonProfileRecordOperation(_In_ ULONG ProcessId, _In_ ULONG OpCode, _In_ ULONG BufferSize);

/**
 * @function   MonProfileRecordHandle
 * @purpose    Record IoRing handle creation/destruction
 * @precondition IRQL <= DISPATCH_LEVEL
 *
 * @param[in]  ProcessId - Process
 * @param[in]  Created - TRUE for creation, FALSE for destruction
 *
 * @thread-safety Interlocked counters
 */
_IRQL_requires_max_(DISPATCH_LEVEL) VOID
    MonProfileRecordHandle(_In_ ULONG ProcessId, _In_ BOOLEAN Created);

/**
 * @function   MonProfileRecordViolation
 * @purpose    Record a RegBuffer or policy violation
 * @precondition IRQL <= DISPATCH_LEVEL
 *
 * @param[in]  ProcessId - Process with violation
 *
 * @thread-safety Interlocked increment
 * @side-effects May trigger anomaly event
 */
_IRQL_requires_max_(DISPATCH_LEVEL) VOID MonProfileRecordViolation(_In_ ULONG ProcessId);

/**
 * @function   MonProfileGetSummary
 * @purpose    Get sanitized profile summary for user-mode
 * @precondition IRQL == PASSIVE_LEVEL
 *
 * @param[in]  ProcessId - Target process
 * @param[out] Summary - Output buffer
 * @returns    STATUS_SUCCESS if found
 *             STATUS_NOT_FOUND if no profile
 *
 * @thread-safety Snapshot under shared lock
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS
    MonProfileGetSummary(_In_ ULONG ProcessId, _Out_ PMON_PROFILE_SUMMARY Summary);

/**
 * @function   MonProfileEnumerate
 * @purpose    Enumerate all active profiles
 * @precondition IRQL == PASSIVE_LEVEL
 *
 * @param[out]    Buffer - Array of summaries
 * @param[in]     MaxCount - Buffer capacity
 * @param[out]    ActualCount - Number of profiles returned
 * @returns       STATUS_SUCCESS on success
 *
 * @thread-safety Shared lock during enumeration
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS
    MonProfileEnumerate(_Out_writes_to_(MaxCount, *ActualCount) PMON_PROFILE_SUMMARY Buffer,
                        _In_ ULONG MaxCount, _Out_ ULONG *ActualCount);

/**
 * @function   MonProfileExportFeatures
 * @purpose    Export ML feature vector for a process
 * @precondition IRQL == PASSIVE_LEVEL
 *
 * @param[in]  ProcessId - Target process
 * @param[out] Features - Output feature vector
 * @returns    STATUS_SUCCESS if exported
 *             STATUS_NOT_FOUND if no profile
 *
 * @thread-safety Snapshot under shared lock
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS
    MonProfileExportFeatures(_In_ ULONG ProcessId, _Out_ PMON_ML_FEATURE_VECTOR Features);

/**
 * @function   MonProfileGetStats
 * @purpose    Get global profiling statistics
 * @precondition IRQL <= DISPATCH_LEVEL
 *
 * @param[out] Stats - Output statistics
 *
 * @thread-safety Lock-free counter reads
 */
_IRQL_requires_max_(DISPATCH_LEVEL) VOID MonProfileGetStats(_Out_ PMON_PROFILE_STATS Stats);

/**
 * @function   MonProfileSetConfig
 * @purpose    Configure profiling behavior
 * @precondition IRQL == PASSIVE_LEVEL
 *
 * @param[in]  Config - New configuration
 * @returns    STATUS_SUCCESS on success
 *
 * @thread-safety ERESOURCE-synchronized
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS MonProfileSetConfig(_In_ PMON_PROFILE_CONFIG Config);

/**
 * @function   MonProfileGetConfig
 * @purpose    Get current profiling configuration
 * @precondition IRQL <= DISPATCH_LEVEL
 *
 * @param[out] Config - Output configuration
 *
 * @thread-safety Lock-free snapshot
 */
_IRQL_requires_max_(DISPATCH_LEVEL) VOID MonProfileGetConfig(_Out_ PMON_PROFILE_CONFIG Config);

/**
 * @function   MonProfileResetAll
 * @purpose    Reset all profile counters (keep profiles)
 * @precondition IRQL == PASSIVE_LEVEL
 *
 * @thread-safety Exclusive lock during reset
 * @side-effects Clears all metrics; resets anomaly scores
 */
_IRQL_requires_(PASSIVE_LEVEL) VOID MonProfileResetAll(VOID);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _ZIX_LABS_PROCESS_PROFILE_H_ */
