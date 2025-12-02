/*
 * Cross-Process Communication Detection Module - Public Header
 *
 * Author: Colin MacRitchie | ziX Labs
 * Organization: ziX Labs - Security Research Division
 * File: cross_process.h
 * Version: 1.0
 * Date: 2025-11-30
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and
 * confidential. Redistribution or disclosure without prior written consent is
 * prohibited.
 *
 * Summary
 * -------
 * Cross-process communication detection focused on IoRing buffer sharing
 * scenarios. Detects shared buffers between processes, tracks handle
 * inheritance/duplication, and correlates named object access to identify
 * potential data exfiltration or privilege escalation attempts.
 *
 * SECURITY PROPERTIES:
 * - Input: All process IDs and handles validated before access
 * - Output: Object addresses masked; no kernel pointers disclosed
 * - Memory Safety: ERESOURCE for relationship map; interlocked for counters
 * - IRQL: Most functions PASSIVE_LEVEL; statistics DISPATCH_LEVEL safe
 *
 * Architecture:
 * - Handle correlation engine with hash table grouping
 * - Process tree cache with binary search lookup
 * - Risk scoring with aggravators/mitigators
 * - 6 built-in detection rules with MITRE ATT&CK mapping
 *
 * References:
 * - PLAN_phase9_cross_process.md
 * - MITRE ATT&CK: T1055 (Process Injection), T1068 (Exploitation)
 */

#ifndef _ZIX_LABS_CROSS_PROCESS_H_
#define _ZIX_LABS_CROSS_PROCESS_H_

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
#define MON_XP_TAG              'pXnM' /* 'MnXp' - Cross-Process general */
#define MON_XP_RELATIONSHIP_TAG 'rXnM' /* 'MnXr' - Relationship entries */
#define MON_XP_TREE_TAG         'tXnM' /* 'MnXt' - Process tree cache */
#define MON_XP_ALERT_TAG        'aXnM' /* 'MnXa' - Alert allocations */

/*--------------------------------------------------------------------------
 * Configuration Constants
 *-------------------------------------------------------------------------*/
#define MON_XP_MAGIC                    0x58505250 /* 'XPRP' */
#define MON_XP_MAX_PROCESSES            64         /* Max processes sharing one object */
#define MON_XP_MAX_SHARED_OBJECTS       256        /* Max tracked shared objects */
#define MON_XP_MAX_CACHED_PROCESSES     4096       /* Process tree cache capacity */
#define MON_XP_MAX_ANCESTORS            8          /* Lineage depth for validation */
#define MON_XP_HASH_BUCKETS             65536      /* Handle grouping hash table size */
#define MON_XP_DEFAULT_SCAN_INTERVAL_MS 30000      /* 30 seconds */
#define MON_XP_DEFAULT_TREE_REFRESH_MS  60000      /* 60 seconds */

/*--------------------------------------------------------------------------
 * Integrity Level Constants
 *-------------------------------------------------------------------------*/
#define MON_IL_UNTRUSTED   0x0000 /* Untrusted */
#define MON_IL_LOW         0x1000 /* Low integrity (sandboxed) */
#define MON_IL_MEDIUM      0x2000 /* Standard user */
#define MON_IL_MEDIUM_PLUS 0x2100 /* Medium+ (IE protected mode) */
#define MON_IL_HIGH        0x3000 /* Elevated admin */
#define MON_IL_SYSTEM      0x4000 /* SYSTEM */
#define MON_IL_PROTECTED   0x5000 /* Protected process */

/*--------------------------------------------------------------------------
 * Cross-Process Alert Types
 *-------------------------------------------------------------------------*/
typedef enum _MON_XP_ALERT_TYPE {
  MonXpAlert_None = 0,
  MonXpAlert_SharedIoRing = 1,        /* IoRing handle in multiple processes */
  MonXpAlert_UnrelatedSharing = 2,    /* Non-parent/child sharing */
  MonXpAlert_CrossIntegrityShare = 3, /* Different integrity levels */
  MonXpAlert_SystemIoRingAccess = 4,  /* SYSTEM has handle to user IoRing */
  MonXpAlert_HandleDuplication = 5,   /* DuplicateHandle detected */
  MonXpAlert_SectionSharing = 6,      /* Section shared with IoRing buffer */
  MonXpAlert_InheritanceAnomaly = 7,  /* Unexpected inheritance */
  MonXpAlert_Max = 8
} MON_XP_ALERT_TYPE;

/*--------------------------------------------------------------------------
 * Cross-Process Severity Levels (0-4, aligned with anomaly_rules.h)
 *-------------------------------------------------------------------------*/
typedef enum _MON_XP_SEVERITY {
  MonXpSeverity_Info = 0,
  MonXpSeverity_Low = 1,
  MonXpSeverity_Medium = 2,
  MonXpSeverity_High = 3,
  MonXpSeverity_Critical = 4
} MON_XP_SEVERITY;

/*--------------------------------------------------------------------------
 * Cross-Process Rule IDs (100-105 range)
 *-------------------------------------------------------------------------*/
typedef enum _MON_XP_RULE_ID {
  MonXpRule_None = 0,
  MonXpRule_UnrelatedIoRingSharing = 100, /* T1055 - Non-parent/child sharing */
  MonXpRule_SystemIoRingFromUser = 101,   /* T1068 - SYSTEM has user IoRing */
  MonXpRule_CrossIntegrityIoRing = 102,   /* T1548 - 2+ integrity level gap */
  MonXpRule_SectionIoRingBuffer = 103,    /* T1055 - Section for IoRing buffer */
  MonXpRule_UnexpectedInheritance = 104,  /* T1055 - Wrong process lineage */
  MonXpRule_RapidDuplication = 105,       /* T1499 - Many DuplicateHandle calls */
  MonXpRule_Max = 106
} MON_XP_RULE_ID;

/*--------------------------------------------------------------------------
 * Shared Object Flags
 *-------------------------------------------------------------------------*/
#define MON_XP_FLAG_CROSS_INTEGRITY  0x0001 /* Different integrity levels */
#define MON_XP_FLAG_CROSS_SESSION    0x0002 /* Different sessions */
#define MON_XP_FLAG_SYSTEM_INVOLVED  0x0004 /* SYSTEM process involved */
#define MON_XP_FLAG_SERVICE_INVOLVED 0x0008 /* Service process involved */
#define MON_XP_FLAG_UNRELATED        0x0010 /* No parent-child relationship */
#define MON_XP_FLAG_SUSPICIOUS       0x0020 /* Anomaly detected */
#define MON_XP_FLAG_INHERITED        0x0040 /* Handle was inherited at spawn */
#define MON_XP_FLAG_WHITELISTED      0x0080 /* Matches whitelist pattern */

/*--------------------------------------------------------------------------
 * Process Cache Flags
 *-------------------------------------------------------------------------*/
#define MON_XP_PROC_FLAG_ELEVATED    0x0001 /* Process is elevated/admin */
#define MON_XP_PROC_FLAG_SERVICE     0x0002 /* Running as service */
#define MON_XP_PROC_FLAG_SYSTEM      0x0004 /* SYSTEM account */
#define MON_XP_PROC_FLAG_INTERACTIVE 0x0008 /* Interactive session */
#define MON_XP_PROC_FLAG_TERMINATED  0x0010 /* Process has exited */

/*--------------------------------------------------------------------------
 * Handle Entry (per-process handle info within a shared object)
 *-------------------------------------------------------------------------*/
typedef struct _MON_XP_HANDLE_ENTRY {
  ULONG ProcessId;
  ULONG64 HandleValue;
  ULONG AccessMask;
  ULONG IntegrityLevel;
  ULONG SessionId;
  BOOLEAN IsInherited; /* If known */
  BOOLEAN Reserved[3];
  ULONG64 FirstSeenTime; /* When handle was first detected */
} MON_XP_HANDLE_ENTRY, *PMON_XP_HANDLE_ENTRY;

C_ASSERT(sizeof(MON_XP_HANDLE_ENTRY) == 40);

/*--------------------------------------------------------------------------
 * Shared Object Record
 *
 * Tracks an IoRing object that has handles in multiple processes.
 *-------------------------------------------------------------------------*/
typedef struct _MON_XP_SHARED_OBJECT {
  ULONG64 ObjectAddressMasked; /* Masked kernel object address */
  UCHAR ObjectTypeIndex;       /* From handle table */
  UCHAR ProcessCount;          /* Number of processes with handles */
  USHORT Flags;                /* MON_XP_FLAG_* */

  /* Per-process info */
  MON_XP_HANDLE_ENTRY Processes[MON_XP_MAX_PROCESSES];

  /* Relationship analysis */
  BOOLEAN HasParentChildRelation;
  ULONG CommonAncestorPid;
  ULONG RelationshipDepth;

  /* Risk scoring */
  ULONG RiskScore;      /* 0-100 */
  ULONG TriggeredRules; /* Bitmask of rule IDs */

  /* Timestamps */
  ULONG64 FirstDetectedTime;
  ULONG64 LastUpdatedTime;

  /* Section correlation (if applicable) */
  BOOLEAN HasSectionBacking;
  BOOLEAN Reserved1[3];
  ULONG64 SectionHandle;
  WCHAR SectionName[64];

  /* List linkage */
  LIST_ENTRY ListEntry;

} MON_XP_SHARED_OBJECT, *PMON_XP_SHARED_OBJECT;

/*--------------------------------------------------------------------------
 * Process Cache Entry (for process tree lookups)
 *-------------------------------------------------------------------------*/
typedef struct _MON_XP_PROCESS_ENTRY {
  ULONG ProcessId;
  ULONG ParentProcessId;
  ULONG SessionId;
  ULONG IntegrityLevel; /* SECURITY_MANDATORY_*_RID */
  ULONG Flags;          /* MON_XP_PROC_FLAG_* */
  ULONG64 CreateTime;
  WCHAR ImageName[32]; /* First 32 chars of image name */
} MON_XP_PROCESS_ENTRY, *PMON_XP_PROCESS_ENTRY;

C_ASSERT(sizeof(MON_XP_PROCESS_ENTRY) == 88);

/*--------------------------------------------------------------------------
 * Cross-Process Detection Rule
 *-------------------------------------------------------------------------*/
typedef struct _MON_XP_RULE {
  MON_XP_RULE_ID RuleId;
  WCHAR RuleName[32];
  MON_XP_ALERT_TYPE AlertType;
  MON_XP_SEVERITY Severity;
  ULONG BaseScore; /* Base risk score (30-80) */
  BOOLEAN Enabled;
  BOOLEAN Reserved[3];
  CHAR MitreTechnique[16]; /* e.g., "T1055" */
} MON_XP_RULE, *PMON_XP_RULE;

C_ASSERT(sizeof(MON_XP_RULE) == 96);

/*--------------------------------------------------------------------------
 * Cross-Process Alert Event (for ring buffer / telemetry)
 *-------------------------------------------------------------------------*/
typedef struct _MON_XP_ALERT_EVENT {
  ULONG Size;
  MON_XP_ALERT_TYPE AlertType;
  MON_XP_SEVERITY Severity;
  ULONG RuleId;
  ULONG64 Timestamp;

  /* Object info */
  ULONG64 ObjectAddressMasked;
  UCHAR ObjectTypeIndex;
  UCHAR Reserved1[3];

  /* Process info */
  ULONG SourceProcessId;
  ULONG TargetProcessId;
  WCHAR SourceProcessName[32];
  WCHAR TargetProcessName[32];

  /* Handle info */
  ULONG64 SourceHandle;
  ULONG64 TargetHandle;
  ULONG SourceAccess;
  ULONG TargetAccess;

  /* Relationship */
  BOOLEAN IsParentChild;
  BOOLEAN Reserved2[3];
  ULONG SourceIntegrity;
  ULONG TargetIntegrity;

  /* Risk assessment */
  ULONG RiskScore;

  /* Context */
  CHAR MitreTechnique[16];
  CHAR Description[64];

} MON_XP_ALERT_EVENT, *PMON_XP_ALERT_EVENT;

C_ASSERT(sizeof(MON_XP_ALERT_EVENT) == 296);

/*--------------------------------------------------------------------------
 * Cross-Process Statistics
 *-------------------------------------------------------------------------*/
typedef struct _MON_XP_STATS {
  ULONG Size;
  ULONG Reserved;
  ULONG ActiveSharedObjects; /* Current tracked shared objects */
  ULONG TotalSharedObjectsDetected;
  ULONG TotalAlertsGenerated;
  ULONG AlertsSuppressedByWhitelist;
  ULONG TotalScans;
  ULONG CachedProcessCount;
  ULONG64 LastScanTime;
  ULONG64 LastTreeRefreshTime;
  /* Per-rule counters */
  ULONG RuleHits[8];
} MON_XP_STATS, *PMON_XP_STATS;

C_ASSERT(sizeof(MON_XP_STATS) == 72);

/*--------------------------------------------------------------------------
 * Cross-Process Configuration
 *-------------------------------------------------------------------------*/
typedef struct _MON_XP_CONFIG {
  ULONG Size;
  BOOLEAN Enabled;           /* Detection enabled */
  BOOLEAN WhitelistEnabled;  /* Apply whitelist patterns */
  BOOLEAN AutoBlockCritical; /* Block on critical score */
  BOOLEAN Reserved1;
  ULONG ScanIntervalMs;        /* Background scan interval */
  ULONG TreeRefreshIntervalMs; /* Process tree cache refresh */
  ULONG AlertThreshold;        /* Score threshold for alerts (40) */
  ULONG CriticalThreshold;     /* Score for critical alerts (80) */
  ULONG MaxAlertsPerMinute;    /* Rate limit for alerts */
} MON_XP_CONFIG, *PMON_XP_CONFIG;

C_ASSERT(sizeof(MON_XP_CONFIG) == 32);

/*--------------------------------------------------------------------------
 * Section Information (for section object enumeration)
 *-------------------------------------------------------------------------*/
typedef struct _MON_XP_SECTION_INFO {
  PVOID SectionAddress;  /* Kernel section object address */
  ULONG64 SectionSize;   /* Size of section */
  ULONG Protection;      /* Page protection */
  ULONG Flags;           /* Section flags */
  HANDLE OwnerProcessId; /* Owner process */
  WCHAR SectionName[64]; /* Named section name */
} MON_XP_SECTION_INFO, *PMON_XP_SECTION_INFO;

/*==========================================================================
 * Public API Function Prototypes
 *=========================================================================*/

/**
 * @function   MonXpInitialize
 * @purpose    Initialize the cross-process detection subsystem
 * @precondition IRQL == PASSIVE_LEVEL; Called from DriverEntry
 * @postcondition Relationship map, process tree cache, and rules initialized
 * @returns    STATUS_SUCCESS on success
 *             STATUS_INSUFFICIENT_RESOURCES if allocation fails
 * @thread-safety Single-threaded init
 * @side-effects Allocates storage; initializes locks and timer
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS MonXpInitialize(VOID);

/**
 * @function   MonXpShutdown
 * @purpose    Shutdown cross-process detection and free all resources
 * @precondition IRQL == PASSIVE_LEVEL; Called from DriverUnload
 * @postcondition All resources freed; subsystem unavailable
 * @thread-safety Single-threaded shutdown
 * @side-effects Frees all allocated memory; cancels timer
 */
_IRQL_requires_(PASSIVE_LEVEL) VOID MonXpShutdown(VOID);

/**
 * @function   MonXpIsInitialized
 * @purpose    Check if cross-process detection is ready
 * @precondition IRQL <= DISPATCH_LEVEL
 * @returns    TRUE if initialized and ready
 * @thread-safety Lock-free read
 */
_IRQL_requires_max_(DISPATCH_LEVEL) BOOLEAN MonXpIsInitialized(VOID);

/**
 * @function   MonXpScanNow
 * @purpose    Trigger immediate cross-process scan
 * @precondition IRQL == PASSIVE_LEVEL
 * @postcondition Scan queued or executed synchronously
 * @returns    STATUS_SUCCESS if scan initiated
 *             STATUS_NOT_SUPPORTED if not initialized
 * @thread-safety ERESOURCE-synchronized
 * @side-effects Updates shared object map; may generate alerts
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS MonXpScanNow(VOID);

/**
 * @function   MonXpGetSharedObjects
 * @purpose    Retrieve list of shared IoRing objects (allocates output)
 * @precondition IRQL == PASSIVE_LEVEL
 *
 * @param[out] Objects - Receives allocated array (caller frees with MON_XP_TAG)
 * @param[out] Count - Number of objects returned
 * @returns    STATUS_SUCCESS on success
 *             STATUS_INSUFFICIENT_RESOURCES on allocation failure
 *
 * @thread-safety Shared lock during enumeration
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS
    MonXpGetSharedObjects(_Outptr_result_maybenull_ PMON_XP_SHARED_OBJECT *Objects,
                          _Out_ ULONG *Count);

/**
 * @function   MonXpGetProcessTree
 * @purpose    Retrieve process tree snapshot (allocates output)
 * @precondition IRQL == PASSIVE_LEVEL
 *
 * @param[out] Entries - Receives allocated array (caller frees with MON_XP_TAG)
 * @param[out] Count - Number of entries returned
 * @returns    STATUS_SUCCESS on success
 *             STATUS_INSUFFICIENT_RESOURCES on allocation failure
 *
 * @thread-safety Shared lock during snapshot
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS
    MonXpGetProcessTree(_Outptr_result_maybenull_ PMON_XP_PROCESS_ENTRY *Entries,
                        _Out_ ULONG *Count);

/**
 * @function   MonXpGetAlerts
 * @purpose    Retrieve pending cross-process alerts (allocates output)
 * @precondition IRQL == PASSIVE_LEVEL
 *
 * @param[out] Alerts - Receives allocated array (caller frees with MON_XP_TAG)
 * @param[out] Count - Number of alerts returned
 * @returns    STATUS_SUCCESS on success
 *             STATUS_INSUFFICIENT_RESOURCES on allocation failure
 *
 * @thread-safety Uses ring buffer for alerts
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS
    MonXpGetAlerts(_Outptr_result_maybenull_ PMON_XP_ALERT_EVENT *Alerts, _Out_ ULONG *Count);

/**
 * @function   MonXpScanSections
 * @purpose    Enumerate section objects for a process (allocates output)
 * @precondition IRQL == PASSIVE_LEVEL
 *
 * @param[in]  ProcessId - Target process (use NULL for all)
 * @param[out] Sections - Receives allocated array (caller frees with
 * MON_XP_TAG)
 * @param[out] Count - Number of sections returned
 * @returns    STATUS_SUCCESS on success
 *             STATUS_NOT_FOUND if process not found
 *
 * @thread-safety Process attachment for enumeration
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS
    MonXpScanSections(_In_opt_ HANDLE ProcessId,
                      _Outptr_result_maybenull_ PMON_XP_SECTION_INFO *Sections, _Out_ ULONG *Count);

/**
 * @function   MonXpConvertProcessEntryToPublic
 * @purpose    Convert internal process entry to public format
 * @precondition IRQL <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL) VOID
    MonXpConvertProcessEntryToPublic(_In_ const MON_XP_PROCESS_ENTRY *Internal, _Out_ PVOID Public);

/**
 * @function   MonXpConvertAlertToPublic
 * @purpose    Convert internal alert to public format
 * @precondition IRQL <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL) VOID
    MonXpConvertAlertToPublic(_In_ const MON_XP_ALERT_EVENT *Internal, _Out_ PVOID Public);

/**
 * @function   MonXpGetStats
 * @purpose    Get cross-process detection statistics
 * @precondition IRQL <= DISPATCH_LEVEL
 *
 * @param[out] Stats - Output statistics buffer
 *
 * @thread-safety Lock-free counter reads
 */
_IRQL_requires_max_(DISPATCH_LEVEL) VOID MonXpGetStats(_Out_ PMON_XP_STATS Stats);

/**
 * @function   MonXpGetConfig
 * @purpose    Get current cross-process configuration
 * @precondition IRQL <= DISPATCH_LEVEL
 *
 * @param[out] Config - Output configuration buffer
 *
 * @thread-safety Lock-free snapshot
 */
_IRQL_requires_max_(DISPATCH_LEVEL) VOID MonXpGetConfig(_Out_ PMON_XP_CONFIG Config);

/**
 * @function   MonXpSetConfig
 * @purpose    Configure cross-process detection behavior
 * @precondition IRQL == PASSIVE_LEVEL
 *
 * @param[in]  Config - New configuration
 * @returns    STATUS_SUCCESS on success
 *             STATUS_INVALID_PARAMETER if config invalid
 *
 * @thread-safety ERESOURCE-synchronized
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS MonXpSetConfig(_In_ const MON_XP_CONFIG *Config);

/**
 * @function   MonXpIsProcessDescendant
 * @purpose    Check if one process is descendant of another
 * @precondition IRQL == PASSIVE_LEVEL
 *
 * @param[in]  AncestorPid - Potential ancestor process ID
 * @param[in]  DescendantPid - Potential descendant process ID
 * @param[in]  MaxDepth - Maximum generations to search
 * @returns    TRUE if descendant relationship exists
 *
 * @thread-safety Shared lock on process tree
 */
_IRQL_requires_(PASSIVE_LEVEL) BOOLEAN
    MonXpIsProcessDescendant(_In_ ULONG AncestorPid, _In_ ULONG DescendantPid, _In_ ULONG MaxDepth);

/**
 * @function   MonXpGetProcessIntegrity
 * @purpose    Query process integrity level
 * @precondition IRQL == PASSIVE_LEVEL
 *
 * @param[in]  ProcessId - Target process
 * @param[out] IntegrityLevel - Output integrity RID
 * @returns    STATUS_SUCCESS if queried successfully
 *             STATUS_NOT_FOUND if process not found
 *
 * @thread-safety May use cached value or query live
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS
    MonXpGetProcessIntegrity(_In_ ULONG ProcessId, _Out_ ULONG *IntegrityLevel);

/**
 * @function   MonXpResetStats
 * @purpose    Reset cross-process detection statistics
 * @precondition IRQL == PASSIVE_LEVEL
 *
 * @thread-safety Interlocked operations
 * @side-effects Clears all counters
 */
_IRQL_requires_(PASSIVE_LEVEL) VOID MonXpResetStats(VOID);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _ZIX_LABS_CROSS_PROCESS_H_ */
