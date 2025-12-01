/*
 * Win11Mon Cross-Process Detection Client API - Public Header
 *
 * Author: Colin MacRitchie | ziX Labs
 * Organization: ziX Labs - Security Research Division
 * File: win11mon_xprocess.h
 * Version: 1.0
 * Date: 2025-11-30
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and confidential.
 *   Redistribution or disclosure without prior written consent is prohibited.
 *
 * Summary
 * -------
 * User-mode client APIs for cross-process communication detection.
 * Provides shared IoRing object enumeration, process tree queries, section
 * scanning, and cross-process alert retrieval. Communicates with
 * win11_monitor.sys via DeviceIoControl.
 *
 * Thread Safety:
 * - All functions are thread-safe
 * - Handle management is caller's responsibility
 */

#ifndef _ZIX_LABS_WIN11MON_XPROCESS_H_
#define _ZIX_LABS_WIN11MON_XPROCESS_H_

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------
 * Cross-Process Detection Constants
 *-------------------------------------------------------------------------*/
#define WIN11MON_XP_MAX_SHARED_OBJECTS  256
#define WIN11MON_XP_MAX_PROCESSES       8
#define WIN11MON_XP_MAX_CACHED_PROCS    4096
#define WIN11MON_XP_MAX_SECTIONS        128
#define WIN11MON_XP_MAX_ALERTS          64

/*--------------------------------------------------------------------------
 * Alert Type Enumeration
 *-------------------------------------------------------------------------*/
typedef enum _WIN11MON_XP_ALERT_TYPE {
    Win11MonXpAlert_None = 0,
    Win11MonXpAlert_SharedIoRing = 1,
    Win11MonXpAlert_UnrelatedSharing = 2,
    Win11MonXpAlert_CrossIntegrityShare = 3,
    Win11MonXpAlert_SystemIoRingAccess = 4,
    Win11MonXpAlert_HandleDuplication = 5,
    Win11MonXpAlert_SectionSharing = 6,
    Win11MonXpAlert_InheritanceAnomaly = 7,
    Win11MonXpAlert_Max = 8
} WIN11MON_XP_ALERT_TYPE;

/*--------------------------------------------------------------------------
 * Severity Enumeration
 *-------------------------------------------------------------------------*/
typedef enum _WIN11MON_XP_SEVERITY {
    Win11MonXpSeverity_Info = 0,
    Win11MonXpSeverity_Low = 1,
    Win11MonXpSeverity_Medium = 2,
    Win11MonXpSeverity_High = 3,
    Win11MonXpSeverity_Critical = 4
} WIN11MON_XP_SEVERITY;

/*--------------------------------------------------------------------------
 * Rule ID Enumeration
 *-------------------------------------------------------------------------*/
typedef enum _WIN11MON_XP_RULE_ID {
    Win11MonXpRule_None = 0,
    Win11MonXpRule_UnrelatedIoRingSharing = 100,
    Win11MonXpRule_SystemIoRingFromUser = 101,
    Win11MonXpRule_CrossIntegrityIoRing = 102,
    Win11MonXpRule_SectionIoRingBuffer = 103,
    Win11MonXpRule_UnexpectedInheritance = 104,
    Win11MonXpRule_RapidDuplication = 105,
    Win11MonXpRule_Max = 106
} WIN11MON_XP_RULE_ID;

/*--------------------------------------------------------------------------
 * Shared Object Flags
 *-------------------------------------------------------------------------*/
#define WIN11MON_XP_FLAG_CROSS_INTEGRITY    0x0001
#define WIN11MON_XP_FLAG_CROSS_SESSION      0x0002
#define WIN11MON_XP_FLAG_SYSTEM_INVOLVED    0x0004
#define WIN11MON_XP_FLAG_SERVICE_INVOLVED   0x0008
#define WIN11MON_XP_FLAG_UNRELATED          0x0010
#define WIN11MON_XP_FLAG_SUSPICIOUS         0x0020
#define WIN11MON_XP_FLAG_INHERITED          0x0040
#define WIN11MON_XP_FLAG_WHITELISTED        0x0080

/*--------------------------------------------------------------------------
 * Process Flags
 *-------------------------------------------------------------------------*/
#define WIN11MON_XP_PROC_FLAG_ELEVATED      0x0001
#define WIN11MON_XP_PROC_FLAG_SERVICE       0x0002
#define WIN11MON_XP_PROC_FLAG_SYSTEM        0x0004
#define WIN11MON_XP_PROC_FLAG_INTERACTIVE   0x0008
#define WIN11MON_XP_PROC_FLAG_TERMINATED    0x0010

/*--------------------------------------------------------------------------
 * Handle Entry (per-process handle info within a shared object)
 *-------------------------------------------------------------------------*/
#pragma pack(push, 8)
typedef struct _WIN11MON_XP_HANDLE_ENTRY {
    DWORD       ProcessId;
    ULONG64     HandleValue;
    DWORD       AccessMask;
    DWORD       IntegrityLevel;
    DWORD       SessionId;
    DWORD       Reserved;
} WIN11MON_XP_HANDLE_ENTRY, *PWIN11MON_XP_HANDLE_ENTRY;
#pragma pack(pop)

/*--------------------------------------------------------------------------
 * Shared Object Record
 *-------------------------------------------------------------------------*/
#pragma pack(push, 8)
typedef struct _WIN11MON_XP_SHARED_OBJECT {
    ULONG64     ObjectAddressMasked;
    DWORD       ObjectTypeIndex;
    DWORD       ProcessCount;
    DWORD       Flags;
    DWORD       RiskScore;
    DWORD       TriggeredRules;
    BOOL        HasParentChildRelation;
    DWORD       CommonAncestorPid;
    ULONG64     FirstDetectedTime;
    ULONG64     LastUpdatedTime;
    BOOL        HasSectionBacking;
    DWORD       Reserved;
    WIN11MON_XP_HANDLE_ENTRY Processes[WIN11MON_XP_MAX_PROCESSES];
} WIN11MON_XP_SHARED_OBJECT, *PWIN11MON_XP_SHARED_OBJECT;
#pragma pack(pop)

/*--------------------------------------------------------------------------
 * Process Entry (for tree cache)
 *-------------------------------------------------------------------------*/
#pragma pack(push, 8)
typedef struct _WIN11MON_XP_PROCESS_ENTRY {
    DWORD       ProcessId;
    DWORD       ParentProcessId;
    DWORD       SessionId;
    DWORD       IntegrityLevel;
    DWORD       Flags;
    DWORD       Reserved;
    ULONG64     CreateTime;
    WCHAR       ImageName[32];
} WIN11MON_XP_PROCESS_ENTRY, *PWIN11MON_XP_PROCESS_ENTRY;
#pragma pack(pop)

/*--------------------------------------------------------------------------
 * Section Information
 *-------------------------------------------------------------------------*/
#pragma pack(push, 8)
typedef struct _WIN11MON_XP_SECTION_INFO {
    ULONG64     SectionAddressMasked;
    WCHAR       SectionName[64];
    BOOL        IsNamed;
    DWORD       MappingCount;
    ULONG64     MaximumSize;
    DWORD       AllocationAttributes;
    BOOL        RelatedToIoRing;
    DWORD       RelatedIoRingPid;
    DWORD       Reserved;
} WIN11MON_XP_SECTION_INFO, *PWIN11MON_XP_SECTION_INFO;
#pragma pack(pop)

/*--------------------------------------------------------------------------
 * Alert Event
 *-------------------------------------------------------------------------*/
#pragma pack(push, 8)
typedef struct _WIN11MON_XP_ALERT_EVENT {
    DWORD       Size;
    WIN11MON_XP_ALERT_TYPE AlertType;
    WIN11MON_XP_SEVERITY Severity;
    DWORD       RuleId;
    ULONG64     Timestamp;
    ULONG64     ObjectAddressMasked;
    DWORD       ObjectTypeIndex;
    DWORD       SourceProcessId;
    DWORD       TargetProcessId;
    WCHAR       SourceProcessName[32];
    WCHAR       TargetProcessName[32];
    ULONG64     SourceHandle;
    ULONG64     TargetHandle;
    DWORD       SourceAccess;
    DWORD       TargetAccess;
    BOOL        IsParentChild;
    DWORD       SourceIntegrity;
    DWORD       TargetIntegrity;
    DWORD       RiskScore;
    CHAR        MitreTechnique[16];
    CHAR        Description[64];
} WIN11MON_XP_ALERT_EVENT, *PWIN11MON_XP_ALERT_EVENT;
#pragma pack(pop)

/*--------------------------------------------------------------------------
 * Statistics
 *-------------------------------------------------------------------------*/
#pragma pack(push, 8)
typedef struct _WIN11MON_XP_STATS {
    DWORD       Size;
    DWORD       Reserved;
    DWORD       TotalScansPerformed;
    DWORD       SharedObjectsDetected;
    DWORD       UnrelatedSharingCount;
    DWORD       CrossIntegritySharingCount;
    DWORD       SystemAccessCount;
    DWORD       HandleDuplicationCount;
    DWORD       SectionSharingCount;
    DWORD       InheritanceAnomalyCount;
    DWORD       TotalAlertsGenerated;
    DWORD       ProcessesTracked;
    DWORD       AverageScanTimeUs;
    DWORD       Reserved2;
} WIN11MON_XP_STATS, *PWIN11MON_XP_STATS;
#pragma pack(pop)

/*--------------------------------------------------------------------------
 * Configuration
 *-------------------------------------------------------------------------*/
#pragma pack(push, 8)
typedef struct _WIN11MON_XP_CONFIG {
    DWORD       Size;
    DWORD       Reserved;
    BOOL        Enabled;
    DWORD       ScanIntervalMs;
    DWORD       AlertThreshold;
    DWORD       CriticalThreshold;
    BOOL        WhitelistEnabled;
    DWORD       MaxAlertsPerMinute;
    DWORD       ProcessTreeRefreshMs;
} WIN11MON_XP_CONFIG, *PWIN11MON_XP_CONFIG;
#pragma pack(pop)

/*==========================================================================
 * Shared Object APIs
 *=========================================================================*/

/**
 * @function   Win11MonXpGetSharedObjects
 * @purpose    Get list of shared IoRing objects
 * @precondition hDevice must be valid driver handle
 *
 * @param[in]  hDevice - Driver device handle
 * @param[out] pBuffer - Buffer for count + object array
 * @param[in]  BufferSize - Buffer size in bytes
 * @param[out] pBytesWritten - Actual bytes written
 * @returns    ERROR_SUCCESS on success
 *             ERROR_MORE_DATA if buffer too small
 *
 * @thread-safety Thread-safe
 */
DWORD
WINAPI
Win11MonXpGetSharedObjects(
    _In_ HANDLE hDevice,
    _Out_writes_bytes_to_(BufferSize, *pBytesWritten) PVOID pBuffer,
    _In_ DWORD BufferSize,
    _Out_ DWORD* pBytesWritten
);

/*==========================================================================
 * Process Tree APIs
 *=========================================================================*/

/**
 * @function   Win11MonXpGetProcessTree
 * @purpose    Get process relationship tree snapshot
 * @precondition hDevice must be valid driver handle
 *
 * @param[in]  hDevice - Driver device handle
 * @param[out] pBuffer - Buffer for count + entry array
 * @param[in]  BufferSize - Buffer size in bytes
 * @param[out] pBytesWritten - Actual bytes written
 * @returns    ERROR_SUCCESS on success
 *             ERROR_MORE_DATA if buffer too small
 *
 * @thread-safety Thread-safe
 */
DWORD
WINAPI
Win11MonXpGetProcessTree(
    _In_ HANDLE hDevice,
    _Out_writes_bytes_to_(BufferSize, *pBytesWritten) PVOID pBuffer,
    _In_ DWORD BufferSize,
    _Out_ DWORD* pBytesWritten
);

/*==========================================================================
 * Section Scanning APIs
 *=========================================================================*/

/**
 * @function   Win11MonXpScanSections
 * @purpose    Enumerate section objects for a process
 * @precondition hDevice must be valid driver handle
 *
 * @param[in]  hDevice - Driver device handle
 * @param[in]  ProcessId - Target process ID (0 = all)
 * @param[out] pBuffer - Buffer for count + section array
 * @param[in]  BufferSize - Buffer size in bytes
 * @param[out] pBytesWritten - Actual bytes written
 * @returns    ERROR_SUCCESS on success
 *             ERROR_NOT_FOUND if process doesn't exist
 *             ERROR_MORE_DATA if buffer too small
 *
 * @thread-safety Thread-safe
 */
DWORD
WINAPI
Win11MonXpScanSections(
    _In_ HANDLE hDevice,
    _In_ DWORD ProcessId,
    _Out_writes_bytes_to_(BufferSize, *pBytesWritten) PVOID pBuffer,
    _In_ DWORD BufferSize,
    _Out_ DWORD* pBytesWritten
);

/*==========================================================================
 * Alert APIs
 *=========================================================================*/

/**
 * @function   Win11MonXpGetAlerts
 * @purpose    Get pending cross-process alerts
 * @precondition hDevice must be valid driver handle
 *
 * @param[in]  hDevice - Driver device handle
 * @param[out] pBuffer - Buffer for count + alert array
 * @param[in]  BufferSize - Buffer size in bytes
 * @param[out] pBytesWritten - Actual bytes written
 * @returns    ERROR_SUCCESS on success
 *             ERROR_MORE_DATA if buffer too small
 *
 * @thread-safety Thread-safe
 */
DWORD
WINAPI
Win11MonXpGetAlerts(
    _In_ HANDLE hDevice,
    _Out_writes_bytes_to_(BufferSize, *pBytesWritten) PVOID pBuffer,
    _In_ DWORD BufferSize,
    _Out_ DWORD* pBytesWritten
);

/*==========================================================================
 * Statistics & Configuration APIs
 *=========================================================================*/

/**
 * @function   Win11MonXpGetStats
 * @purpose    Get cross-process detection statistics
 * @precondition hDevice must be valid driver handle
 *
 * @param[in]  hDevice - Driver device handle
 * @param[out] pStats - Output statistics
 * @returns    ERROR_SUCCESS on success
 *
 * @thread-safety Thread-safe
 */
DWORD
WINAPI
Win11MonXpGetStats(
    _In_ HANDLE hDevice,
    _Out_ PWIN11MON_XP_STATS pStats
);

/**
 * @function   Win11MonXpGetConfig
 * @purpose    Get cross-process detection configuration
 * @precondition hDevice must be valid driver handle
 *
 * @param[in]  hDevice - Driver device handle
 * @param[out] pConfig - Output configuration
 * @returns    ERROR_SUCCESS on success
 *
 * @thread-safety Thread-safe
 */
DWORD
WINAPI
Win11MonXpGetConfig(
    _In_ HANDLE hDevice,
    _Out_ PWIN11MON_XP_CONFIG pConfig
);

/**
 * @function   Win11MonXpSetConfig
 * @purpose    Set cross-process detection configuration
 * @precondition hDevice must be valid driver handle
 *
 * @param[in]  hDevice - Driver device handle
 * @param[in]  pConfig - New configuration
 * @returns    ERROR_SUCCESS on success
 *             ERROR_INVALID_PARAMETER if config invalid
 *
 * @thread-safety Thread-safe
 */
DWORD
WINAPI
Win11MonXpSetConfig(
    _In_ HANDLE hDevice,
    _In_ const WIN11MON_XP_CONFIG* pConfig
);

/**
 * @function   Win11MonXpScanNow
 * @purpose    Trigger immediate cross-process scan
 * @precondition hDevice must be valid driver handle
 *
 * @param[in]  hDevice - Driver device handle
 * @returns    ERROR_SUCCESS on success
 *
 * @thread-safety Thread-safe
 */
DWORD
WINAPI
Win11MonXpScanNow(
    _In_ HANDLE hDevice
);

/*==========================================================================
 * Helper Functions
 *=========================================================================*/

/**
 * @function   Win11MonXpAlertTypeToString
 * @purpose    Get human-readable string for alert type
 *
 * @param[in]  AlertType - Alert type
 * @returns    Static string describing alert type
 */
const WCHAR*
WINAPI
Win11MonXpAlertTypeToString(
    _In_ WIN11MON_XP_ALERT_TYPE AlertType
);

/**
 * @function   Win11MonXpSeverityToString
 * @purpose    Get human-readable string for severity level
 *
 * @param[in]  Severity - Severity level
 * @returns    Static string describing severity
 */
const WCHAR*
WINAPI
Win11MonXpSeverityToString(
    _In_ WIN11MON_XP_SEVERITY Severity
);

/**
 * @function   Win11MonXpRuleIdToString
 * @purpose    Get human-readable string for rule ID
 *
 * @param[in]  RuleId - Rule ID
 * @returns    Static string describing rule
 */
const WCHAR*
WINAPI
Win11MonXpRuleIdToString(
    _In_ WIN11MON_XP_RULE_ID RuleId
);

/**
 * @function   Win11MonXpIntegrityToString
 * @purpose    Get human-readable string for integrity level
 *
 * @param[in]  IntegrityLevel - Integrity level RID
 * @returns    Static string describing integrity level
 */
const WCHAR*
WINAPI
Win11MonXpIntegrityToString(
    _In_ DWORD IntegrityLevel
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _ZIX_LABS_WIN11MON_XPROCESS_H_ */
