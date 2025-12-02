/*
 * Win11Mon Profile Client API - Public Header
 *
 * Author: Colin MacRitchie | ziX Labs
 * Organization: ziX Labs - Security Research Division
 * File: win11mon_profile.h
 * Version: 1.0
 * Date: 2025-11-30
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and
 * confidential. Redistribution or disclosure without prior written consent is
 * prohibited.
 *
 * Summary
 * -------
 * User-mode client APIs for process behavior profiling and anomaly detection.
 * Communicates with win11_monitor.sys via DeviceIoControl.
 *
 * Thread Safety:
 * - All functions are thread-safe
 * - Handle management is caller's responsibility
 */

#ifndef _ZIX_LABS_WIN11MON_PROFILE_H_
#define _ZIX_LABS_WIN11MON_PROFILE_H_

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------
 * Profile Constants (mirror kernel definitions)
 *-------------------------------------------------------------------------*/
#define WIN11MON_PROFILE_MAX_NAME 64
#define WIN11MON_PROFILE_ML_VERSION 1

/*--------------------------------------------------------------------------
 * Profile Flags
 *-------------------------------------------------------------------------*/
#define WIN11MON_PROFILE_FLAG_ELEVATED 0x0001
#define WIN11MON_PROFILE_FLAG_SERVICE 0x0002
#define WIN11MON_PROFILE_FLAG_NON_INTERACTIVE 0x0004
#define WIN11MON_PROFILE_FLAG_SYSTEM 0x0008
#define WIN11MON_PROFILE_FLAG_BLACKLISTED 0x0010
#define WIN11MON_PROFILE_FLAG_WHITELISTED 0x0020
#define WIN11MON_PROFILE_FLAG_EXPORTED 0x0040

/*--------------------------------------------------------------------------
 * Anomaly Rule IDs (mirror kernel definitions)
 *-------------------------------------------------------------------------*/
typedef enum _WIN11MON_ANOMALY_RULE_ID {
  Win11MonAnomalyRule_None = 0,
  Win11MonAnomalyRule_HighOpsFrequency = 1,
  Win11MonAnomalyRule_LargeBufferRegistration = 2,
  Win11MonAnomalyRule_RapidHandleCreation = 3,
  Win11MonAnomalyRule_ElevatedIoRingAbuse = 4,
  Win11MonAnomalyRule_BurstPattern = 5,
  Win11MonAnomalyRule_ConcurrentTargets = 6,
  Win11MonAnomalyRule_ViolationAccumulation = 7,
  Win11MonAnomalyRule_Max = 8
} WIN11MON_ANOMALY_RULE_ID;

/*--------------------------------------------------------------------------
 * Anomaly Severity Levels
 *-------------------------------------------------------------------------*/
typedef enum _WIN11MON_ANOMALY_SEVERITY {
  Win11MonSeverity_Info = 0,
  Win11MonSeverity_Low = 1,
  Win11MonSeverity_Medium = 2,
  Win11MonSeverity_High = 3,
  Win11MonSeverity_Critical = 4
} WIN11MON_ANOMALY_SEVERITY;

/*--------------------------------------------------------------------------
 * Profile Summary (for enumeration)
 *-------------------------------------------------------------------------*/
#pragma pack(push, 8)
typedef struct _WIN11MON_PROFILE_SUMMARY {
  ULONG Size;
  ULONG ProcessId;
  WCHAR ProcessName[WIN11MON_PROFILE_MAX_NAME];

  /* Key metrics */
  ULONG ActiveHandles;
  ULONG64 TotalOperations;
  ULONG OpsPerSecond;
  ULONG64 TotalMemoryBytes;

  /* Anomaly info */
  ULONG AnomalyScore; /* 0-100 */
  ULONG AnomalyEventCount;
  ULONG ViolationCount;
  ULONG TriggeredRules; /* Bitmask */

  /* Timestamps */
  ULONG64 FirstSeenTime;
  ULONG64 LastActivityTime;
  ULONG ActiveDurationSec;

  /* Flags */
  ULONG Flags;

} WIN11MON_PROFILE_SUMMARY, *PWIN11MON_PROFILE_SUMMARY;
#pragma pack(pop)

/*--------------------------------------------------------------------------
 * ML Feature Vector (for export)
 *-------------------------------------------------------------------------*/
#pragma pack(push, 8)
typedef struct _WIN11MON_ML_FEATURE_VECTOR {
  ULONG Size;
  ULONG Version;
  ULONG ProcessId;
  ULONG Reserved1;
  ULONG64 Timestamp;

  /* Normalized features */
  float OpsPerSecond;
  float SubmitsPerMinute;
  float HandleCount;
  float AvgBufferSizeKB;
  float MaxBufferSizeMB;
  float TotalMemoryMB;
  float ReadWriteRatio;
  float RegisteredFiles;
  float ActiveDurationMin;
  float BurstFrequency;
  float ViolationRate;
  float ProcessAgeMin;

  /* Categorical features */
  ULONG ProcessElevation;
  ULONG ProcessInteractive;
  ULONG ProcessIsService;
  ULONG AnomalyScore;

  /* Label */
  ULONG Label;
  ULONG Reserved2;

} WIN11MON_ML_FEATURE_VECTOR, *PWIN11MON_ML_FEATURE_VECTOR;
#pragma pack(pop)

/*--------------------------------------------------------------------------
 * Anomaly Rule Definition
 *-------------------------------------------------------------------------*/
#pragma pack(push, 8)
typedef struct _WIN11MON_ANOMALY_RULE {
  WIN11MON_ANOMALY_RULE_ID RuleId;
  WCHAR RuleName[32];
  ULONG Threshold;
  ULONG WindowSeconds;
  WIN11MON_ANOMALY_SEVERITY Severity;
  ULONG ScoreImpact;
  BOOL Enabled;
  BYTE Reserved[3];
  CHAR MitreTechnique[16];
} WIN11MON_ANOMALY_RULE, *PWIN11MON_ANOMALY_RULE;
#pragma pack(pop)

/*--------------------------------------------------------------------------
 * Profile Configuration
 *-------------------------------------------------------------------------*/
#pragma pack(push, 8)
typedef struct _WIN11MON_PROFILE_CONFIG {
  ULONG Size;
  BOOL Enabled;
  BOOL AutoExport;
  BOOL AutoBlacklist;
  BYTE Reserved1;
  ULONG AnomalyThreshold;   /* Score threshold for events (0-100) */
  ULONG BlacklistThreshold; /* Score for auto-blacklist (0-100) */
  ULONG HistoryWindowSec;
  ULONG Reserved2;
} WIN11MON_PROFILE_CONFIG, *PWIN11MON_PROFILE_CONFIG;
#pragma pack(pop)

/*--------------------------------------------------------------------------
 * Profile Statistics
 *-------------------------------------------------------------------------*/
#pragma pack(push, 8)
typedef struct _WIN11MON_PROFILE_STATS {
  ULONG Size;
  ULONG Reserved;
  ULONG ActiveProfiles;
  ULONG TotalProfilesCreated;
  ULONG TotalProfilesDestroyed;
  ULONG TotalAnomaliesDetected;
  ULONG64 TotalUpdates;
  ULONG64 TotalExports;
} WIN11MON_PROFILE_STATS, *PWIN11MON_PROFILE_STATS;
#pragma pack(pop)

/*--------------------------------------------------------------------------
 * Anomaly Statistics
 *-------------------------------------------------------------------------*/
#pragma pack(push, 8)
typedef struct _WIN11MON_ANOMALY_STATS {
  ULONG Size;
  ULONG TotalRules;
  ULONG EnabledRules;
  ULONG TotalEvaluations;
  ULONG TotalMatches;
  ULONG Reserved;
} WIN11MON_ANOMALY_STATS, *PWIN11MON_ANOMALY_STATS;
#pragma pack(pop)

/*==========================================================================
 * Profile Query APIs
 *=========================================================================*/

/**
 * @function   Win11MonProfileGet
 * @purpose    Get profile summary for a specific process
 * @precondition hDevice must be valid driver handle
 *
 * @param[in]  hDevice - Driver device handle
 * @param[in]  ProcessId - Target process ID
 * @param[out] pSummary - Output profile summary
 * @returns    ERROR_SUCCESS on success
 *             ERROR_NOT_FOUND if no profile exists
 *             ERROR_INVALID_HANDLE if hDevice invalid
 *
 * @thread-safety Thread-safe
 */
DWORD
WINAPI
Win11MonProfileGet(_In_ HANDLE hDevice, _In_ DWORD ProcessId,
                   _Out_ PWIN11MON_PROFILE_SUMMARY pSummary);

/**
 * @function   Win11MonProfileList
 * @purpose    Enumerate all active profiles
 * @precondition hDevice must be valid driver handle
 *
 * @param[in]  hDevice - Driver device handle
 * @param[out] pBuffer - Array of profile summaries
 * @param[in]  MaxCount - Buffer capacity
 * @param[out] pActualCount - Number of profiles returned
 * @returns    ERROR_SUCCESS on success
 *             ERROR_MORE_DATA if buffer too small
 *
 * @thread-safety Thread-safe
 */
DWORD
WINAPI
Win11MonProfileList(_In_ HANDLE hDevice,
                    _Out_writes_to_(MaxCount, *pActualCount)
                        PWIN11MON_PROFILE_SUMMARY pBuffer,
                    _In_ DWORD MaxCount, _Out_ DWORD* pActualCount);

/**
 * @function   Win11MonProfileExportML
 * @purpose    Export ML feature vector for a process
 * @precondition hDevice must be valid driver handle
 *
 * @param[in]  hDevice - Driver device handle
 * @param[in]  ProcessId - Target process ID
 * @param[out] pFeatures - Output feature vector
 * @returns    ERROR_SUCCESS on success
 *             ERROR_NOT_FOUND if no profile exists
 *
 * @thread-safety Thread-safe
 */
DWORD
WINAPI
Win11MonProfileExportML(_In_ HANDLE hDevice, _In_ DWORD ProcessId,
                        _Out_ PWIN11MON_ML_FEATURE_VECTOR pFeatures);

/**
 * @function   Win11MonProfileGetStats
 * @purpose    Get global profile statistics
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
Win11MonProfileGetStats(_In_ HANDLE hDevice,
                        _Out_ PWIN11MON_PROFILE_STATS pStats);

/*==========================================================================
 * Profile Configuration APIs
 *=========================================================================*/

/**
 * @function   Win11MonProfileGetConfig
 * @purpose    Get current profile configuration
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
Win11MonProfileGetConfig(_In_ HANDLE hDevice,
                         _Out_ PWIN11MON_PROFILE_CONFIG pConfig);

/**
 * @function   Win11MonProfileSetConfig
 * @purpose    Set profile configuration
 * @precondition hDevice must be valid driver handle
 *
 * @param[in]  hDevice - Driver device handle
 * @param[in]  pConfig - New configuration
 * @returns    ERROR_SUCCESS on success
 *
 * @thread-safety Thread-safe
 */
DWORD
WINAPI
Win11MonProfileSetConfig(_In_ HANDLE hDevice,
                         _In_ const WIN11MON_PROFILE_CONFIG* pConfig);

/**
 * @function   Win11MonProfileReset
 * @purpose    Reset all profile counters (keeps profiles)
 * @precondition hDevice must be valid driver handle
 *
 * @param[in]  hDevice - Driver device handle
 * @returns    ERROR_SUCCESS on success
 *
 * @thread-safety Thread-safe
 */
DWORD
WINAPI
Win11MonProfileReset(_In_ HANDLE hDevice);

/*==========================================================================
 * Anomaly Rule APIs
 *=========================================================================*/

/**
 * @function   Win11MonAnomalyGetRules
 * @purpose    Enumerate all anomaly rules
 * @precondition hDevice must be valid driver handle
 *
 * @param[in]  hDevice - Driver device handle
 * @param[out] pBuffer - Array of rules
 * @param[in]  MaxCount - Buffer capacity
 * @param[out] pActualCount - Number of rules returned
 * @returns    ERROR_SUCCESS on success
 *
 * @thread-safety Thread-safe
 */
DWORD
WINAPI
Win11MonAnomalyGetRules(_In_ HANDLE hDevice,
                        _Out_writes_to_(MaxCount, *pActualCount)
                            PWIN11MON_ANOMALY_RULE pBuffer,
                        _In_ DWORD MaxCount, _Out_ DWORD* pActualCount);

/**
 * @function   Win11MonAnomalySetThreshold
 * @purpose    Configure threshold for an anomaly rule
 * @precondition hDevice must be valid driver handle
 *
 * @param[in]  hDevice - Driver device handle
 * @param[in]  RuleId - Rule to modify
 * @param[in]  Threshold - New threshold value
 * @returns    ERROR_SUCCESS on success
 *             ERROR_NOT_FOUND if rule doesn't exist
 *
 * @thread-safety Thread-safe
 */
DWORD
WINAPI
Win11MonAnomalySetThreshold(_In_ HANDLE hDevice,
                            _In_ WIN11MON_ANOMALY_RULE_ID RuleId,
                            _In_ DWORD Threshold);

/**
 * @function   Win11MonAnomalyEnableRule
 * @purpose    Enable or disable an anomaly rule
 * @precondition hDevice must be valid driver handle
 *
 * @param[in]  hDevice - Driver device handle
 * @param[in]  RuleId - Rule to modify
 * @param[in]  Enable - TRUE to enable, FALSE to disable
 * @returns    ERROR_SUCCESS on success
 *             ERROR_NOT_FOUND if rule doesn't exist
 *
 * @thread-safety Thread-safe
 */
DWORD
WINAPI
Win11MonAnomalyEnableRule(_In_ HANDLE hDevice,
                          _In_ WIN11MON_ANOMALY_RULE_ID RuleId,
                          _In_ BOOL Enable);

/**
 * @function   Win11MonAnomalyGetStats
 * @purpose    Get anomaly detection statistics
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
Win11MonAnomalyGetStats(_In_ HANDLE hDevice,
                        _Out_ PWIN11MON_ANOMALY_STATS pStats);

/**
 * @function   Win11MonAnomalyResetStats
 * @purpose    Reset anomaly detection statistics
 * @precondition hDevice must be valid driver handle
 *
 * @param[in]  hDevice - Driver device handle
 * @returns    ERROR_SUCCESS on success
 *
 * @thread-safety Thread-safe
 */
DWORD
WINAPI
Win11MonAnomalyResetStats(_In_ HANDLE hDevice);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _ZIX_LABS_WIN11MON_PROFILE_H_ */
