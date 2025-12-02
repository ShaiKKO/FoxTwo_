/*
 * Win11Mon Profile Client API - Implementation
 *
 * Author: Colin MacRitchie | ziX Labs
 * Organization: ziX Labs - Security Research Division
 * File: win11mon_profile.c
 * Version: 1.0
 * Date: 2025-11-30
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and
 * confidential. Redistribution or disclosure without prior written consent is
 * prohibited.
 *
 * Summary
 * -------
 * User-mode client implementation for process profiling and anomaly APIs.
 * Communicates with win11_monitor.sys via DeviceIoControl.
 */

#include "win11mon_profile.h"

#include <windows.h>

#pragma warning(push)
#pragma warning(disable : 4201) /* nameless struct/union */

/*--------------------------------------------------------------------------
 * IOCTL Definitions (must match kernel definitions)
 *-------------------------------------------------------------------------*/
#define WIN11MON_IOCTL_BASE 0x800
#define FILE_DEVICE_WIN11MON FILE_DEVICE_UNKNOWN

/* Profile IOCTLs (0x30-0x3F range) */
#define IOCTL_MONITOR_PROFILE_GET                                             \
  CTL_CODE(FILE_DEVICE_WIN11MON, WIN11MON_IOCTL_BASE + 0x30, METHOD_BUFFERED, \
           FILE_READ_ACCESS)

#define IOCTL_MONITOR_PROFILE_LIST                                            \
  CTL_CODE(FILE_DEVICE_WIN11MON, WIN11MON_IOCTL_BASE + 0x31, METHOD_BUFFERED, \
           FILE_READ_ACCESS)

#define IOCTL_MONITOR_PROFILE_EXPORT_ML                                       \
  CTL_CODE(FILE_DEVICE_WIN11MON, WIN11MON_IOCTL_BASE + 0x32, METHOD_BUFFERED, \
           FILE_READ_ACCESS)

#define IOCTL_MONITOR_PROFILE_GET_STATS                                       \
  CTL_CODE(FILE_DEVICE_WIN11MON, WIN11MON_IOCTL_BASE + 0x33, METHOD_BUFFERED, \
           FILE_READ_ACCESS)

#define IOCTL_MONITOR_PROFILE_GET_CONFIG                                      \
  CTL_CODE(FILE_DEVICE_WIN11MON, WIN11MON_IOCTL_BASE + 0x34, METHOD_BUFFERED, \
           FILE_READ_ACCESS)

#define IOCTL_MONITOR_PROFILE_SET_CONFIG                                      \
  CTL_CODE(FILE_DEVICE_WIN11MON, WIN11MON_IOCTL_BASE + 0x35, METHOD_BUFFERED, \
           FILE_WRITE_ACCESS)

#define IOCTL_MONITOR_PROFILE_RESET                                           \
  CTL_CODE(FILE_DEVICE_WIN11MON, WIN11MON_IOCTL_BASE + 0x36, METHOD_BUFFERED, \
           FILE_WRITE_ACCESS)

/* Anomaly IOCTLs (0x38-0x3F range) */
#define IOCTL_MONITOR_ANOMALY_GET_RULES                                       \
  CTL_CODE(FILE_DEVICE_WIN11MON, WIN11MON_IOCTL_BASE + 0x38, METHOD_BUFFERED, \
           FILE_READ_ACCESS)

#define IOCTL_MONITOR_ANOMALY_SET_THRESHOLD                                   \
  CTL_CODE(FILE_DEVICE_WIN11MON, WIN11MON_IOCTL_BASE + 0x39, METHOD_BUFFERED, \
           FILE_WRITE_ACCESS)

#define IOCTL_MONITOR_ANOMALY_ENABLE_RULE                                     \
  CTL_CODE(FILE_DEVICE_WIN11MON, WIN11MON_IOCTL_BASE + 0x3A, METHOD_BUFFERED, \
           FILE_WRITE_ACCESS)

#define IOCTL_MONITOR_ANOMALY_GET_STATS                                       \
  CTL_CODE(FILE_DEVICE_WIN11MON, WIN11MON_IOCTL_BASE + 0x3B, METHOD_BUFFERED, \
           FILE_READ_ACCESS)

#define IOCTL_MONITOR_ANOMALY_RESET_STATS                                     \
  CTL_CODE(FILE_DEVICE_WIN11MON, WIN11MON_IOCTL_BASE + 0x3C, METHOD_BUFFERED, \
           FILE_WRITE_ACCESS)

/*--------------------------------------------------------------------------
 * IOCTL Input Structures
 *-------------------------------------------------------------------------*/
typedef struct _PROFILE_GET_INPUT {
  ULONG ProcessId;
} PROFILE_GET_INPUT;

typedef struct _ANOMALY_THRESHOLD_INPUT {
  ULONG RuleId;
  ULONG Threshold;
} ANOMALY_THRESHOLD_INPUT;

typedef struct _ANOMALY_ENABLE_INPUT {
  ULONG RuleId;
  BOOL Enable;
} ANOMALY_ENABLE_INPUT;

/*--------------------------------------------------------------------------
 * Internal Helper
 *-------------------------------------------------------------------------*/
static DWORD ProfileIoctl(_In_ HANDLE hDevice, _In_ DWORD IoCtlCode,
                          _In_opt_ LPVOID pInput, _In_ DWORD InputSize,
                          _Out_opt_ LPVOID pOutput, _In_ DWORD OutputSize,
                          _Out_opt_ DWORD* pBytesReturned) {
  DWORD bytesReturned = 0;
  BOOL success;

  if (hDevice == NULL || hDevice == INVALID_HANDLE_VALUE) {
    return ERROR_INVALID_HANDLE;
  }

  success = DeviceIoControl(hDevice, IoCtlCode, pInput, InputSize, pOutput,
                            OutputSize, &bytesReturned, NULL);

  if (pBytesReturned != NULL) {
    *pBytesReturned = bytesReturned;
  }

  if (!success) {
    return GetLastError();
  }

  return ERROR_SUCCESS;
}

/*==========================================================================
 * Profile Query APIs
 *=========================================================================*/

_Use_decl_annotations_ DWORD WINAPI Win11MonProfileGet(
    HANDLE hDevice, DWORD ProcessId, PWIN11MON_PROFILE_SUMMARY pSummary) {
  PROFILE_GET_INPUT input;
  DWORD bytesReturned;
  DWORD err;

  if (pSummary == NULL) {
    return ERROR_INVALID_PARAMETER;
  }

  ZeroMemory(pSummary, sizeof(*pSummary));
  input.ProcessId = ProcessId;

  err = ProfileIoctl(hDevice, IOCTL_MONITOR_PROFILE_GET, &input, sizeof(input),
                     pSummary, sizeof(*pSummary), &bytesReturned);

  if (err == ERROR_SUCCESS && bytesReturned < sizeof(*pSummary)) {
    return ERROR_INSUFFICIENT_BUFFER;
  }

  return err;
}

_Use_decl_annotations_ DWORD WINAPI
Win11MonProfileList(HANDLE hDevice, PWIN11MON_PROFILE_SUMMARY pBuffer,
                    DWORD MaxCount, DWORD* pActualCount) {
  DWORD bytesReturned;
  DWORD err;

  if (pBuffer == NULL || pActualCount == NULL || MaxCount == 0) {
    return ERROR_INVALID_PARAMETER;
  }

  *pActualCount = 0;

  err = ProfileIoctl(
      hDevice, IOCTL_MONITOR_PROFILE_LIST, &MaxCount, sizeof(MaxCount), pBuffer,
      MaxCount * sizeof(WIN11MON_PROFILE_SUMMARY), &bytesReturned);

  if (err == ERROR_SUCCESS) {
    *pActualCount = bytesReturned / sizeof(WIN11MON_PROFILE_SUMMARY);
  }

  return err;
}

_Use_decl_annotations_ DWORD WINAPI Win11MonProfileExportML(
    HANDLE hDevice, DWORD ProcessId, PWIN11MON_ML_FEATURE_VECTOR pFeatures) {
  PROFILE_GET_INPUT input;
  DWORD bytesReturned;
  DWORD err;

  if (pFeatures == NULL) {
    return ERROR_INVALID_PARAMETER;
  }

  ZeroMemory(pFeatures, sizeof(*pFeatures));
  input.ProcessId = ProcessId;

  err = ProfileIoctl(hDevice, IOCTL_MONITOR_PROFILE_EXPORT_ML, &input,
                     sizeof(input), pFeatures, sizeof(*pFeatures),
                     &bytesReturned);

  if (err == ERROR_SUCCESS && bytesReturned < sizeof(*pFeatures)) {
    return ERROR_INSUFFICIENT_BUFFER;
  }

  return err;
}

_Use_decl_annotations_ DWORD WINAPI
Win11MonProfileGetStats(HANDLE hDevice, PWIN11MON_PROFILE_STATS pStats) {
  DWORD bytesReturned;

  if (pStats == NULL) {
    return ERROR_INVALID_PARAMETER;
  }

  ZeroMemory(pStats, sizeof(*pStats));

  return ProfileIoctl(hDevice, IOCTL_MONITOR_PROFILE_GET_STATS, NULL, 0, pStats,
                      sizeof(*pStats), &bytesReturned);
}

/*==========================================================================
 * Profile Configuration APIs
 *=========================================================================*/

_Use_decl_annotations_ DWORD WINAPI
Win11MonProfileGetConfig(HANDLE hDevice, PWIN11MON_PROFILE_CONFIG pConfig) {
  DWORD bytesReturned;

  if (pConfig == NULL) {
    return ERROR_INVALID_PARAMETER;
  }

  ZeroMemory(pConfig, sizeof(*pConfig));

  return ProfileIoctl(hDevice, IOCTL_MONITOR_PROFILE_GET_CONFIG, NULL, 0,
                      pConfig, sizeof(*pConfig), &bytesReturned);
}

_Use_decl_annotations_ DWORD WINAPI Win11MonProfileSetConfig(
    HANDLE hDevice, const WIN11MON_PROFILE_CONFIG* pConfig) {
  if (pConfig == NULL) {
    return ERROR_INVALID_PARAMETER;
  }

  return ProfileIoctl(hDevice, IOCTL_MONITOR_PROFILE_SET_CONFIG,
                      (LPVOID)pConfig, sizeof(*pConfig), NULL, 0, NULL);
}

_Use_decl_annotations_ DWORD WINAPI Win11MonProfileReset(HANDLE hDevice) {
  return ProfileIoctl(hDevice, IOCTL_MONITOR_PROFILE_RESET, NULL, 0, NULL, 0,
                      NULL);
}

/*==========================================================================
 * Anomaly Rule APIs
 *=========================================================================*/

_Use_decl_annotations_ DWORD WINAPI
Win11MonAnomalyGetRules(HANDLE hDevice, PWIN11MON_ANOMALY_RULE pBuffer,
                        DWORD MaxCount, DWORD* pActualCount) {
  DWORD bytesReturned;
  DWORD err;

  if (pBuffer == NULL || pActualCount == NULL || MaxCount == 0) {
    return ERROR_INVALID_PARAMETER;
  }

  *pActualCount = 0;

  err = ProfileIoctl(hDevice, IOCTL_MONITOR_ANOMALY_GET_RULES, &MaxCount,
                     sizeof(MaxCount), pBuffer,
                     MaxCount * sizeof(WIN11MON_ANOMALY_RULE), &bytesReturned);

  if (err == ERROR_SUCCESS) {
    *pActualCount = bytesReturned / sizeof(WIN11MON_ANOMALY_RULE);
  }

  return err;
}

_Use_decl_annotations_ DWORD WINAPI Win11MonAnomalySetThreshold(
    HANDLE hDevice, WIN11MON_ANOMALY_RULE_ID RuleId, DWORD Threshold) {
  ANOMALY_THRESHOLD_INPUT input;

  input.RuleId = (ULONG)RuleId;
  input.Threshold = Threshold;

  return ProfileIoctl(hDevice, IOCTL_MONITOR_ANOMALY_SET_THRESHOLD, &input,
                      sizeof(input), NULL, 0, NULL);
}

_Use_decl_annotations_ DWORD WINAPI Win11MonAnomalyEnableRule(
    HANDLE hDevice, WIN11MON_ANOMALY_RULE_ID RuleId, BOOL Enable) {
  ANOMALY_ENABLE_INPUT input;

  input.RuleId = (ULONG)RuleId;
  input.Enable = Enable;

  return ProfileIoctl(hDevice, IOCTL_MONITOR_ANOMALY_ENABLE_RULE, &input,
                      sizeof(input), NULL, 0, NULL);
}

_Use_decl_annotations_ DWORD WINAPI
Win11MonAnomalyGetStats(HANDLE hDevice, PWIN11MON_ANOMALY_STATS pStats) {
  DWORD bytesReturned;

  if (pStats == NULL) {
    return ERROR_INVALID_PARAMETER;
  }

  ZeroMemory(pStats, sizeof(*pStats));

  return ProfileIoctl(hDevice, IOCTL_MONITOR_ANOMALY_GET_STATS, NULL, 0, pStats,
                      sizeof(*pStats), &bytesReturned);
}

_Use_decl_annotations_ DWORD WINAPI Win11MonAnomalyResetStats(HANDLE hDevice) {
  return ProfileIoctl(hDevice, IOCTL_MONITOR_ANOMALY_RESET_STATS, NULL, 0, NULL,
                      0, NULL);
}

#pragma warning(pop)
