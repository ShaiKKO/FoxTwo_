/*
 * Win11Mon Memory Client API - Implementation
 *
 * Author: Colin MacRitchie | ziX Labs
 * Organization: ziX Labs - Security Research Division
 * File: win11mon_memory.c
 * Version: 1.0
 * Date: 2025-12-01
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and
 * confidential. Redistribution or disclosure without prior written consent is
 * prohibited.
 *
 * Summary
 * -------
 * User-mode client implementation for memory monitoring APIs.
 * Communicates with win11_monitor.sys via DeviceIoControl.
 */

#include "win11mon_memory.h"

#include <windows.h>

#pragma warning(push)
#pragma warning(disable : 4201) /* nameless struct/union */

/*--------------------------------------------------------------------------
 * IOCTL Definitions (must match kernel definitions)
 *-------------------------------------------------------------------------*/
#define WIN11MON_IOCTL_BASE  0x800
#define FILE_DEVICE_WIN11MON FILE_DEVICE_UNKNOWN

/* Memory Monitoring IOCTLs (0x40-0x44 range) */
#define IOCTL_MONITOR_MEM_SCAN_VAD \
  CTL_CODE(FILE_DEVICE_WIN11MON, WIN11MON_IOCTL_BASE + 0x40, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_MONITOR_MEM_GET_MDLS \
  CTL_CODE(FILE_DEVICE_WIN11MON, WIN11MON_IOCTL_BASE + 0x41, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_MONITOR_MEM_SCAN_PHYSICAL \
  CTL_CODE(FILE_DEVICE_WIN11MON, WIN11MON_IOCTL_BASE + 0x42, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_MONITOR_MEM_GET_SHARING \
  CTL_CODE(FILE_DEVICE_WIN11MON, WIN11MON_IOCTL_BASE + 0x43, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_MONITOR_MEM_GET_STATS \
  CTL_CODE(FILE_DEVICE_WIN11MON, WIN11MON_IOCTL_BASE + 0x44, METHOD_BUFFERED, FILE_READ_ACCESS)

/*--------------------------------------------------------------------------
 * IOCTL Input Structures
 *-------------------------------------------------------------------------*/
typedef struct _MEM_SCAN_INPUT {
  ULONG ProcessId;
} MEM_SCAN_INPUT;

/*--------------------------------------------------------------------------
 * Static String Tables
 *-------------------------------------------------------------------------*/
static const WCHAR *g_AnomalyStrings[] = {L"None",
                                          L"Executable Heap",
                                          L"Writable Code Section",
                                          L"Unbacked Executable",
                                          L"Hidden Region",
                                          L"Double-Mapped Pages",
                                          L"Cross-Process Sharing",
                                          L"Kernel Address in User Space",
                                          L"Missing Guard Page",
                                          L"Suspicious Protection",
                                          L"Large Private Region",
                                          L"RWX Region",
                                          L"MDL Locked Pages",
                                          L"Unknown"};

static const WCHAR *g_VadTypeStrings[] = {L"Private",    L"Mapped",     L"Image",  L"Physical",
                                          L"WriteWatch", L"LargePages", L"Rotate", L"Unknown"};

/*--------------------------------------------------------------------------
 * Internal Helper
 *-------------------------------------------------------------------------*/
static DWORD MemIoctl(_In_ HANDLE hDevice, _In_ DWORD IoCtlCode, _In_opt_ LPVOID pInput,
                      _In_ DWORD InputSize, _Out_opt_ LPVOID pOutput, _In_ DWORD OutputSize,
                      _Out_opt_ DWORD *pBytesReturned) {
  DWORD bytesReturned = 0;
  BOOL success;

  if (hDevice == NULL || hDevice == INVALID_HANDLE_VALUE) {
    return ERROR_INVALID_HANDLE;
  }

  success = DeviceIoControl(hDevice, IoCtlCode, pInput, InputSize, pOutput, OutputSize,
                            &bytesReturned, NULL);

  if (pBytesReturned != NULL) {
    *pBytesReturned = bytesReturned;
  }

  if (!success) {
    return GetLastError();
  }

  return ERROR_SUCCESS;
}

/*==========================================================================
 * VAD Scanning APIs
 *=========================================================================*/

_Use_decl_annotations_ DWORD WINAPI Win11MonMemScanVad(HANDLE hDevice, DWORD ProcessId,
                                                       PWIN11MON_VAD_SCAN_RESULT pResult) {
  MEM_SCAN_INPUT input;
  DWORD bytesReturned;
  DWORD err;

  if (pResult == NULL) {
    return ERROR_INVALID_PARAMETER;
  }

  ZeroMemory(pResult, sizeof(*pResult));
  input.ProcessId = ProcessId;

  err = MemIoctl(hDevice, IOCTL_MONITOR_MEM_SCAN_VAD, &input, sizeof(input), pResult,
                 sizeof(*pResult), &bytesReturned);

  if (err == ERROR_SUCCESS && bytesReturned < sizeof(*pResult)) {
    return ERROR_INSUFFICIENT_BUFFER;
  }

  return err;
}

_Use_decl_annotations_ DWORD WINAPI Win11MonMemScanVadDetailed(HANDLE hDevice, DWORD ProcessId,
                                                               PVOID pBuffer, DWORD BufferSize,
                                                               DWORD *pBytesWritten) {
  MEM_SCAN_INPUT input;
  DWORD err;

  if (pBuffer == NULL || pBytesWritten == NULL) {
    return ERROR_INVALID_PARAMETER;
  }

  if (BufferSize < sizeof(WIN11MON_VAD_SCAN_RESULT)) {
    return ERROR_INSUFFICIENT_BUFFER;
  }

  *pBytesWritten = 0;
  ZeroMemory(pBuffer, BufferSize);
  input.ProcessId = ProcessId;

  err = MemIoctl(hDevice, IOCTL_MONITOR_MEM_SCAN_VAD, &input, sizeof(input), pBuffer, BufferSize,
                 pBytesWritten);

  return err;
}

/*==========================================================================
 * MDL Tracking APIs
 *=========================================================================*/

_Use_decl_annotations_ DWORD WINAPI Win11MonMemGetMdls(HANDLE hDevice, DWORD ProcessId,
                                                       PVOID pBuffer, DWORD BufferSize,
                                                       DWORD *pBytesWritten) {
  MEM_SCAN_INPUT input;
  DWORD err;

  if (pBuffer == NULL || pBytesWritten == NULL) {
    return ERROR_INVALID_PARAMETER;
  }

  if (BufferSize < sizeof(WIN11MON_MDL_TRACKER_RESULT)) {
    return ERROR_INSUFFICIENT_BUFFER;
  }

  *pBytesWritten = 0;
  ZeroMemory(pBuffer, BufferSize);
  input.ProcessId = ProcessId;

  err = MemIoctl(hDevice, IOCTL_MONITOR_MEM_GET_MDLS, &input, sizeof(input), pBuffer, BufferSize,
                 pBytesWritten);

  return err;
}

/*==========================================================================
 * Physical Memory Analysis APIs
 *=========================================================================*/

_Use_decl_annotations_ DWORD WINAPI
Win11MonMemScanPhysical(HANDLE hDevice, DWORD ProcessId, PWIN11MON_PHYSICAL_SCAN_RESULT pResult) {
  MEM_SCAN_INPUT input;
  DWORD bytesReturned;
  DWORD err;

  if (pResult == NULL) {
    return ERROR_INVALID_PARAMETER;
  }

  ZeroMemory(pResult, sizeof(*pResult));
  input.ProcessId = ProcessId;

  err = MemIoctl(hDevice, IOCTL_MONITOR_MEM_SCAN_PHYSICAL, &input, sizeof(input), pResult,
                 sizeof(*pResult), &bytesReturned);

  if (err == ERROR_SUCCESS && bytesReturned < sizeof(*pResult)) {
    return ERROR_INSUFFICIENT_BUFFER;
  }

  return err;
}

/*==========================================================================
 * Shared Memory Detection APIs
 *=========================================================================*/

_Use_decl_annotations_ DWORD WINAPI Win11MonMemGetSharing(HANDLE hDevice, DWORD ProcessId,
                                                          PVOID pBuffer, DWORD BufferSize,
                                                          DWORD *pBytesWritten) {
  MEM_SCAN_INPUT input;
  DWORD err;

  if (pBuffer == NULL || pBytesWritten == NULL) {
    return ERROR_INVALID_PARAMETER;
  }

  if (BufferSize < sizeof(WIN11MON_SHARING_SCAN_RESULT)) {
    return ERROR_INSUFFICIENT_BUFFER;
  }

  *pBytesWritten = 0;
  ZeroMemory(pBuffer, BufferSize);
  input.ProcessId = ProcessId;

  err = MemIoctl(hDevice, IOCTL_MONITOR_MEM_GET_SHARING, &input, sizeof(input), pBuffer, BufferSize,
                 pBytesWritten);

  return err;
}

/*==========================================================================
 * Statistics APIs
 *=========================================================================*/

_Use_decl_annotations_ DWORD WINAPI Win11MonMemGetStats(HANDLE hDevice,
                                                        PWIN11MON_MEM_STATS pStats) {
  DWORD bytesReturned;

  if (pStats == NULL) {
    return ERROR_INVALID_PARAMETER;
  }

  ZeroMemory(pStats, sizeof(*pStats));

  return MemIoctl(hDevice, IOCTL_MONITOR_MEM_GET_STATS, NULL, 0, pStats, sizeof(*pStats),
                  &bytesReturned);
}

/*==========================================================================
 * Helper Functions
 *=========================================================================*/

_Use_decl_annotations_ const WCHAR *WINAPI
Win11MonMemAnomalyToString(WIN11MON_MEM_ANOMALY Anomaly) {
  if ((ULONG)Anomaly >= ARRAYSIZE(g_AnomalyStrings)) {
    return g_AnomalyStrings[ARRAYSIZE(g_AnomalyStrings) - 1];
  }
  return g_AnomalyStrings[(ULONG)Anomaly];
}

_Use_decl_annotations_ const WCHAR *WINAPI Win11MonMemVadTypeToString(WIN11MON_VAD_TYPE VadType) {
  if ((ULONG)VadType >= ARRAYSIZE(g_VadTypeStrings)) {
    return g_VadTypeStrings[ARRAYSIZE(g_VadTypeStrings) - 1];
  }
  return g_VadTypeStrings[(ULONG)VadType];
}

_Use_decl_annotations_ DWORD WINAPI Win11MonMemProtectionToString(ULONG Protection, WCHAR *Buffer,
                                                                  DWORD BufferSize) {
  WCHAR flags[8] = {L'-', L'-', L'-', L'\0'};

  if (Buffer == NULL || BufferSize < 4) {
    return ERROR_INVALID_PARAMETER;
  }

  /* Decode protection bits to R/W/X format */
  switch (Protection) {
  case 0: /* PAGE_NOACCESS */
    flags[0] = L'-';
    flags[1] = L'-';
    flags[2] = L'-';
    break;
  case 1: /* PAGE_READONLY */
    flags[0] = L'R';
    flags[1] = L'-';
    flags[2] = L'-';
    break;
  case 2: /* PAGE_EXECUTE */
    flags[0] = L'-';
    flags[1] = L'-';
    flags[2] = L'X';
    break;
  case 3: /* PAGE_EXECUTE_READ */
    flags[0] = L'R';
    flags[1] = L'-';
    flags[2] = L'X';
    break;
  case 4: /* PAGE_READWRITE */
    flags[0] = L'R';
    flags[1] = L'W';
    flags[2] = L'-';
    break;
  case 5: /* PAGE_WRITECOPY */
    flags[0] = L'R';
    flags[1] = L'C';
    flags[2] = L'-';
    break;
  case 6: /* PAGE_EXECUTE_READWRITE */
    flags[0] = L'R';
    flags[1] = L'W';
    flags[2] = L'X';
    break;
  case 7: /* PAGE_EXECUTE_WRITECOPY */
    flags[0] = L'R';
    flags[1] = L'C';
    flags[2] = L'X';
    break;
  default:
    flags[0] = L'?';
    flags[1] = L'?';
    flags[2] = L'?';
    break;
  }

  if (BufferSize < 4) {
    return ERROR_INSUFFICIENT_BUFFER;
  }

  wcscpy_s(Buffer, BufferSize, flags);
  return ERROR_SUCCESS;
}

#pragma warning(pop)
