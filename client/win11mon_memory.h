/*
 * Win11Mon Memory Client API - Public Header
 *
 * Author: Colin MacRitchie | ziX Labs
 * Organization: ziX Labs - Security Research Division
 * File: win11mon_memory.h
 * Version: 1.0
 * Date: 2025-12-01
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and
 * confidential. Redistribution or disclosure without prior written consent is
 * prohibited.
 *
 * Summary
 * -------
 * User-mode client APIs for memory region monitoring and anomaly detection.
 * Provides VAD scanning, MDL tracking, physical page analysis, and shared
 * memory detection. Communicates with win11_monitor.sys via DeviceIoControl.
 *
 * Thread Safety:
 * - All functions are thread-safe
 * - Handle management is caller's responsibility
 */

#ifndef _ZIX_LABS_WIN11MON_MEMORY_H_
#define _ZIX_LABS_WIN11MON_MEMORY_H_

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------
 * Memory Monitoring Constants
 *-------------------------------------------------------------------------*/
#define WIN11MON_MEM_MAX_VADS           256
#define WIN11MON_MEM_MAX_MDLS           128
#define WIN11MON_MEM_MAX_SHARED         64
#define WIN11MON_MEM_ANOMALY_TYPE_COUNT 16

/*--------------------------------------------------------------------------
 * VAD Type Enumeration
 *-------------------------------------------------------------------------*/
typedef enum _WIN11MON_VAD_TYPE {
  Win11MonVadType_Private = 0,
  Win11MonVadType_Mapped = 1,
  Win11MonVadType_Image = 2,
  Win11MonVadType_Physical = 3,
  Win11MonVadType_WriteWatch = 4,
  Win11MonVadType_LargePages = 5,
  Win11MonVadType_Rotate = 6,
  Win11MonVadType_Unknown = 7
} WIN11MON_VAD_TYPE;

/*--------------------------------------------------------------------------
 * Memory Anomaly Types
 *-------------------------------------------------------------------------*/
typedef enum _WIN11MON_MEM_ANOMALY {
  Win11MonMemAnomaly_None = 0,
  Win11MonMemAnomaly_ExecutableHeap = 1,
  Win11MonMemAnomaly_WritableCode = 2,
  Win11MonMemAnomaly_UnbackedExecutable = 3,
  Win11MonMemAnomaly_HiddenRegion = 4,
  Win11MonMemAnomaly_DoubleMapped = 5,
  Win11MonMemAnomaly_CrossProcessSharing = 6,
  Win11MonMemAnomaly_KernelAddressInUser = 7,
  Win11MonMemAnomaly_GuardPageMissing = 8,
  Win11MonMemAnomaly_SuspiciousProtection = 9,
  Win11MonMemAnomaly_LargePrivateRegion = 10,
  Win11MonMemAnomaly_RWXRegion = 11,
  Win11MonMemAnomaly_MdlLocked = 12,
  Win11MonMemAnomaly_Max = 13
} WIN11MON_MEM_ANOMALY;

/*--------------------------------------------------------------------------
 * VAD Information (single entry)
 *-------------------------------------------------------------------------*/
#pragma pack(push, 8)
typedef struct _WIN11MON_VAD_INFO {
  ULONG64 StartAddress; /* Masked */
  ULONG64 EndAddress;   /* Masked */
  ULONG64 Size;
  WIN11MON_VAD_TYPE VadType;
  ULONG Protection;
  ULONG InitialProtection;
  BOOL IsExecutable;
  BOOL IsWritable;
  BOOL IsPrivate;
  BOOL IsCommitted;
  BOOL HasFileBacking;
  ULONG AnomalyFlags; /* Bitmask */
} WIN11MON_VAD_INFO, *PWIN11MON_VAD_INFO;
#pragma pack(pop)

/*--------------------------------------------------------------------------
 * VAD Scan Result (summary + optional detailed entries)
 *-------------------------------------------------------------------------*/
#pragma pack(push, 8)
typedef struct _WIN11MON_VAD_SCAN_RESULT {
  ULONG Size;
  ULONG ProcessId;
  ULONG VadCount;
  ULONG DetailedInfoCount;
  ULONG64 TotalPrivateBytes;
  ULONG64 TotalMappedBytes;
  ULONG64 TotalExecutableBytes;
  ULONG64 TotalCommittedBytes;
  ULONG SuspiciousVadCount;
  ULONG AnomalyFlags;
  ULONG64 ScanStartTime;
  ULONG64 ScanEndTime;
  ULONG ScanDurationUs;
  ULONG Reserved;
  /* WIN11MON_VAD_INFO array follows if detailed */
} WIN11MON_VAD_SCAN_RESULT, *PWIN11MON_VAD_SCAN_RESULT;
#pragma pack(pop)

/*--------------------------------------------------------------------------
 * MDL Information (single entry)
 *-------------------------------------------------------------------------*/
#pragma pack(push, 8)
typedef struct _WIN11MON_MDL_INFO {
  ULONG64 VirtualAddress; /* Masked */
  ULONG64 ByteCount;
  ULONG64 ByteOffset;
  ULONG ProcessId;
  ULONG Flags;
  ULONG PageCount;
  BOOL IsLocked;
  BOOL IsMapped;
  BOOL IsNonPagedPool;
  BYTE Reserved1;
  ULONG64 CreationTime;
  ULONG AnomalyFlags;
  ULONG Reserved2;
} WIN11MON_MDL_INFO, *PWIN11MON_MDL_INFO;
#pragma pack(pop)

/*--------------------------------------------------------------------------
 * MDL Tracker Result
 *-------------------------------------------------------------------------*/
#pragma pack(push, 8)
typedef struct _WIN11MON_MDL_TRACKER_RESULT {
  ULONG Size;
  ULONG ProcessId;
  ULONG TrackedMdlCount;
  ULONG MaxMdlsReturned;
  ULONG64 TotalLockedBytes;
  ULONG64 TotalMappedBytes;
  ULONG SuspiciousMdlCount;
  ULONG Reserved;
  /* WIN11MON_MDL_INFO array follows */
} WIN11MON_MDL_TRACKER_RESULT, *PWIN11MON_MDL_TRACKER_RESULT;
#pragma pack(pop)

/*--------------------------------------------------------------------------
 * Physical Scan Result
 *-------------------------------------------------------------------------*/
#pragma pack(push, 8)
typedef struct _WIN11MON_PHYSICAL_SCAN_RESULT {
  ULONG Size;
  ULONG ProcessId;
  ULONG64 TotalPhysicalBytes;
  ULONG64 WorkingSetBytes;
  ULONG PageCount;
  ULONG SharedPageCount;
  ULONG PrivatePageCount;
  ULONG ModifiedPageCount;
  ULONG DoubleMappedCount;
  ULONG SuspiciousCount;
  ULONG AnomalyFlags;
  ULONG ScanDurationUs;
} WIN11MON_PHYSICAL_SCAN_RESULT, *PWIN11MON_PHYSICAL_SCAN_RESULT;
#pragma pack(pop)

/*--------------------------------------------------------------------------
 * Shared Region Information (single entry)
 *-------------------------------------------------------------------------*/
#pragma pack(push, 8)
typedef struct _WIN11MON_SHARED_REGION {
  ULONG64 VirtualAddress; /* Masked */
  ULONG64 Size;
  ULONG ProcessIdOwner;
  ULONG ProcessIdSharer;
  ULONG ShareType;
  BOOL IsExecutable;
  ULONG AnomalyFlags;
  ULONG Reserved;
} WIN11MON_SHARED_REGION, *PWIN11MON_SHARED_REGION;
#pragma pack(pop)

/*--------------------------------------------------------------------------
 * Sharing Scan Result
 *-------------------------------------------------------------------------*/
#pragma pack(push, 8)
typedef struct _WIN11MON_SHARING_SCAN_RESULT {
  ULONG Size;
  ULONG ProcessId;
  ULONG SharedRegionCount;
  ULONG SuspiciousShareCount;
  ULONG64 TotalSharedBytes;
  ULONG CrossProcessShareCount;
  ULONG Reserved;
  /* WIN11MON_SHARED_REGION array follows */
} WIN11MON_SHARING_SCAN_RESULT, *PWIN11MON_SHARING_SCAN_RESULT;
#pragma pack(pop)

/*--------------------------------------------------------------------------
 * Memory Monitoring Statistics
 *-------------------------------------------------------------------------*/
#pragma pack(push, 8)
typedef struct _WIN11MON_MEM_STATS {
  ULONG Size;
  ULONG Reserved;
  ULONG64 VadScansPerformed;
  ULONG64 MdlScansPerformed;
  ULONG64 PhysicalScansPerformed;
  ULONG64 SharingScansPerformed;
  ULONG64 TotalAnomaliesDetected;
  ULONG TrackedMdlCount;
  ULONG TrackedProcessCount;
  ULONG64 TotalBytesScanned;
  ULONG AverageVadScanTimeUs;
  ULONG PeakVadScanTimeUs;
  ULONG AnomaliesByType[WIN11MON_MEM_ANOMALY_TYPE_COUNT];
} WIN11MON_MEM_STATS, *PWIN11MON_MEM_STATS;
#pragma pack(pop)

/*==========================================================================
 * VAD Scanning APIs
 *=========================================================================*/

/**
 * @function   Win11MonMemScanVad
 * @purpose    Scan VAD tree for a process (summary only)
 * @precondition hDevice must be valid driver handle
 *
 * @param[in]  hDevice - Driver device handle
 * @param[in]  ProcessId - Target process ID
 * @param[out] pResult - Output scan result (summary)
 * @returns    ERROR_SUCCESS on success
 *             ERROR_NOT_FOUND if process doesn't exist
 *             ERROR_INVALID_HANDLE if hDevice invalid
 *
 * @thread-safety Thread-safe
 */
DWORD
WINAPI
Win11MonMemScanVad(_In_ HANDLE hDevice, _In_ DWORD ProcessId,
                   _Out_ PWIN11MON_VAD_SCAN_RESULT pResult);

/**
 * @function   Win11MonMemScanVadDetailed
 * @purpose    Scan VAD tree for a process (with detailed VAD entries)
 * @precondition hDevice must be valid driver handle
 *
 * @param[in]  hDevice - Driver device handle
 * @param[in]  ProcessId - Target process ID
 * @param[out] pBuffer - Buffer for result + VAD info array
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
Win11MonMemScanVadDetailed(_In_ HANDLE hDevice, _In_ DWORD ProcessId,
                           _Out_writes_bytes_to_(BufferSize, *pBytesWritten) PVOID pBuffer,
                           _In_ DWORD BufferSize, _Out_ DWORD *pBytesWritten);

/*==========================================================================
 * MDL Tracking APIs
 *=========================================================================*/

/**
 * @function   Win11MonMemGetMdls
 * @purpose    Get tracked MDLs for a process
 * @precondition hDevice must be valid driver handle
 *
 * @param[in]  hDevice - Driver device handle
 * @param[in]  ProcessId - Target process ID (0 = all processes)
 * @param[out] pBuffer - Buffer for result + MDL info array
 * @param[in]  BufferSize - Buffer size in bytes
 * @param[out] pBytesWritten - Actual bytes written
 * @returns    ERROR_SUCCESS on success
 *             ERROR_MORE_DATA if buffer too small
 *
 * @thread-safety Thread-safe
 */
DWORD
WINAPI
Win11MonMemGetMdls(_In_ HANDLE hDevice, _In_ DWORD ProcessId,
                   _Out_writes_bytes_to_(BufferSize, *pBytesWritten) PVOID pBuffer,
                   _In_ DWORD BufferSize, _Out_ DWORD *pBytesWritten);

/*==========================================================================
 * Physical Memory Analysis APIs
 *=========================================================================*/

/**
 * @function   Win11MonMemScanPhysical
 * @purpose    Analyze physical page mappings for a process
 * @precondition hDevice must be valid driver handle
 *
 * @param[in]  hDevice - Driver device handle
 * @param[in]  ProcessId - Target process ID
 * @param[out] pResult - Output scan result
 * @returns    ERROR_SUCCESS on success
 *             ERROR_NOT_FOUND if process doesn't exist
 *
 * @thread-safety Thread-safe
 */
DWORD
WINAPI
Win11MonMemScanPhysical(_In_ HANDLE hDevice, _In_ DWORD ProcessId,
                        _Out_ PWIN11MON_PHYSICAL_SCAN_RESULT pResult);

/*==========================================================================
 * Shared Memory Detection APIs
 *=========================================================================*/

/**
 * @function   Win11MonMemGetSharing
 * @purpose    Detect cross-process memory sharing
 * @precondition hDevice must be valid driver handle
 *
 * @param[in]  hDevice - Driver device handle
 * @param[in]  ProcessId - Target process ID
 * @param[out] pBuffer - Buffer for result + shared region array
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
Win11MonMemGetSharing(_In_ HANDLE hDevice, _In_ DWORD ProcessId,
                      _Out_writes_bytes_to_(BufferSize, *pBytesWritten) PVOID pBuffer,
                      _In_ DWORD BufferSize, _Out_ DWORD *pBytesWritten);

/*==========================================================================
 * Statistics APIs
 *=========================================================================*/

/**
 * @function   Win11MonMemGetStats
 * @purpose    Get memory monitoring statistics
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
Win11MonMemGetStats(_In_ HANDLE hDevice, _Out_ PWIN11MON_MEM_STATS pStats);

/*==========================================================================
 * Helper Functions
 *=========================================================================*/

/**
 * @function   Win11MonMemAnomalyToString
 * @purpose    Get human-readable string for anomaly type
 *
 * @param[in]  Anomaly - Anomaly type
 * @returns    Static string describing anomaly
 */
const WCHAR *WINAPI Win11MonMemAnomalyToString(_In_ WIN11MON_MEM_ANOMALY Anomaly);

/**
 * @function   Win11MonMemVadTypeToString
 * @purpose    Get human-readable string for VAD type
 *
 * @param[in]  VadType - VAD type
 * @returns    Static string describing VAD type
 */
const WCHAR *WINAPI Win11MonMemVadTypeToString(_In_ WIN11MON_VAD_TYPE VadType);

/**
 * @function   Win11MonMemProtectionToString
 * @purpose    Convert protection flags to string (e.g., "RWX")
 *
 * @param[in]  Protection - Protection value
 * @param[out] Buffer - Output buffer
 * @param[in]  BufferSize - Buffer size in characters
 * @returns    ERROR_SUCCESS on success
 */
DWORD
WINAPI
Win11MonMemProtectionToString(_In_ ULONG Protection, _Out_writes_z_(BufferSize) WCHAR *Buffer,
                              _In_ DWORD BufferSize);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _ZIX_LABS_WIN11MON_MEMORY_H_ */
