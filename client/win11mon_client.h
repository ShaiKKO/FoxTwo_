/*
 * Windows 11 Monitor Manager - Usermode Client Library Header
 *
 * Author: Colin MacRitchie
 * Organization: ziX Performance Labs
 * File: client/win11mon_client.h
 * Version: 1.0
 * Date: 2025-12-01
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and
 * confidential. Redistribution or disclosure without prior written consent is
 * prohibited.
 *
 * Summary
 * -------
 * Type-safe C API wrapper for the Windows 11 Monitor Manager kernel driver.
 * Provides:
 *   - Synchronous and asynchronous IOCTL wrappers
 *   - Automatic driver version compatibility check
 *   - Comprehensive error handling with human-readable messages
 *   - Thread-safe handle management
 *
 * Usage
 * -----
 *   #include "win11mon_client.h"
 *
 *   HWIN11MON hMon = NULL;
 *   HRESULT hr = Win11MonOpen(&hMon);
 *   if (SUCCEEDED(hr)) {
 *       WIN11MON_VERSION version;
 *       Win11MonGetVersion(hMon, &version);
 *       printf("Driver v%d.%d.%d\n", version.Major, version.Minor,
 * version.Build); Win11MonClose(hMon);
 *   }
 *
 * Build
 * -----
 * Link with: win11mon_client.lib
 * Requires: Windows SDK for HRESULT, DeviceIoControl
 */

#ifndef WIN11MON_CLIENT_H
#define WIN11MON_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>

/*--------------------------------------------------------------------------
 * Export/Import Macros
 *-------------------------------------------------------------------------*/
#ifdef WIN11MON_CLIENT_EXPORTS
#define WIN11MON_API __declspec(dllexport)
#else
#define WIN11MON_API
#endif

/*--------------------------------------------------------------------------
 * Opaque Handle Type
 *-------------------------------------------------------------------------*/
typedef struct _WIN11MON_HANDLE* HWIN11MON;

/*--------------------------------------------------------------------------
 * Version Information
 *-------------------------------------------------------------------------*/
typedef struct _WIN11MON_VERSION {
  DWORD Major;
  DWORD Minor;
  DWORD Build;
  DWORD Capabilities;
} WIN11MON_VERSION, *PWIN11MON_VERSION;

/*--------------------------------------------------------------------------
 * Capability Flags (mirrors kernel WIN11MON_CAP_* defines)
 *-------------------------------------------------------------------------*/
#define WIN11MON_CLIENT_CAP_IOP_MC 0x00000001u
#define WIN11MON_CLIENT_CAP_POOL_TRACK 0x00000002u
#define WIN11MON_CLIENT_CAP_TELEMETRY 0x00000004u
#define WIN11MON_CLIENT_CAP_RATE_LIMIT 0x00000008u
#define WIN11MON_CLIENT_CAP_ENCRYPTION_STUB 0x00000010u
#define WIN11MON_CLIENT_CAP_IORING_ENUM 0x00000100u
#define WIN11MON_CLIENT_CAP_REGBUF_INTEGRITY 0x00000200u
#define WIN11MON_CLIENT_CAP_ETW_PROVIDER 0x00000400u
#define WIN11MON_CLIENT_CAP_ADDR_MASKING 0x00000800u
#define WIN11MON_CLIENT_CAP_PERPROC_RATELIMIT 0x00001000u
#define WIN11MON_CLIENT_CAP_RING_BUFFER 0x00002000u
#define WIN11MON_CLIENT_CAP_RUNTIME_OFFSETS 0x00004000u
#define WIN11MON_CLIENT_CAP_ATTACK_TAGGING 0x00008000u

/*--------------------------------------------------------------------------
 * Monitoring Configuration
 *-------------------------------------------------------------------------*/
typedef struct _WIN11MON_CONFIG {
  DWORD Size; /* Must be sizeof(WIN11MON_CONFIG) */
  BOOL EnableMonitoring;
  BOOL EnableTelemetry;
  BOOL EnableEncryption;
  DWORD RateLimitPerSec;
} WIN11MON_CONFIG, *PWIN11MON_CONFIG;

/*--------------------------------------------------------------------------
 * Monitor Statistics
 *-------------------------------------------------------------------------*/
typedef struct _WIN11MON_STATS {
  DWORD Size;
  DWORD64 TotalAllocations;
  DWORD64 IopMcDetections;
  DWORD64 CrossVmDetections;
  DWORD64 PolicyViolations;
  DWORD64 DroppedEvents;
  DWORD PoolEntryCount;
  DWORD TelemetryEventCount;
  DWORD CurrentRateLimit;
} WIN11MON_STATS, *PWIN11MON_STATS;

/*--------------------------------------------------------------------------
 * IoRing Handle Information
 *-------------------------------------------------------------------------*/
typedef struct _WIN11MON_IORING_INFO {
  DWORD ProcessId;
  DWORD64 HandleValue;
  DWORD64 ObjectAddress; /* Masked per policy */
  DWORD AccessMask;
  DWORD RegBuffersCount;
  DWORD ViolationFlags;
} WIN11MON_IORING_INFO, *PWIN11MON_IORING_INFO;

/*--------------------------------------------------------------------------
 * Ring Buffer Statistics
 *-------------------------------------------------------------------------*/
typedef struct _WIN11MON_RINGBUF_STATS {
  DWORD Size;
  DWORD BufferSizeBytes;
  DWORD UsedBytes;
  DWORD FreeBytes;
  DWORD EventCount;
  DWORD TotalEventsWritten;
  DWORD EventsOverwritten;
  DWORD EventsDropped;
  DWORD WrapCount;
  DWORD64 OldestTimestamp;
  DWORD64 NewestTimestamp;
} WIN11MON_RINGBUF_STATS, *PWIN11MON_RINGBUF_STATS;

/*--------------------------------------------------------------------------
 * Rate Limit Statistics
 *-------------------------------------------------------------------------*/
typedef struct _WIN11MON_RATE_STATS {
  DWORD Size;
  DWORD ActiveProcessCount;
  DWORD64 TotalEventsAllowed;
  DWORD64 TotalEventsDropped;
  DWORD64 ProcessDropCount;
  DWORD64 GlobalDropCount;
  DWORD CurrentGlobalRate;
  DWORD PeakGlobalRate;
  DWORD GlobalLimitPerSec;
  DWORD PerProcessLimitPerSec;
} WIN11MON_RATE_STATS, *PWIN11MON_RATE_STATS;

/*--------------------------------------------------------------------------
 * Offset Resolution Status
 *-------------------------------------------------------------------------*/
typedef enum _WIN11MON_OFFSET_METHOD {
  Win11MonOffset_Unknown = 0,
  Win11MonOffset_Embedded = 1,
  Win11MonOffset_Detected = 2,
  Win11MonOffset_Degraded = 3
} WIN11MON_OFFSET_METHOD;

typedef struct _WIN11MON_OFFSET_STATUS {
  DWORD Size;
  DWORD WindowsBuildNumber;
  WIN11MON_OFFSET_METHOD Method;
  BOOL IoRingOffsetsValid;
  BOOL IopMcOffsetsValid;
  DWORD IoRingStructureSize;
  DWORD IopMcStructureSize;
} WIN11MON_OFFSET_STATUS, *PWIN11MON_OFFSET_STATUS;

/*--------------------------------------------------------------------------
 * Address Mask Policy
 *-------------------------------------------------------------------------*/
typedef enum _WIN11MON_MASK_POLICY {
  Win11MonMask_None = 0,
  Win11MonMask_HashBased = 1,
  Win11MonMask_ZeroPublic = 2
} WIN11MON_MASK_POLICY;

/*--------------------------------------------------------------------------
 * Event Types (for telemetry events)
 *-------------------------------------------------------------------------*/
typedef enum _WIN11MON_EVENT_TYPE {
  Win11MonEvent_None = 0,
  Win11MonEvent_IopMcDetected = 1,
  Win11MonEvent_CrossVmDetected = 2,
  Win11MonEvent_Anomaly = 3,
  Win11MonEvent_IoRingOpSubmit = 4,
  Win11MonEvent_IoRingOpComplete = 5,
  Win11MonEvent_RegBufViolation = 6
} WIN11MON_EVENT_TYPE;

/*--------------------------------------------------------------------------
 * Generic Event Header
 *-------------------------------------------------------------------------*/
typedef struct _WIN11MON_EVENT_HEADER {
  DWORD Size;
  WIN11MON_EVENT_TYPE Type;
  DWORD ProcessId;
  DWORD ThreadId;
  DWORD64 Timestamp;
} WIN11MON_EVENT_HEADER, *PWIN11MON_EVENT_HEADER;

/*--------------------------------------------------------------------------
 * Async Event Callback
 *-------------------------------------------------------------------------*/
typedef VOID(CALLBACK* WIN11MON_EVENT_CALLBACK)(_In_ PVOID Context,
                                                _In_reads_bytes_(EventSize)
                                                    const VOID* EventData,
                                                _In_ DWORD EventSize);

/*--------------------------------------------------------------------------
 * Error Codes
 *-------------------------------------------------------------------------*/
#define WIN11MON_E_DRIVER_NOT_FOUND \
  MAKE_HRESULT(SEVERITY_ERROR, FACILITY_ITF, 0x0001)
#define WIN11MON_E_VERSION_MISMATCH \
  MAKE_HRESULT(SEVERITY_ERROR, FACILITY_ITF, 0x0002)
#define WIN11MON_E_ACCESS_DENIED \
  MAKE_HRESULT(SEVERITY_ERROR, FACILITY_ITF, 0x0003)
#define WIN11MON_E_INVALID_HANDLE \
  MAKE_HRESULT(SEVERITY_ERROR, FACILITY_ITF, 0x0004)
#define WIN11MON_E_BUFFER_TOO_SMALL \
  MAKE_HRESULT(SEVERITY_ERROR, FACILITY_ITF, 0x0005)
#define WIN11MON_E_NOT_SUPPORTED \
  MAKE_HRESULT(SEVERITY_ERROR, FACILITY_ITF, 0x0006)
#define WIN11MON_E_NO_MORE_EVENTS \
  MAKE_HRESULT(SEVERITY_ERROR, FACILITY_ITF, 0x0007)
#define WIN11MON_E_ASYNC_PENDING \
  MAKE_HRESULT(SEVERITY_ERROR, FACILITY_ITF, 0x0008)

/*==========================================================================
 * Public API - Handle Management
 *=========================================================================*/

/**
 * @function   Win11MonOpen
 * @purpose    Open a connection to the Win11 Monitor driver
 * @param[out] Handle - Receives opaque handle on success
 * @returns    S_OK on success
 *             WIN11MON_E_DRIVER_NOT_FOUND if driver not loaded
 *             WIN11MON_E_ACCESS_DENIED if access denied
 */
WIN11MON_API HRESULT Win11MonOpen(_Out_ HWIN11MON* Handle);

/**
 * @function   Win11MonClose
 * @purpose    Close a driver connection and free resources
 * @param[in]  Handle - Handle from Win11MonOpen
 */
WIN11MON_API VOID Win11MonClose(_In_ HWIN11MON Handle);

/**
 * @function   Win11MonIsAvailable
 * @purpose    Quick check if driver is loaded (no handle required)
 * @returns    TRUE if driver device exists
 */
WIN11MON_API BOOL Win11MonIsAvailable(VOID);

/*==========================================================================
 * Public API - Version and Capabilities
 *=========================================================================*/

/**
 * @function   Win11MonGetVersion
 * @purpose    Get driver version and capability flags
 * @param[in]  Handle - Valid driver handle
 * @param[out] Version - Receives version info
 * @returns    S_OK on success
 */
WIN11MON_API HRESULT Win11MonGetVersion(_In_ HWIN11MON Handle,
                                        _Out_ PWIN11MON_VERSION Version);

/**
 * @function   Win11MonHasCapability
 * @purpose    Check if driver supports a specific capability
 * @param[in]  Handle - Valid driver handle
 * @param[in]  CapabilityFlag - WIN11MON_CLIENT_CAP_* flag
 * @returns    TRUE if capability supported
 */
WIN11MON_API BOOL Win11MonHasCapability(_In_ HWIN11MON Handle,
                                        _In_ DWORD CapabilityFlag);

/*==========================================================================
 * Public API - Monitoring Control
 *=========================================================================*/

/**
 * @function   Win11MonEnable
 * @purpose    Enable monitoring with specified configuration
 * @param[in]  Handle - Valid driver handle
 * @param[in]  Config - Configuration settings
 * @returns    S_OK on success
 */
WIN11MON_API HRESULT Win11MonEnable(_In_ HWIN11MON Handle,
                                    _In_ const WIN11MON_CONFIG* Config);

/**
 * @function   Win11MonDisable
 * @purpose    Disable monitoring
 * @param[in]  Handle - Valid driver handle
 * @returns    S_OK on success
 */
WIN11MON_API HRESULT Win11MonDisable(_In_ HWIN11MON Handle);

/**
 * @function   Win11MonTriggerScan
 * @purpose    Trigger immediate pool scan
 * @param[in]  Handle - Valid driver handle
 * @returns    S_OK on success
 */
WIN11MON_API HRESULT Win11MonTriggerScan(_In_ HWIN11MON Handle);

/*==========================================================================
 * Public API - Statistics
 *=========================================================================*/

/**
 * @function   Win11MonGetStats
 * @purpose    Get monitoring statistics
 * @param[in]  Handle - Valid driver handle
 * @param[out] Stats - Receives statistics
 * @returns    S_OK on success
 */
WIN11MON_API HRESULT Win11MonGetStats(_In_ HWIN11MON Handle,
                                      _Out_ PWIN11MON_STATS Stats);

/**
 * @function   Win11MonGetRateStats
 * @purpose    Get per-process rate limiting statistics
 * @param[in]  Handle - Valid driver handle
 * @param[out] Stats - Receives rate limit statistics
 * @returns    S_OK on success
 */
WIN11MON_API HRESULT Win11MonGetRateStats(_In_ HWIN11MON Handle,
                                          _Out_ PWIN11MON_RATE_STATS Stats);

/*==========================================================================
 * Public API - Event Fetching
 *=========================================================================*/

/**
 * @function   Win11MonFetchEvents
 * @purpose    Fetch pending telemetry events
 * @param[in]  Handle - Valid driver handle
 * @param[out] Buffer - Buffer to receive events
 * @param[in]  BufferSize - Size of buffer in bytes
 * @param[out] BytesFetched - Actual bytes written
 * @param[out] EventCount - Number of events fetched
 * @returns    S_OK on success
 *             WIN11MON_E_NO_MORE_EVENTS if queue empty
 *             WIN11MON_E_BUFFER_TOO_SMALL if buffer too small
 */
WIN11MON_API HRESULT Win11MonFetchEvents(
    _In_ HWIN11MON Handle,
    _Out_writes_bytes_to_(BufferSize, *BytesFetched) PVOID Buffer,
    _In_ DWORD BufferSize, _Out_ DWORD* BytesFetched, _Out_ DWORD* EventCount);

/*==========================================================================
 * Public API - IoRing Enumeration
 *=========================================================================*/

/**
 * @function   Win11MonEnumerateIoRings
 * @purpose    Enumerate all IoRing handles in the system
 * @param[in]  Handle - Valid driver handle
 * @param[out] Buffer - Buffer to receive IoRing info
 * @param[in]  MaxEntries - Maximum entries buffer can hold
 * @param[out] EntriesFound - Actual entries returned
 * @returns    S_OK on success
 *             WIN11MON_E_NOT_SUPPORTED if capability not available
 */
WIN11MON_API HRESULT Win11MonEnumerateIoRings(
    _In_ HWIN11MON Handle,
    _Out_writes_to_(MaxEntries, *EntriesFound) PWIN11MON_IORING_INFO Buffer,
    _In_ DWORD MaxEntries, _Out_ DWORD* EntriesFound);

/*==========================================================================
 * Public API - Ring Buffer
 *=========================================================================*/

/**
 * @function   Win11MonGetRingBufferStats
 * @purpose    Get ring buffer telemetry statistics
 * @param[in]  Handle - Valid driver handle
 * @param[out] Stats - Receives ring buffer statistics
 * @returns    S_OK on success
 */
WIN11MON_API HRESULT Win11MonGetRingBufferStats(
    _In_ HWIN11MON Handle, _Out_ PWIN11MON_RINGBUF_STATS Stats);

/**
 * @function   Win11MonSnapshotRingBuffer
 * @purpose    Non-destructive snapshot of ring buffer events
 * @param[in]  Handle - Valid driver handle
 * @param[out] Buffer - Buffer to receive snapshot
 * @param[in]  BufferSize - Size of buffer in bytes
 * @param[out] BytesWritten - Actual bytes written
 * @returns    S_OK on success
 *             WIN11MON_E_BUFFER_TOO_SMALL if buffer too small
 */
WIN11MON_API HRESULT Win11MonSnapshotRingBuffer(
    _In_ HWIN11MON Handle,
    _Out_writes_bytes_to_(BufferSize, *BytesWritten) PVOID Buffer,
    _In_ DWORD BufferSize, _Out_ DWORD* BytesWritten);

/**
 * @function   Win11MonClearRingBuffer
 * @purpose    Clear all events from ring buffer
 * @param[in]  Handle - Valid driver handle
 * @returns    S_OK on success
 */
WIN11MON_API HRESULT Win11MonClearRingBuffer(_In_ HWIN11MON Handle);

/*==========================================================================
 * Public API - Offset Status
 *=========================================================================*/

/**
 * @function   Win11MonGetOffsetStatus
 * @purpose    Get offset resolution status
 * @param[in]  Handle - Valid driver handle
 * @param[out] Status - Receives offset status
 * @returns    S_OK on success
 */
WIN11MON_API HRESULT Win11MonGetOffsetStatus(
    _In_ HWIN11MON Handle, _Out_ PWIN11MON_OFFSET_STATUS Status);

/*==========================================================================
 * Public API - Configuration
 *=========================================================================*/

/**
 * @function   Win11MonSetMaskPolicy
 * @purpose    Set address masking policy
 * @param[in]  Handle - Valid driver handle
 * @param[in]  Policy - Mask policy to set
 * @returns    S_OK on success
 */
WIN11MON_API HRESULT Win11MonSetMaskPolicy(_In_ HWIN11MON Handle,
                                           _In_ WIN11MON_MASK_POLICY Policy);

/*==========================================================================
 * Public API - Async Operations
 *=========================================================================*/

/**
 * @function   Win11MonStartEventMonitor
 * @purpose    Start asynchronous event monitoring with callback
 * @param[in]  Handle - Valid driver handle
 * @param[in]  Callback - Function to call for each event
 * @param[in]  Context - User context passed to callback
 * @param[in]  PollIntervalMs - Polling interval in milliseconds
 * @returns    S_OK on success
 */
WIN11MON_API HRESULT Win11MonStartEventMonitor(
    _In_ HWIN11MON Handle, _In_ WIN11MON_EVENT_CALLBACK Callback,
    _In_opt_ PVOID Context, _In_ DWORD PollIntervalMs);

/**
 * @function   Win11MonStopEventMonitor
 * @purpose    Stop asynchronous event monitoring
 * @param[in]  Handle - Valid driver handle
 * @returns    S_OK on success
 */
WIN11MON_API HRESULT Win11MonStopEventMonitor(_In_ HWIN11MON Handle);

/*==========================================================================
 * Public API - Error Handling
 *=========================================================================*/

/**
 * @function   Win11MonGetErrorMessage
 * @purpose    Get human-readable error message
 * @param[in]  ErrorCode - HRESULT error code
 * @returns    Static string describing error
 */
WIN11MON_API const WCHAR* Win11MonGetErrorMessage(_In_ HRESULT ErrorCode);

#ifdef __cplusplus
}
#endif

#endif /* WIN11MON_CLIENT_H */
