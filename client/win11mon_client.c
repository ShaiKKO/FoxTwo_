/*
 * Windows 11 Monitor Manager - Usermode Client Library Implementation
 *
 * Author: Colin MacRitchie
 * Organization: ziX Performance Labs
 * File: client/win11mon_client.c
 * Version: 1.0
 * Date: 2025-12-01
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and confidential.
 *   Redistribution or disclosure without prior written consent is prohibited.
 *
 * Summary
 * -------
 * Synchronous API implementation for the Win11 Monitor client library.
 * Uses DeviceIoControl for all driver communication.
 */

#include "win11mon_client.h"
#include <stdio.h>

/*--------------------------------------------------------------------------
 * IOCTL Definitions (mirror from kernel win11_monitor_public.h)
 *-------------------------------------------------------------------------*/
#define WIN11MON_IOCTL_BASE                 0x800

#define IOCTL_MONITOR_GET_VERSION           CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x01, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_GET_CAPABILITIES      CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x02, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_ENABLE                CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x03, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_MONITOR_DISABLE               CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x04, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_MONITOR_GET_STATS             CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x05, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_FETCH_EVENTS          CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x06, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_SET_TELEMETRY         CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x07, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_MONITOR_SET_ENCRYPTION        CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x08, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_MONITOR_SCAN_NOW              CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x09, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_MONITOR_PARSE_IOP_MC          CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x0A, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_MONITOR_GET_OFFSET_STATUS     CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x0B, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_GET_IORING_HANDLES    CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x0C, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_SET_MASK_POLICY       CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x0D, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_MONITOR_GET_RATE_STATS        CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x0E, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_RINGBUF_CONFIGURE     CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x10, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_MONITOR_RINGBUF_SNAPSHOT      CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x11, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_RINGBUF_GET_STATS     CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x12, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_RINGBUF_CLEAR         CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x13, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/*--------------------------------------------------------------------------
 * Device Path
 *-------------------------------------------------------------------------*/
#define WIN11MON_DEVICE_PATH    L"\\\\.\\Win11Monitor"

/*--------------------------------------------------------------------------
 * Internal Handle Structure
 *-------------------------------------------------------------------------*/
typedef struct _WIN11MON_HANDLE {
    HANDLE              DeviceHandle;
    DWORD               Capabilities;
    WIN11MON_VERSION    Version;
    BOOL                AsyncActive;
    HANDLE              AsyncThread;
    WIN11MON_EVENT_CALLBACK AsyncCallback;
    PVOID               AsyncContext;
    DWORD               AsyncPollInterval;
    volatile BOOL       AsyncStopFlag;
    CRITICAL_SECTION    Lock;
} WIN11MON_HANDLE_INTERNAL;

/*--------------------------------------------------------------------------
 * Internal IOCTL Helper
 *-------------------------------------------------------------------------*/
static HRESULT SendIoctl(
    HANDLE Device,
    DWORD IoctlCode,
    PVOID InBuffer,
    DWORD InSize,
    PVOID OutBuffer,
    DWORD OutSize,
    DWORD* BytesReturned
)
{
    DWORD returned = 0;

    BOOL success = DeviceIoControl(
        Device,
        IoctlCode,
        InBuffer,
        InSize,
        OutBuffer,
        OutSize,
        &returned,
        NULL
    );

    if (BytesReturned) {
        *BytesReturned = returned;
    }

    if (!success) {
        DWORD error = GetLastError();
        switch (error) {
        case ERROR_FILE_NOT_FOUND:
            return WIN11MON_E_DRIVER_NOT_FOUND;
        case ERROR_ACCESS_DENIED:
            return WIN11MON_E_ACCESS_DENIED;
        case ERROR_INSUFFICIENT_BUFFER:
        case ERROR_MORE_DATA:
            return WIN11MON_E_BUFFER_TOO_SMALL;
        case ERROR_NOT_SUPPORTED:
            return WIN11MON_E_NOT_SUPPORTED;
        case ERROR_NO_MORE_ITEMS:
            return WIN11MON_E_NO_MORE_EVENTS;
        default:
            return HRESULT_FROM_WIN32(error);
        }
    }

    return S_OK;
}

/*==========================================================================
 * Handle Management
 *=========================================================================*/

WIN11MON_API BOOL Win11MonIsAvailable(VOID)
{
    HANDLE hDevice = CreateFileW(
        WIN11MON_DEVICE_PATH,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    CloseHandle(hDevice);
    return TRUE;
}

WIN11MON_API HRESULT Win11MonOpen(HWIN11MON* Handle)
{
    if (Handle == NULL) {
        return E_INVALIDARG;
    }

    *Handle = NULL;

    /* Open device */
    HANDLE hDevice = CreateFileW(
        WIN11MON_DEVICE_PATH,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND) {
            return WIN11MON_E_DRIVER_NOT_FOUND;
        }
        if (error == ERROR_ACCESS_DENIED) {
            return WIN11MON_E_ACCESS_DENIED;
        }
        return HRESULT_FROM_WIN32(error);
    }

    /* Allocate handle structure */
    WIN11MON_HANDLE_INTERNAL* pHandle = (WIN11MON_HANDLE_INTERNAL*)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        sizeof(WIN11MON_HANDLE_INTERNAL)
    );

    if (pHandle == NULL) {
        CloseHandle(hDevice);
        return E_OUTOFMEMORY;
    }

    pHandle->DeviceHandle = hDevice;
    InitializeCriticalSection(&pHandle->Lock);

    /* Query version */
    DWORD versionPacked = 0;
    HRESULT hr = SendIoctl(
        hDevice,
        IOCTL_MONITOR_GET_VERSION,
        NULL, 0,
        &versionPacked, sizeof(versionPacked),
        NULL
    );

    if (SUCCEEDED(hr)) {
        pHandle->Version.Major = (versionPacked >> 24) & 0xFF;
        pHandle->Version.Minor = (versionPacked >> 16) & 0xFF;
        pHandle->Version.Build = versionPacked & 0xFFFF;
    }

    /* Query capabilities */
    hr = SendIoctl(
        hDevice,
        IOCTL_MONITOR_GET_CAPABILITIES,
        NULL, 0,
        &pHandle->Capabilities, sizeof(pHandle->Capabilities),
        NULL
    );

    if (SUCCEEDED(hr)) {
        pHandle->Version.Capabilities = pHandle->Capabilities;
    }

    *Handle = (HWIN11MON)pHandle;
    return S_OK;
}

WIN11MON_API VOID Win11MonClose(HWIN11MON Handle)
{
    if (Handle == NULL) {
        return;
    }

    WIN11MON_HANDLE_INTERNAL* pHandle = (WIN11MON_HANDLE_INTERNAL*)Handle;

    /* Stop async monitoring if active */
    if (pHandle->AsyncActive) {
        Win11MonStopEventMonitor(Handle);
    }

    /* Close device */
    if (pHandle->DeviceHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(pHandle->DeviceHandle);
    }

    DeleteCriticalSection(&pHandle->Lock);

    HeapFree(GetProcessHeap(), 0, pHandle);
}

/*==========================================================================
 * Version and Capabilities
 *=========================================================================*/

WIN11MON_API HRESULT Win11MonGetVersion(HWIN11MON Handle, PWIN11MON_VERSION Version)
{
    if (Handle == NULL || Version == NULL) {
        return E_INVALIDARG;
    }

    WIN11MON_HANDLE_INTERNAL* pHandle = (WIN11MON_HANDLE_INTERNAL*)Handle;
    *Version = pHandle->Version;
    return S_OK;
}

WIN11MON_API BOOL Win11MonHasCapability(HWIN11MON Handle, DWORD CapabilityFlag)
{
    if (Handle == NULL) {
        return FALSE;
    }

    WIN11MON_HANDLE_INTERNAL* pHandle = (WIN11MON_HANDLE_INTERNAL*)Handle;
    return (pHandle->Capabilities & CapabilityFlag) != 0;
}

/*==========================================================================
 * Monitoring Control
 *=========================================================================*/

WIN11MON_API HRESULT Win11MonEnable(HWIN11MON Handle, const WIN11MON_CONFIG* Config)
{
    if (Handle == NULL || Config == NULL) {
        return E_INVALIDARG;
    }

    if (Config->Size != sizeof(WIN11MON_CONFIG)) {
        return E_INVALIDARG;
    }

    WIN11MON_HANDLE_INTERNAL* pHandle = (WIN11MON_HANDLE_INTERNAL*)Handle;

    /* Build kernel MONITOR_SETTINGS structure */
    struct {
        DWORD Size;
        BYTE EnableMonitoring;
        BYTE EnableTelemetry;
        BYTE EnableEncryption;
        BYTE Reserved;
        DWORD RateLimitPerSec;
    } settings = {0};

    settings.Size = sizeof(settings);
    settings.EnableMonitoring = Config->EnableMonitoring ? 1 : 0;
    settings.EnableTelemetry = Config->EnableTelemetry ? 1 : 0;
    settings.EnableEncryption = Config->EnableEncryption ? 1 : 0;
    settings.RateLimitPerSec = Config->RateLimitPerSec;

    return SendIoctl(
        pHandle->DeviceHandle,
        IOCTL_MONITOR_ENABLE,
        &settings, sizeof(settings),
        NULL, 0,
        NULL
    );
}

WIN11MON_API HRESULT Win11MonDisable(HWIN11MON Handle)
{
    if (Handle == NULL) {
        return E_INVALIDARG;
    }

    WIN11MON_HANDLE_INTERNAL* pHandle = (WIN11MON_HANDLE_INTERNAL*)Handle;

    return SendIoctl(
        pHandle->DeviceHandle,
        IOCTL_MONITOR_DISABLE,
        NULL, 0,
        NULL, 0,
        NULL
    );
}

WIN11MON_API HRESULT Win11MonTriggerScan(HWIN11MON Handle)
{
    if (Handle == NULL) {
        return E_INVALIDARG;
    }

    WIN11MON_HANDLE_INTERNAL* pHandle = (WIN11MON_HANDLE_INTERNAL*)Handle;

    return SendIoctl(
        pHandle->DeviceHandle,
        IOCTL_MONITOR_SCAN_NOW,
        NULL, 0,
        NULL, 0,
        NULL
    );
}

/*==========================================================================
 * Statistics
 *=========================================================================*/

WIN11MON_API HRESULT Win11MonGetStats(HWIN11MON Handle, PWIN11MON_STATS Stats)
{
    if (Handle == NULL || Stats == NULL) {
        return E_INVALIDARG;
    }

    WIN11MON_HANDLE_INTERNAL* pHandle = (WIN11MON_HANDLE_INTERNAL*)Handle;

    /* Kernel structure layout */
    struct {
        DWORD Size;
        DWORD64 TotalAllocations;
        DWORD64 IopMcDetections;
        DWORD64 CrossVmDetections;
        DWORD64 PolicyViolations;
        DWORD64 DroppedEvents;
        DWORD PoolEntryCount;
        DWORD TelemetryEventCount;
        DWORD CurrentRateLimit;
    } kernelStats = {0};

    HRESULT hr = SendIoctl(
        pHandle->DeviceHandle,
        IOCTL_MONITOR_GET_STATS,
        NULL, 0,
        &kernelStats, sizeof(kernelStats),
        NULL
    );

    if (SUCCEEDED(hr)) {
        Stats->Size = sizeof(WIN11MON_STATS);
        Stats->TotalAllocations = kernelStats.TotalAllocations;
        Stats->IopMcDetections = kernelStats.IopMcDetections;
        Stats->CrossVmDetections = kernelStats.CrossVmDetections;
        Stats->PolicyViolations = kernelStats.PolicyViolations;
        Stats->DroppedEvents = kernelStats.DroppedEvents;
        Stats->PoolEntryCount = kernelStats.PoolEntryCount;
        Stats->TelemetryEventCount = kernelStats.TelemetryEventCount;
        Stats->CurrentRateLimit = kernelStats.CurrentRateLimit;
    }

    return hr;
}

WIN11MON_API HRESULT Win11MonGetRateStats(HWIN11MON Handle, PWIN11MON_RATE_STATS Stats)
{
    if (Handle == NULL || Stats == NULL) {
        return E_INVALIDARG;
    }

    WIN11MON_HANDLE_INTERNAL* pHandle = (WIN11MON_HANDLE_INTERNAL*)Handle;

    /* Kernel structure - same layout as WIN11MON_RATE_STATS */
    return SendIoctl(
        pHandle->DeviceHandle,
        IOCTL_MONITOR_GET_RATE_STATS,
        NULL, 0,
        Stats, sizeof(WIN11MON_RATE_STATS),
        NULL
    );
}

/*==========================================================================
 * Event Fetching
 *=========================================================================*/

WIN11MON_API HRESULT Win11MonFetchEvents(
    HWIN11MON Handle,
    PVOID Buffer,
    DWORD BufferSize,
    DWORD* BytesFetched,
    DWORD* EventCount
)
{
    if (Handle == NULL || Buffer == NULL || BytesFetched == NULL || EventCount == NULL) {
        return E_INVALIDARG;
    }

    WIN11MON_HANDLE_INTERNAL* pHandle = (WIN11MON_HANDLE_INTERNAL*)Handle;

    *BytesFetched = 0;
    *EventCount = 0;

    HRESULT hr = SendIoctl(
        pHandle->DeviceHandle,
        IOCTL_MONITOR_FETCH_EVENTS,
        NULL, 0,
        Buffer, BufferSize,
        BytesFetched
    );

    if (SUCCEEDED(hr) && *BytesFetched > 0) {
        *EventCount = 1; /* SLIST fetch returns one event at a time */
    }

    return hr;
}

/*==========================================================================
 * IoRing Enumeration
 *=========================================================================*/

WIN11MON_API HRESULT Win11MonEnumerateIoRings(
    HWIN11MON Handle,
    PWIN11MON_IORING_INFO Buffer,
    DWORD MaxEntries,
    DWORD* EntriesFound
)
{
    if (Handle == NULL || Buffer == NULL || EntriesFound == NULL || MaxEntries == 0) {
        return E_INVALIDARG;
    }

    WIN11MON_HANDLE_INTERNAL* pHandle = (WIN11MON_HANDLE_INTERNAL*)Handle;

    *EntriesFound = 0;

    /* Calculate buffer size: header (8 bytes) + entries */
    DWORD headerSize = sizeof(DWORD) * 2;
    DWORD entrySize = sizeof(WIN11MON_IORING_INFO);
    DWORD totalSize = headerSize + (MaxEntries * entrySize);

    BYTE* outBuffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, totalSize);
    if (outBuffer == NULL) {
        return E_OUTOFMEMORY;
    }

    DWORD bytesReturned = 0;
    HRESULT hr = SendIoctl(
        pHandle->DeviceHandle,
        IOCTL_MONITOR_GET_IORING_HANDLES,
        NULL, 0,
        outBuffer, totalSize,
        &bytesReturned
    );

    if (SUCCEEDED(hr) && bytesReturned >= headerSize) {
        DWORD* header = (DWORD*)outBuffer;
        DWORD handleCount = header[1];

        if (handleCount > MaxEntries) {
            handleCount = MaxEntries;
        }

        if (handleCount > 0) {
            memcpy(Buffer, outBuffer + headerSize, handleCount * entrySize);
        }

        *EntriesFound = handleCount;
    }

    HeapFree(GetProcessHeap(), 0, outBuffer);
    return hr;
}

/*==========================================================================
 * Ring Buffer
 *=========================================================================*/

WIN11MON_API HRESULT Win11MonGetRingBufferStats(HWIN11MON Handle, PWIN11MON_RINGBUF_STATS Stats)
{
    if (Handle == NULL || Stats == NULL) {
        return E_INVALIDARG;
    }

    WIN11MON_HANDLE_INTERNAL* pHandle = (WIN11MON_HANDLE_INTERNAL*)Handle;

    return SendIoctl(
        pHandle->DeviceHandle,
        IOCTL_MONITOR_RINGBUF_GET_STATS,
        NULL, 0,
        Stats, sizeof(WIN11MON_RINGBUF_STATS),
        NULL
    );
}

WIN11MON_API HRESULT Win11MonSnapshotRingBuffer(
    HWIN11MON Handle,
    PVOID Buffer,
    DWORD BufferSize,
    DWORD* BytesWritten
)
{
    if (Handle == NULL || Buffer == NULL || BytesWritten == NULL) {
        return E_INVALIDARG;
    }

    WIN11MON_HANDLE_INTERNAL* pHandle = (WIN11MON_HANDLE_INTERNAL*)Handle;

    return SendIoctl(
        pHandle->DeviceHandle,
        IOCTL_MONITOR_RINGBUF_SNAPSHOT,
        NULL, 0,
        Buffer, BufferSize,
        BytesWritten
    );
}

WIN11MON_API HRESULT Win11MonClearRingBuffer(HWIN11MON Handle)
{
    if (Handle == NULL) {
        return E_INVALIDARG;
    }

    WIN11MON_HANDLE_INTERNAL* pHandle = (WIN11MON_HANDLE_INTERNAL*)Handle;

    return SendIoctl(
        pHandle->DeviceHandle,
        IOCTL_MONITOR_RINGBUF_CLEAR,
        NULL, 0,
        NULL, 0,
        NULL
    );
}

/*==========================================================================
 * Offset Status
 *=========================================================================*/

WIN11MON_API HRESULT Win11MonGetOffsetStatus(HWIN11MON Handle, PWIN11MON_OFFSET_STATUS Status)
{
    if (Handle == NULL || Status == NULL) {
        return E_INVALIDARG;
    }

    WIN11MON_HANDLE_INTERNAL* pHandle = (WIN11MON_HANDLE_INTERNAL*)Handle;

    /* Kernel structure */
    struct {
        DWORD Size;
        DWORD WindowsBuildNumber;
        DWORD Method;
        BYTE IoRingOffsetsValid;
        BYTE IopMcOffsetsValid;
        BYTE Reserved[2];
        DWORD IoRingStructureSize;
        DWORD IopMcStructureSize;
    } kernelStatus = {0};

    HRESULT hr = SendIoctl(
        pHandle->DeviceHandle,
        IOCTL_MONITOR_GET_OFFSET_STATUS,
        NULL, 0,
        &kernelStatus, sizeof(kernelStatus),
        NULL
    );

    if (SUCCEEDED(hr)) {
        Status->Size = sizeof(WIN11MON_OFFSET_STATUS);
        Status->WindowsBuildNumber = kernelStatus.WindowsBuildNumber;
        Status->Method = (WIN11MON_OFFSET_METHOD)kernelStatus.Method;
        Status->IoRingOffsetsValid = kernelStatus.IoRingOffsetsValid != 0;
        Status->IopMcOffsetsValid = kernelStatus.IopMcOffsetsValid != 0;
        Status->IoRingStructureSize = kernelStatus.IoRingStructureSize;
        Status->IopMcStructureSize = kernelStatus.IopMcStructureSize;
    }

    return hr;
}

/*==========================================================================
 * Configuration
 *=========================================================================*/

WIN11MON_API HRESULT Win11MonSetMaskPolicy(HWIN11MON Handle, WIN11MON_MASK_POLICY Policy)
{
    if (Handle == NULL) {
        return E_INVALIDARG;
    }

    WIN11MON_HANDLE_INTERNAL* pHandle = (WIN11MON_HANDLE_INTERNAL*)Handle;

    struct {
        DWORD Size;
        DWORD Policy;
    } input = {0};

    input.Size = sizeof(input);
    input.Policy = (DWORD)Policy;

    return SendIoctl(
        pHandle->DeviceHandle,
        IOCTL_MONITOR_SET_MASK_POLICY,
        &input, sizeof(input),
        NULL, 0,
        NULL
    );
}

/*==========================================================================
 * Async Operations
 *=========================================================================*/

static DWORD WINAPI AsyncEventThread(LPVOID lpParam)
{
    WIN11MON_HANDLE_INTERNAL* pHandle = (WIN11MON_HANDLE_INTERNAL*)lpParam;

    BYTE eventBuffer[4096];

    while (!pHandle->AsyncStopFlag) {
        DWORD bytesReturned = 0;

        HRESULT hr = SendIoctl(
            pHandle->DeviceHandle,
            IOCTL_MONITOR_FETCH_EVENTS,
            NULL, 0,
            eventBuffer, sizeof(eventBuffer),
            &bytesReturned
        );

        if (SUCCEEDED(hr) && bytesReturned > 0 && pHandle->AsyncCallback) {
            pHandle->AsyncCallback(
                pHandle->AsyncContext,
                eventBuffer,
                bytesReturned
            );
        }

        Sleep(pHandle->AsyncPollInterval);
    }

    return 0;
}

WIN11MON_API HRESULT Win11MonStartEventMonitor(
    HWIN11MON Handle,
    WIN11MON_EVENT_CALLBACK Callback,
    PVOID Context,
    DWORD PollIntervalMs
)
{
    if (Handle == NULL || Callback == NULL || PollIntervalMs == 0) {
        return E_INVALIDARG;
    }

    WIN11MON_HANDLE_INTERNAL* pHandle = (WIN11MON_HANDLE_INTERNAL*)Handle;

    EnterCriticalSection(&pHandle->Lock);

    if (pHandle->AsyncActive) {
        LeaveCriticalSection(&pHandle->Lock);
        return WIN11MON_E_ASYNC_PENDING;
    }

    pHandle->AsyncCallback = Callback;
    pHandle->AsyncContext = Context;
    pHandle->AsyncPollInterval = PollIntervalMs;
    pHandle->AsyncStopFlag = FALSE;

    pHandle->AsyncThread = CreateThread(
        NULL,
        0,
        AsyncEventThread,
        pHandle,
        0,
        NULL
    );

    if (pHandle->AsyncThread == NULL) {
        LeaveCriticalSection(&pHandle->Lock);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    pHandle->AsyncActive = TRUE;

    LeaveCriticalSection(&pHandle->Lock);
    return S_OK;
}

WIN11MON_API HRESULT Win11MonStopEventMonitor(HWIN11MON Handle)
{
    if (Handle == NULL) {
        return E_INVALIDARG;
    }

    WIN11MON_HANDLE_INTERNAL* pHandle = (WIN11MON_HANDLE_INTERNAL*)Handle;

    EnterCriticalSection(&pHandle->Lock);

    if (!pHandle->AsyncActive) {
        LeaveCriticalSection(&pHandle->Lock);
        return S_OK;
    }

    pHandle->AsyncStopFlag = TRUE;

    LeaveCriticalSection(&pHandle->Lock);

    /* Wait for thread to exit */
    if (pHandle->AsyncThread != NULL) {
        WaitForSingleObject(pHandle->AsyncThread, 5000);
        CloseHandle(pHandle->AsyncThread);
        pHandle->AsyncThread = NULL;
    }

    EnterCriticalSection(&pHandle->Lock);
    pHandle->AsyncActive = FALSE;
    pHandle->AsyncCallback = NULL;
    pHandle->AsyncContext = NULL;
    LeaveCriticalSection(&pHandle->Lock);

    return S_OK;
}

/*==========================================================================
 * Error Handling
 *=========================================================================*/

WIN11MON_API const WCHAR* Win11MonGetErrorMessage(HRESULT ErrorCode)
{
    switch (ErrorCode) {
    case S_OK:
        return L"Success";
    case WIN11MON_E_DRIVER_NOT_FOUND:
        return L"Win11 Monitor driver not found or not loaded";
    case WIN11MON_E_VERSION_MISMATCH:
        return L"Driver version mismatch";
    case WIN11MON_E_ACCESS_DENIED:
        return L"Access denied - administrator privileges required";
    case WIN11MON_E_INVALID_HANDLE:
        return L"Invalid handle";
    case WIN11MON_E_BUFFER_TOO_SMALL:
        return L"Buffer too small";
    case WIN11MON_E_NOT_SUPPORTED:
        return L"Operation not supported";
    case WIN11MON_E_NO_MORE_EVENTS:
        return L"No more events available";
    case WIN11MON_E_ASYNC_PENDING:
        return L"Async operation already in progress";
    case E_INVALIDARG:
        return L"Invalid argument";
    case E_OUTOFMEMORY:
        return L"Out of memory";
    default:
        return L"Unknown error";
    }
}
