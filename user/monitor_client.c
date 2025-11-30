#include "monitor_client.h"

/**
 * @function   MonOpen
 * @purpose    Opens a handle to the kernel monitor device via WIN11MON_DOSLINK_U
 * @precondition phMon non-NULL; driver service started and symlink available
 * @postcondition On success, *phMon is a valid handle; caller must MonClose
 * @thread-safety Re-entrant; no shared state modified
 * @side-effects Opens a file handle to \\.\\Win11MonitorMgr
 */
DWORD MonOpen(HANDLE* phMon)
{
    if (phMon == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    *phMon = NULL;

    HANDLE h = CreateFileW(
        WIN11MON_DOSLINK_U,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (h == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }

    *phMon = h;
    return ERROR_SUCCESS;
}

/**
 * @function   MonClose
 * @purpose    Closes a monitor handle previously opened by MonOpen
 * @precondition hMon is a valid handle or INVALID_HANDLE_VALUE/NULL
 * @postcondition Handle closed if valid; no other side-effects
 * @thread-safety Re-entrant; no shared state
 * @side-effects Closes OS handle
 */
VOID MonClose(HANDLE hMon)
{
    if (hMon && hMon != INVALID_HANDLE_VALUE) {
        CloseHandle(hMon);
    }
}

/**
 * @function   MonIoctl
 * @purpose    Thin wrapper over DeviceIoControl with optional in/out buffers
 * @precondition hMon valid; buffers (if provided) sized correctly; bytesRet optional
 * @postcondition On success, *bytesRet set to bytes returned
 * @thread-safety Re-entrant; no global state
 * @side-effects Issues synchronous I/O to the driver
 */
static DWORD MonIoctl(
    HANDLE hMon,
    DWORD code,
    void* inBuf,
    DWORD inLen,
    void* outBuf,
    DWORD outLen,
    DWORD* bytesRet
    )
{
    if (hMon == NULL || hMon == INVALID_HANDLE_VALUE) {
        return ERROR_INVALID_HANDLE;
    }

    DWORD localBytes = 0;
    if (bytesRet == NULL) {
        bytesRet = &localBytes;
    }

    BOOL ok = DeviceIoControl(
        hMon,
        code,
        inBuf,
        inLen,
        outBuf,
        outLen,
        bytesRet,
        NULL);
    if (!ok) {
        return GetLastError();
    }

    return ERROR_SUCCESS;
}

/**
 * @function   MonGetVersion
 * @purpose    Retrieves driver version (ULONG packed)
 * @precondition hMon valid; pVersion non-NULL
 * @postcondition *pVersion set on success
 * @thread-safety Re-entrant
 * @side-effects None
 */
DWORD MonGetVersion(HANDLE hMon, ULONG* pVersion)
{
    if (pVersion == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    *pVersion = 0;

    DWORD bytes = 0;
    DWORD err = MonIoctl(hMon, IOCTL_MONITOR_GET_VERSION, NULL, 0, pVersion, sizeof(*pVersion), &bytes);
    if (err != ERROR_SUCCESS) {
        return err;
    }
    if (bytes < sizeof(*pVersion)) {
        return ERROR_GEN_FAILURE;
    }
    return ERROR_SUCCESS;
}

/**
 * @function   MonGetCapabilities
 * @purpose    Retrieves driver capability bitmap
 * @precondition hMon valid; pCaps non-NULL
 * @postcondition *pCaps set on success
 * @thread-safety Re-entrant
 * @side-effects None
 */
DWORD MonGetCapabilities(HANDLE hMon, ULONG* pCaps)
{
    if (pCaps == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    *pCaps = 0;

    DWORD bytes = 0;
    DWORD err = MonIoctl(hMon, IOCTL_MONITOR_GET_CAPABILITIES, NULL, 0, pCaps, sizeof(*pCaps), &bytes);
    if (err != ERROR_SUCCESS) {
        return err;
    }
    if (bytes < sizeof(*pCaps)) {
        return ERROR_GEN_FAILURE;
    }
    return ERROR_SUCCESS;
}

/**
 * @function   MonEnable
 * @purpose    Enables monitoring with provided settings
 * @precondition hMon valid; Settings non-NULL
 * @postcondition Driver configured; no output buffer
 * @thread-safety Re-entrant
 * @side-effects Sends IOCTL_MONITOR_ENABLE
 */
DWORD MonEnable(HANDLE hMon, const MONITOR_SETTINGS* Settings)
{
    if (Settings == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    MONITOR_SETTINGS s = *Settings;
    s.Size = sizeof(s);

    DWORD bytes = 0;
    return MonIoctl(hMon, IOCTL_MONITOR_ENABLE, &s, sizeof(s), NULL, 0, &bytes);
}

/**
 * @function   MonDisable
 * @purpose    Disables monitoring
 * @precondition hMon valid
 * @postcondition Monitoring disabled
 * @thread-safety Re-entrant
 * @side-effects Sends IOCTL_MONITOR_DISABLE
 */
DWORD MonDisable(HANDLE hMon)
{
    DWORD bytes = 0;
    return MonIoctl(hMon, IOCTL_MONITOR_DISABLE, NULL, 0, NULL, 0, &bytes);
}

/**
 * @function   MonSetTelemetry
 * @purpose    Enables/disables telemetry emission
 * @precondition hMon valid
 * @postcondition Telemetry toggled per flag
 * @thread-safety Re-entrant
 * @side-effects Sends IOCTL_MONITOR_SET_TELEMETRY
 */
DWORD MonSetTelemetry(HANDLE hMon, BOOL Enable)
{
    ULONG flag = Enable ? 1u : 0u;
    DWORD bytes = 0;
    return MonIoctl(hMon, IOCTL_MONITOR_SET_TELEMETRY, &flag, sizeof(flag), NULL, 0, &bytes);
}

/**
 * @function   MonSetEncryption
 * @purpose    Enables/disables encryption stub
 * @precondition hMon valid
 * @postcondition Encryption flag toggled (stub semantics)
 * @thread-safety Re-entrant
 * @side-effects Sends IOCTL_MONITOR_SET_ENCRYPTION
 */
DWORD MonSetEncryption(HANDLE hMon, BOOL Enable)
{
    ULONG flag = Enable ? 1u : 0u;
    DWORD bytes = 0;
    return MonIoctl(hMon, IOCTL_MONITOR_SET_ENCRYPTION, &flag, sizeof(flag), NULL, 0, &bytes);
}

/**
 * @function   MonScanNow
 * @purpose    Triggers an immediate kernel pool scan
 * @precondition hMon valid
 * @postcondition Scan scheduled/executed by driver
 * @thread-safety Re-entrant
 * @side-effects Sends IOCTL_MONITOR_SCAN_NOW
 */
DWORD MonScanNow(HANDLE hMon)
{
    DWORD bytes = 0;
    return MonIoctl(hMon, IOCTL_MONITOR_SCAN_NOW, NULL, 0, NULL, 0, &bytes);
}

/**
 * @function   MonGetStats
 * @purpose    Retrieves current statistics from the driver
 * @precondition hMon valid; Stats non-NULL
 * @postcondition Stats populated on success
 * @thread-safety Re-entrant
 * @side-effects None
 */
DWORD MonGetStats(HANDLE hMon, MONITOR_STATS* Stats)
{
    if (Stats == NULL) {
        return ERROR_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(*Stats));

    DWORD bytes = 0;
    DWORD err = MonIoctl(hMon, IOCTL_MONITOR_GET_STATS, NULL, 0, Stats, sizeof(*Stats), &bytes);
    if (err != ERROR_SUCCESS) {
        return err;
    }
    if (bytes < sizeof(*Stats)) {
        return ERROR_INSUFFICIENT_BUFFER;
    }
    return ERROR_SUCCESS;
}

/**
 * @function   MonFetchEvent
 * @purpose    Fetches next telemetry event (if any)
 * @precondition hMon valid; Buf non-NULL and >= sizeof(EVENT_BLOB); BytesReturned non-NULL
 * @postcondition On success, Buf filled and *BytesReturned set to payload size
 * @thread-safety Re-entrant
 * @side-effects None
 */
DWORD MonFetchEvent(HANDLE hMon, EVENT_BLOB* Buf, ULONG BufSize, ULONG* BytesReturned)
{
    if (Buf == NULL || BufSize < sizeof(EVENT_BLOB)) {
        return ERROR_INSUFFICIENT_BUFFER;
    }
    if (BytesReturned == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    *BytesReturned = 0;

    DWORD bytes = 0;
    DWORD err = MonIoctl(hMon, IOCTL_MONITOR_FETCH_EVENTS, NULL, 0, Buf, BufSize, &bytes);
    if (err != ERROR_SUCCESS) {
        return err;
    }
    *BytesReturned = bytes;
    return ERROR_SUCCESS;
}
