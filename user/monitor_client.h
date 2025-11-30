#pragma once

/*
 * monitor_client.h – User-mode binding library for Win11MonitorMgr driver
 *
 * Thin, production-oriented wrapper around the kernel IOCTL surface defined in
 * win11_monitor_mgr.h. Exposes a small set of synchronous C APIs using Win32
 * HANDLE/DWORD types while reusing the kernel data structures for settings,
 * statistics, and telemetry blobs.
 */

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Public device name (DOS link) shared with the kernel driver */

/* Forward declarations from the kernel header.
 * The project should ensure win11_monitor_public.h is in the include path.
 */
#include "win11_monitor_public.h"

/* Open/close -------------------------------------------------------------- */

DWORD MonOpen(_Out_ HANDLE* phMon);

VOID MonClose(_In_opt_ HANDLE hMon);

/* Capability & version ---------------------------------------------------- */

DWORD MonGetVersion(_In_ HANDLE hMon, _Out_ ULONG* pVersion);

DWORD MonGetCapabilities(_In_ HANDLE hMon, _Out_ ULONG* pCaps);

/* Configuration & control ------------------------------------------------- */

DWORD MonEnable(_In_ HANDLE hMon, _In_ const MONITOR_SETTINGS* Settings);

DWORD MonDisable(_In_ HANDLE hMon);

DWORD MonSetTelemetry(_In_ HANDLE hMon, _In_ BOOL Enable);

DWORD MonSetEncryption(_In_ HANDLE hMon, _In_ BOOL Enable);

DWORD MonScanNow(_In_ HANDLE hMon);

/* Telemetry consumption --------------------------------------------------- */

DWORD MonGetStats(_In_ HANDLE hMon, _Out_ MONITOR_STATS* Stats);

DWORD MonFetchEvent(
    _In_ HANDLE hMon,
    _Out_writes_bytes_(BufSize) EVENT_BLOB* Buf,
    _In_ ULONG BufSize,
    _Out_ ULONG* BytesReturned
    );

/* MC parse helper (for privileged diagnostics tools) ---------------------- */

#ifdef __cplusplus
} /* extern "C" */
#endif
