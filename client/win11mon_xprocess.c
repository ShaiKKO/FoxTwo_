/*
 * Win11Mon Cross-Process Detection Client API - Implementation
 *
 * Author: Colin MacRitchie | ziX Labs
 * Organization: ziX Labs - Security Research Division
 * File: win11mon_xprocess.c
 * Version: 1.0
 * Date: 2025-11-30
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and confidential.
 *   Redistribution or disclosure without prior written consent is prohibited.
 *
 * Summary
 * -------
 * User-mode client implementation for cross-process detection APIs.
 * Communicates with win11_monitor.sys via DeviceIoControl.
 */

#include <windows.h>
#include "win11mon_xprocess.h"

#pragma warning(push)
#pragma warning(disable: 4201) /* nameless struct/union */

/*--------------------------------------------------------------------------
 * IOCTL Definitions (must match kernel definitions)
 *-------------------------------------------------------------------------*/
#define WIN11MON_IOCTL_BASE             0x800
#define FILE_DEVICE_WIN11MON            FILE_DEVICE_UNKNOWN

/* Cross-Process Detection IOCTLs (0x50-0x57 range) */
#define IOCTL_MONITOR_XP_GET_SHARED     \
    CTL_CODE(FILE_DEVICE_WIN11MON, WIN11MON_IOCTL_BASE + 0x50, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_MONITOR_XP_GET_TREE       \
    CTL_CODE(FILE_DEVICE_WIN11MON, WIN11MON_IOCTL_BASE + 0x51, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_MONITOR_XP_SCAN_SECTIONS  \
    CTL_CODE(FILE_DEVICE_WIN11MON, WIN11MON_IOCTL_BASE + 0x52, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_MONITOR_XP_GET_ALERTS     \
    CTL_CODE(FILE_DEVICE_WIN11MON, WIN11MON_IOCTL_BASE + 0x53, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_MONITOR_XP_GET_STATS      \
    CTL_CODE(FILE_DEVICE_WIN11MON, WIN11MON_IOCTL_BASE + 0x54, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_MONITOR_XP_GET_CONFIG     \
    CTL_CODE(FILE_DEVICE_WIN11MON, WIN11MON_IOCTL_BASE + 0x55, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_MONITOR_XP_SET_CONFIG     \
    CTL_CODE(FILE_DEVICE_WIN11MON, WIN11MON_IOCTL_BASE + 0x56, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_MONITOR_XP_SCAN_NOW       \
    CTL_CODE(FILE_DEVICE_WIN11MON, WIN11MON_IOCTL_BASE + 0x57, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/*--------------------------------------------------------------------------
 * Static String Tables
 *-------------------------------------------------------------------------*/
static const WCHAR* g_AlertTypeStrings[] = {
    L"None",
    L"Shared IoRing",
    L"Unrelated Sharing",
    L"Cross-Integrity Share",
    L"System IoRing Access",
    L"Handle Duplication",
    L"Section Sharing",
    L"Inheritance Anomaly",
    L"Unknown"
};

static const WCHAR* g_SeverityStrings[] = {
    L"Info",
    L"Low",
    L"Medium",
    L"High",
    L"Critical"
};

static const WCHAR* g_RuleStrings[] = {
    L"Unknown",
    L"Unrelated IoRing Sharing (T1055)",
    L"System IoRing From User (T1068)",
    L"Cross-Integrity IoRing (T1548)",
    L"Section IoRing Buffer (T1055)",
    L"Unexpected Inheritance (T1055)",
    L"Rapid Duplication (T1499)"
};

static const WCHAR* g_IntegrityStrings[] = {
    L"Untrusted",
    L"Low",
    L"Medium",
    L"Medium+",
    L"High",
    L"System",
    L"Protected"
};

/*--------------------------------------------------------------------------
 * Internal Helper
 *-------------------------------------------------------------------------*/
static DWORD
XpIoctl(
    _In_ HANDLE hDevice,
    _In_ DWORD IoCtlCode,
    _In_opt_ LPVOID pInput,
    _In_ DWORD InputSize,
    _Out_opt_ LPVOID pOutput,
    _In_ DWORD OutputSize,
    _Out_opt_ DWORD* pBytesReturned
)
{
    DWORD bytesReturned = 0;
    BOOL success;

    if (hDevice == NULL || hDevice == INVALID_HANDLE_VALUE) {
        return ERROR_INVALID_HANDLE;
    }

    success = DeviceIoControl(
        hDevice,
        IoCtlCode,
        pInput,
        InputSize,
        pOutput,
        OutputSize,
        &bytesReturned,
        NULL
    );

    if (pBytesReturned != NULL) {
        *pBytesReturned = bytesReturned;
    }

    if (!success) {
        return GetLastError();
    }

    return ERROR_SUCCESS;
}

/*==========================================================================
 * Shared Object APIs
 *=========================================================================*/

_Use_decl_annotations_
DWORD
WINAPI
Win11MonXpGetSharedObjects(
    HANDLE hDevice,
    PVOID pBuffer,
    DWORD BufferSize,
    DWORD* pBytesWritten
)
{
    DWORD err;

    if (pBuffer == NULL || pBytesWritten == NULL) {
        return ERROR_INVALID_PARAMETER;
    }

    if (BufferSize < sizeof(DWORD) * 2) {
        return ERROR_INSUFFICIENT_BUFFER;
    }

    *pBytesWritten = 0;
    ZeroMemory(pBuffer, BufferSize);

    err = XpIoctl(
        hDevice,
        IOCTL_MONITOR_XP_GET_SHARED,
        NULL,
        0,
        pBuffer,
        BufferSize,
        pBytesWritten
    );

    return err;
}

/*==========================================================================
 * Process Tree APIs
 *=========================================================================*/

_Use_decl_annotations_
DWORD
WINAPI
Win11MonXpGetProcessTree(
    HANDLE hDevice,
    PVOID pBuffer,
    DWORD BufferSize,
    DWORD* pBytesWritten
)
{
    DWORD err;

    if (pBuffer == NULL || pBytesWritten == NULL) {
        return ERROR_INVALID_PARAMETER;
    }

    if (BufferSize < sizeof(DWORD) * 2) {
        return ERROR_INSUFFICIENT_BUFFER;
    }

    *pBytesWritten = 0;
    ZeroMemory(pBuffer, BufferSize);

    err = XpIoctl(
        hDevice,
        IOCTL_MONITOR_XP_GET_TREE,
        NULL,
        0,
        pBuffer,
        BufferSize,
        pBytesWritten
    );

    return err;
}

/*==========================================================================
 * Section Scanning APIs
 *=========================================================================*/

_Use_decl_annotations_
DWORD
WINAPI
Win11MonXpScanSections(
    HANDLE hDevice,
    DWORD ProcessId,
    PVOID pBuffer,
    DWORD BufferSize,
    DWORD* pBytesWritten
)
{
    ULONG64 input;
    DWORD err;

    if (pBuffer == NULL || pBytesWritten == NULL) {
        return ERROR_INVALID_PARAMETER;
    }

    if (BufferSize < sizeof(DWORD) * 2) {
        return ERROR_INSUFFICIENT_BUFFER;
    }

    *pBytesWritten = 0;
    ZeroMemory(pBuffer, BufferSize);
    input = (ULONG64)ProcessId;

    err = XpIoctl(
        hDevice,
        IOCTL_MONITOR_XP_SCAN_SECTIONS,
        &input,
        sizeof(input),
        pBuffer,
        BufferSize,
        pBytesWritten
    );

    return err;
}

/*==========================================================================
 * Alert APIs
 *=========================================================================*/

_Use_decl_annotations_
DWORD
WINAPI
Win11MonXpGetAlerts(
    HANDLE hDevice,
    PVOID pBuffer,
    DWORD BufferSize,
    DWORD* pBytesWritten
)
{
    DWORD err;

    if (pBuffer == NULL || pBytesWritten == NULL) {
        return ERROR_INVALID_PARAMETER;
    }

    if (BufferSize < sizeof(DWORD) * 2) {
        return ERROR_INSUFFICIENT_BUFFER;
    }

    *pBytesWritten = 0;
    ZeroMemory(pBuffer, BufferSize);

    err = XpIoctl(
        hDevice,
        IOCTL_MONITOR_XP_GET_ALERTS,
        NULL,
        0,
        pBuffer,
        BufferSize,
        pBytesWritten
    );

    return err;
}

/*==========================================================================
 * Statistics & Configuration APIs
 *=========================================================================*/

_Use_decl_annotations_
DWORD
WINAPI
Win11MonXpGetStats(
    HANDLE hDevice,
    PWIN11MON_XP_STATS pStats
)
{
    DWORD bytesReturned;
    DWORD err;

    if (pStats == NULL) {
        return ERROR_INVALID_PARAMETER;
    }

    ZeroMemory(pStats, sizeof(*pStats));

    err = XpIoctl(
        hDevice,
        IOCTL_MONITOR_XP_GET_STATS,
        NULL,
        0,
        pStats,
        sizeof(*pStats),
        &bytesReturned
    );

    if (err == ERROR_SUCCESS && bytesReturned < sizeof(*pStats)) {
        return ERROR_INSUFFICIENT_BUFFER;
    }

    return err;
}

_Use_decl_annotations_
DWORD
WINAPI
Win11MonXpGetConfig(
    HANDLE hDevice,
    PWIN11MON_XP_CONFIG pConfig
)
{
    DWORD bytesReturned;
    DWORD err;

    if (pConfig == NULL) {
        return ERROR_INVALID_PARAMETER;
    }

    ZeroMemory(pConfig, sizeof(*pConfig));

    err = XpIoctl(
        hDevice,
        IOCTL_MONITOR_XP_GET_CONFIG,
        NULL,
        0,
        pConfig,
        sizeof(*pConfig),
        &bytesReturned
    );

    if (err == ERROR_SUCCESS && bytesReturned < sizeof(*pConfig)) {
        return ERROR_INSUFFICIENT_BUFFER;
    }

    return err;
}

_Use_decl_annotations_
DWORD
WINAPI
Win11MonXpSetConfig(
    HANDLE hDevice,
    const WIN11MON_XP_CONFIG* pConfig
)
{
    DWORD bytesReturned;

    if (pConfig == NULL) {
        return ERROR_INVALID_PARAMETER;
    }

    return XpIoctl(
        hDevice,
        IOCTL_MONITOR_XP_SET_CONFIG,
        (LPVOID)pConfig,
        sizeof(*pConfig),
        NULL,
        0,
        &bytesReturned
    );
}

_Use_decl_annotations_
DWORD
WINAPI
Win11MonXpScanNow(
    HANDLE hDevice
)
{
    DWORD bytesReturned;

    return XpIoctl(
        hDevice,
        IOCTL_MONITOR_XP_SCAN_NOW,
        NULL,
        0,
        NULL,
        0,
        &bytesReturned
    );
}

/*==========================================================================
 * Helper Functions
 *=========================================================================*/

_Use_decl_annotations_
const WCHAR*
WINAPI
Win11MonXpAlertTypeToString(
    WIN11MON_XP_ALERT_TYPE AlertType
)
{
    if (AlertType >= Win11MonXpAlert_Max) {
        return g_AlertTypeStrings[Win11MonXpAlert_Max];
    }
    return g_AlertTypeStrings[AlertType];
}

_Use_decl_annotations_
const WCHAR*
WINAPI
Win11MonXpSeverityToString(
    WIN11MON_XP_SEVERITY Severity
)
{
    if (Severity > Win11MonXpSeverity_Critical) {
        return L"Unknown";
    }
    return g_SeverityStrings[Severity];
}

_Use_decl_annotations_
const WCHAR*
WINAPI
Win11MonXpRuleIdToString(
    WIN11MON_XP_RULE_ID RuleId
)
{
    if (RuleId == Win11MonXpRule_None) {
        return g_RuleStrings[0];
    }
    if (RuleId >= Win11MonXpRule_UnrelatedIoRingSharing &&
        RuleId <= Win11MonXpRule_RapidDuplication) {
        return g_RuleStrings[RuleId - Win11MonXpRule_UnrelatedIoRingSharing + 1];
    }
    return g_RuleStrings[0];
}

_Use_decl_annotations_
const WCHAR*
WINAPI
Win11MonXpIntegrityToString(
    DWORD IntegrityLevel
)
{
    /* Integrity levels are RIDs: 0x0000, 0x1000, 0x2000, etc. */
    if (IntegrityLevel < 0x1000) {
        return g_IntegrityStrings[0];  /* Untrusted */
    } else if (IntegrityLevel < 0x2000) {
        return g_IntegrityStrings[1];  /* Low */
    } else if (IntegrityLevel < 0x2100) {
        return g_IntegrityStrings[2];  /* Medium */
    } else if (IntegrityLevel < 0x3000) {
        return g_IntegrityStrings[3];  /* Medium+ */
    } else if (IntegrityLevel < 0x4000) {
        return g_IntegrityStrings[4];  /* High */
    } else if (IntegrityLevel < 0x5000) {
        return g_IntegrityStrings[5];  /* System */
    } else {
        return g_IntegrityStrings[6];  /* Protected */
    }
}

#pragma warning(pop)
