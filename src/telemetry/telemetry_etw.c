/*
 * ETW TraceLogging Provider – Implementation
 *
 * Author: Colin MacRitchie
 * Organization: ziX Performance Labs
 * File: telemetry_etw.c
 * Version: 1.1
 * Date: 2025-12-01
 * Copyright:
 *   © 2025 ziX Performance Labs. All rights reserved. Proprietary and confidential.
 *   Redistribution or disclosure without prior written consent is prohibited.
 *
 * Summary
 * -------
 * Implements ETW TraceLogging provider for structured security event
 * emission. Events include MITRE ATT&CK technique tagging for SIEM
 * integration.
 *
 * Consumer Example (PowerShell):
 *   logman create trace Win11MonTrace -p "{7E8B92A1-5C3D-4F2E-B8A9-1D2E3F4A5B6C}" -o trace.etl -ets
 *   logman stop Win11MonTrace -ets
 */

#include <ntddk.h>
#include <evntrace.h>
#include "telemetry_etw.h"
#include "monitor_internal.h"

#pragma warning(push)
#pragma warning(disable: 4201 4214)

/*--------------------------------------------------------------------------
 * TraceLogging Provider Definition
 *
 * When TraceLogging is available, we use the full API.
 * Otherwise, we provide a stub implementation using EtwWrite directly.
 *-------------------------------------------------------------------------*/

#if MON_ETW_TRACELOGGING_AVAILABLE

/*
 * Define provider in non-paged segment.
 * TraceLogging requires the provider to remain in memory.
 */
#pragma data_seg("NONPAGE")
TRACELOGGING_DEFINE_PROVIDER(
    g_hMonitorEtwProvider,
    MON_ETW_PROVIDER_NAME,
    /* GUID: {7E8B92A1-5C3D-4F2E-B8A9-1D2E3F4A5B6C} */
    (0x7e8b92a1, 0x5c3d, 0x4f2e, 0xb8, 0xa9, 0x1d, 0x2e, 0x3f, 0x4a, 0x5b, 0x6c)
);
#pragma data_seg()

static BOOLEAN g_EtwInitialized = FALSE;

#else /* !MON_ETW_TRACELOGGING_AVAILABLE */

/*
 * Legacy implementation for older WDK versions.
 * Uses direct EtwRegister/EtwWrite with EVENT_DESCRIPTOR.
 */
static REGHANDLE g_EtwRegHandle = 0;
static BOOLEAN g_EtwInitialized = FALSE;

/*
 * Legacy ETW helper for writing events without TraceLogging.
 * EVENT_DESCRIPTOR fields:
 *   Id, Version, Channel, Level, Opcode, Task, Keyword
 */
static FORCEINLINE VOID
MonEtwWriteLegacy(
    _In_ USHORT EventId,
    _In_ UCHAR Level,
    _In_ ULONGLONG Keyword,
    _In_reads_bytes_opt_(DataCount * sizeof(EVENT_DATA_DESCRIPTOR)) PEVENT_DATA_DESCRIPTOR Data,
    _In_ ULONG DataCount
)
{
    if (g_EtwRegHandle == 0) {
        return;
    }

    EVENT_DESCRIPTOR descriptor = {0};
    descriptor.Id = EventId;
    descriptor.Version = 0;
    descriptor.Channel = 0;
    descriptor.Level = Level;
    descriptor.Opcode = 0;
    descriptor.Task = 0;
    descriptor.Keyword = Keyword;

    EtwWrite(g_EtwRegHandle, &descriptor, NULL, DataCount, Data);
}

#endif /* MON_ETW_TRACELOGGING_AVAILABLE */

/*--------------------------------------------------------------------------
 * Public API Implementation
 *-------------------------------------------------------------------------*/

_Use_decl_annotations_
NTSTATUS MonEtwInitialize(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;

#if MON_ETW_TRACELOGGING_AVAILABLE
    status = TraceLoggingRegister(g_hMonitorEtwProvider);
    if (NT_SUCCESS(status)) {
        g_EtwInitialized = TRUE;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[WIN11MON][ETW] Provider registered: %s\n",
            MON_ETW_PROVIDER_NAME);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WIN11MON][ETW] Registration failed: 0x%08X\n", status);
    }
#else
    /* Direct EtwRegister for older WDK */
    status = EtwRegister(
        &MON_ETW_PROVIDER_GUID,
        NULL,   /* EnableCallback */
        NULL,   /* CallbackContext */
        &g_EtwRegHandle
    );

    if (NT_SUCCESS(status)) {
        g_EtwInitialized = TRUE;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[WIN11MON][ETW] Provider registered (legacy mode)\n");
    }
#endif

    return status;
}

_Use_decl_annotations_
VOID MonEtwShutdown(VOID)
{
    if (!g_EtwInitialized) {
        return;
    }

#if MON_ETW_TRACELOGGING_AVAILABLE
    TraceLoggingUnregister(g_hMonitorEtwProvider);
#else
    if (g_EtwRegHandle != 0) {
        EtwUnregister(g_EtwRegHandle);
        g_EtwRegHandle = 0;
    }
#endif

    g_EtwInitialized = FALSE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][ETW] Provider unregistered\n");
}

_Use_decl_annotations_
BOOLEAN MonEtwIsEnabled(VOID)
{
    if (!g_EtwInitialized) {
        return FALSE;
    }

#if MON_ETW_TRACELOGGING_AVAILABLE
    return TraceLoggingProviderEnabled(
        g_hMonitorEtwProvider,
        MON_ETW_LEVEL_VERBOSE,
        0 /* any keyword */
    );
#else
    return g_EtwRegHandle != 0;
#endif
}

/*--------------------------------------------------------------------------
 * Event Logging Implementation
 *-------------------------------------------------------------------------*/

_Use_decl_annotations_
VOID
MonEtwLogCrossVmDetection(
    ULONG ProcessId,
    ULONG ThreadId,
    ULONG64 SuspectAddress,
    UCHAR Severity
)
{
    if (!g_EtwInitialized) {
        return;
    }

    /* B2: Apply address masking before emission */
    ULONG64 maskedAddress = MonMaskAddress(SuspectAddress);

#if MON_ETW_TRACELOGGING_AVAILABLE
    TraceLoggingWrite(
        g_hMonitorEtwProvider,
        "CrossVmDetected",
        TraceLoggingLevel(MON_ETW_LEVEL_WARNING),
        TraceLoggingKeyword(MON_ETW_KEYWORD_DETECTION | MON_ETW_KEYWORD_IORING),
        TraceLoggingUInt32(ProcessId, "ProcessId"),
        TraceLoggingUInt32(ThreadId, "ThreadId"),
        TraceLoggingHexUInt64(maskedAddress, "SuspectAddress"),
        TraceLoggingUInt8(Severity, "Severity"),
        TraceLoggingString(MON_ATTACK_TECHNIQUE_T1068, "ATT_CK_Technique"),
        TraceLoggingString(MON_ATTACK_TACTIC_TA0004, "ATT_CK_Tactic")
    );
#else
    /* Legacy path: Use direct EtwWrite */
    EVENT_DATA_DESCRIPTOR dataDesc[4];
    EventDataDescCreate(&dataDesc[0], &ProcessId, sizeof(ProcessId));
    EventDataDescCreate(&dataDesc[1], &ThreadId, sizeof(ThreadId));
    EventDataDescCreate(&dataDesc[2], &maskedAddress, sizeof(maskedAddress));
    EventDataDescCreate(&dataDesc[3], &Severity, sizeof(Severity));

    MonEtwWriteLegacy(
        (USHORT)MonEtwEvent_CrossVmDetected,
        MON_ETW_LEVEL_WARNING,
        MON_ETW_KEYWORD_DETECTION | MON_ETW_KEYWORD_IORING,
        dataDesc,
        4
    );
#endif

    /* Debug output in all builds for visibility */
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
        "[WIN11MON][ETW] CrossVmDetected: PID=%lu TID=%lu Addr=0x%llX Sev=%u\n",
        ProcessId, ThreadId, maskedAddress, Severity);
}

_Use_decl_annotations_
VOID
MonEtwLogRegBuffersViolation(
    ULONG ProcessId,
    ULONG64 IoRingAddress,
    ULONG64 RegBuffersAddress,
    ULONG ViolationFlags
)
{
    if (!g_EtwInitialized) {
        return;
    }

    /* B2: Apply address masking before emission */
    ULONG64 maskedIoRing = MonMaskAddress(IoRingAddress);
    ULONG64 maskedRegBuf = MonMaskAddress(RegBuffersAddress);

#if MON_ETW_TRACELOGGING_AVAILABLE
    TraceLoggingWrite(
        g_hMonitorEtwProvider,
        "RegBuffersViolation",
        TraceLoggingLevel(MON_ETW_LEVEL_ERROR),
        TraceLoggingKeyword(MON_ETW_KEYWORD_DETECTION | MON_ETW_KEYWORD_IORING),
        TraceLoggingUInt32(ProcessId, "ProcessId"),
        TraceLoggingHexUInt64(maskedIoRing, "IoRingAddress"),
        TraceLoggingHexUInt64(maskedRegBuf, "RegBuffersAddress"),
        TraceLoggingHexUInt32(ViolationFlags, "ViolationFlags"),
        TraceLoggingString(MON_ATTACK_TECHNIQUE_T1068, "ATT_CK_Technique"),
        TraceLoggingString(MON_ATTACK_TACTIC_TA0004, "ATT_CK_Tactic")
    );
#else
    /* Legacy path: Use direct EtwWrite */
    EVENT_DATA_DESCRIPTOR dataDesc[4];
    EventDataDescCreate(&dataDesc[0], &ProcessId, sizeof(ProcessId));
    EventDataDescCreate(&dataDesc[1], &maskedIoRing, sizeof(maskedIoRing));
    EventDataDescCreate(&dataDesc[2], &maskedRegBuf, sizeof(maskedRegBuf));
    EventDataDescCreate(&dataDesc[3], &ViolationFlags, sizeof(ViolationFlags));

    MonEtwWriteLegacy(
        (USHORT)MonEtwEvent_RegBuffersViolation,
        MON_ETW_LEVEL_ERROR,
        MON_ETW_KEYWORD_DETECTION | MON_ETW_KEYWORD_IORING,
        dataDesc,
        4
    );
#endif

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[WIN11MON][ETW] RegBuffersViolation: PID=%lu IoRing=0x%llX "
        "RegBuf=0x%llX Flags=0x%X\n",
        ProcessId, maskedIoRing, maskedRegBuf, ViolationFlags);
}

_Use_decl_annotations_
VOID
MonEtwLogIoRingHandle(
    ULONG ProcessId,
    ULONG64 HandleValue,
    ULONG64 ObjectAddress,
    ULONG AccessMask,
    MON_ETW_EVENT_ID EventType
)
{
    if (!g_EtwInitialized) {
        return;
    }

    UCHAR level = MON_ETW_LEVEL_INFO;
    if (EventType == MonEtwEvent_IoRingHandleSpray ||
        EventType == MonEtwEvent_IoRingHandleDuplicated) {
        level = MON_ETW_LEVEL_WARNING;
    }

    /* B2: Apply address masking before emission */
    ULONG64 maskedObject = MonMaskAddress(ObjectAddress);

#if MON_ETW_TRACELOGGING_AVAILABLE
    TraceLoggingWrite(
        g_hMonitorEtwProvider,
        "IoRingHandleEvent",
        TraceLoggingLevel(level),
        TraceLoggingKeyword(MON_ETW_KEYWORD_IORING | MON_ETW_KEYWORD_HANDLE),
        TraceLoggingUInt32(ProcessId, "ProcessId"),
        TraceLoggingHexUInt64(HandleValue, "HandleValue"),
        TraceLoggingHexUInt64(maskedObject, "ObjectAddress"),
        TraceLoggingHexUInt32(AccessMask, "AccessMask"),
        TraceLoggingUInt32((ULONG)EventType, "EventType")
    );
#else
    /* Legacy path: Use direct EtwWrite */
    ULONG eventTypeVal = (ULONG)EventType;
    EVENT_DATA_DESCRIPTOR dataDesc[5];
    EventDataDescCreate(&dataDesc[0], &ProcessId, sizeof(ProcessId));
    EventDataDescCreate(&dataDesc[1], &HandleValue, sizeof(HandleValue));
    EventDataDescCreate(&dataDesc[2], &maskedObject, sizeof(maskedObject));
    EventDataDescCreate(&dataDesc[3], &AccessMask, sizeof(AccessMask));
    EventDataDescCreate(&dataDesc[4], &eventTypeVal, sizeof(eventTypeVal));

    MonEtwWriteLegacy(
        (USHORT)EventType,
        level,
        MON_ETW_KEYWORD_IORING | MON_ETW_KEYWORD_HANDLE,
        dataDesc,
        5
    );
#endif
}

_Use_decl_annotations_
VOID
MonEtwLogPoolAllocation(
    ULONG PoolTag,
    ULONG64 AllocationSize,
    ULONG64 Address,
    BOOLEAN IsNew
)
{
    if (!g_EtwInitialized) {
        return;
    }

    /* B2: Apply address masking before emission */
    ULONG64 maskedAddress = MonMaskAddress(Address);

#if MON_ETW_TRACELOGGING_AVAILABLE
    TraceLoggingWrite(
        g_hMonitorEtwProvider,
        "PoolAllocation",
        TraceLoggingLevel(MON_ETW_LEVEL_VERBOSE),
        TraceLoggingKeyword(MON_ETW_KEYWORD_POOL),
        TraceLoggingUInt32(PoolTag, "PoolTag"),
        TraceLoggingUInt64(AllocationSize, "AllocationSize"),
        TraceLoggingHexUInt64(maskedAddress, "Address"),
        TraceLoggingBoolean(IsNew, "IsNew")
    );
#else
    /* Legacy path: Use direct EtwWrite */
    UCHAR isNewVal = IsNew ? 1 : 0;
    EVENT_DATA_DESCRIPTOR dataDesc[4];
    EventDataDescCreate(&dataDesc[0], &PoolTag, sizeof(PoolTag));
    EventDataDescCreate(&dataDesc[1], &AllocationSize, sizeof(AllocationSize));
    EventDataDescCreate(&dataDesc[2], &maskedAddress, sizeof(maskedAddress));
    EventDataDescCreate(&dataDesc[3], &isNewVal, sizeof(isNewVal));

    MonEtwWriteLegacy(
        (USHORT)MonEtwEvent_PoolAllocation,
        MON_ETW_LEVEL_VERBOSE,
        MON_ETW_KEYWORD_POOL,
        dataDesc,
        4
    );
#endif
}

_Use_decl_annotations_
VOID
MonEtwLogDriverEvent(
    MON_ETW_EVENT_ID EventId,
    ULONG Capabilities,
    ULONG WindowsBuild
)
{
    if (!g_EtwInitialized && EventId != MonEtwEvent_DriverLoaded) {
        return;
    }

#if MON_ETW_TRACELOGGING_AVAILABLE
    /*
     * IMPORTANT: TraceLoggingWrite requires the event name to be a string
     * literal, not a variable. The macro stringifies the second argument,
     * so using a variable would result in the event being named "eventName"
     * rather than the actual event name.
     *
     * Therefore, we must use separate TraceLoggingWrite calls for each event.
     */
    switch (EventId) {
        case MonEtwEvent_DriverLoaded:
            TraceLoggingWrite(
                g_hMonitorEtwProvider,
                "DriverLoaded",
                TraceLoggingLevel(MON_ETW_LEVEL_INFO),
                TraceLoggingKeyword(MON_ETW_KEYWORD_TELEMETRY),
                TraceLoggingUInt32((ULONG)EventId, "EventId"),
                TraceLoggingHexUInt32(Capabilities, "Capabilities"),
                TraceLoggingUInt32(WindowsBuild, "WindowsBuild")
            );
            break;

        case MonEtwEvent_DriverUnloaded:
            TraceLoggingWrite(
                g_hMonitorEtwProvider,
                "DriverUnloaded",
                TraceLoggingLevel(MON_ETW_LEVEL_INFO),
                TraceLoggingKeyword(MON_ETW_KEYWORD_TELEMETRY),
                TraceLoggingUInt32((ULONG)EventId, "EventId"),
                TraceLoggingHexUInt32(Capabilities, "Capabilities"),
                TraceLoggingUInt32(WindowsBuild, "WindowsBuild")
            );
            break;

        case MonEtwEvent_MonitoringEnabled:
            TraceLoggingWrite(
                g_hMonitorEtwProvider,
                "MonitoringEnabled",
                TraceLoggingLevel(MON_ETW_LEVEL_INFO),
                TraceLoggingKeyword(MON_ETW_KEYWORD_TELEMETRY),
                TraceLoggingUInt32((ULONG)EventId, "EventId"),
                TraceLoggingHexUInt32(Capabilities, "Capabilities"),
                TraceLoggingUInt32(WindowsBuild, "WindowsBuild")
            );
            break;

        case MonEtwEvent_MonitoringDisabled:
            TraceLoggingWrite(
                g_hMonitorEtwProvider,
                "MonitoringDisabled",
                TraceLoggingLevel(MON_ETW_LEVEL_INFO),
                TraceLoggingKeyword(MON_ETW_KEYWORD_TELEMETRY),
                TraceLoggingUInt32((ULONG)EventId, "EventId"),
                TraceLoggingHexUInt32(Capabilities, "Capabilities"),
                TraceLoggingUInt32(WindowsBuild, "WindowsBuild")
            );
            break;

        default:
            TraceLoggingWrite(
                g_hMonitorEtwProvider,
                "DriverEvent",
                TraceLoggingLevel(MON_ETW_LEVEL_INFO),
                TraceLoggingKeyword(MON_ETW_KEYWORD_TELEMETRY),
                TraceLoggingUInt32((ULONG)EventId, "EventId"),
                TraceLoggingHexUInt32(Capabilities, "Capabilities"),
                TraceLoggingUInt32(WindowsBuild, "WindowsBuild")
            );
            break;
    }
#else
    /* Legacy path: Use direct EtwWrite */
    ULONG eventIdVal = (ULONG)EventId;
    EVENT_DATA_DESCRIPTOR dataDesc[3];
    EventDataDescCreate(&dataDesc[0], &eventIdVal, sizeof(eventIdVal));
    EventDataDescCreate(&dataDesc[1], &Capabilities, sizeof(Capabilities));
    EventDataDescCreate(&dataDesc[2], &WindowsBuild, sizeof(WindowsBuild));

    MonEtwWriteLegacy(
        (USHORT)EventId,
        MON_ETW_LEVEL_INFO,
        MON_ETW_KEYWORD_TELEMETRY,
        dataDesc,
        3
    );
#endif

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][ETW] DriverEvent: ID=%u Caps=0x%X Build=%lu\n",
        (ULONG)EventId, Capabilities, WindowsBuild);
}

_Use_decl_annotations_
VOID
MonEtwLogPoolSpray(
    ULONG PoolTag,
    const char* TagName,
    ULONG AllocationCount,
    ULONG Threshold,
    UCHAR Severity,
    const char* MitreTechnique
)
{
    if (!g_EtwInitialized) {
        return;
    }

    /* Determine level based on severity */
    UCHAR level = MON_ETW_LEVEL_WARNING;
    if (Severity >= 4) {
        level = MON_ETW_LEVEL_ERROR;
    } else if (Severity >= 3) {
        level = MON_ETW_LEVEL_WARNING;
    }

#if MON_ETW_TRACELOGGING_AVAILABLE
    TraceLoggingWrite(
        g_hMonitorEtwProvider,
        "PoolSprayDetected",
        TraceLoggingLevel(level),
        TraceLoggingKeyword(MON_ETW_KEYWORD_DETECTION | MON_ETW_KEYWORD_POOL),
        TraceLoggingHexUInt32(PoolTag, "PoolTag"),
        TraceLoggingString(TagName, "TagName"),
        TraceLoggingUInt32(AllocationCount, "AllocationCount"),
        TraceLoggingUInt32(Threshold, "Threshold"),
        TraceLoggingUInt8(Severity, "Severity"),
        TraceLoggingString(MitreTechnique, "ATT_CK_Technique"),
        TraceLoggingString(MON_ATTACK_TACTIC_TA0004, "ATT_CK_Tactic")
    );
#else
    /* Legacy path: Use direct EtwWrite */
    EVENT_DATA_DESCRIPTOR dataDesc[5];
    EventDataDescCreate(&dataDesc[0], &PoolTag, sizeof(PoolTag));
    EventDataDescCreate(&dataDesc[1], &AllocationCount, sizeof(AllocationCount));
    EventDataDescCreate(&dataDesc[2], &Threshold, sizeof(Threshold));
    EventDataDescCreate(&dataDesc[3], &Severity, sizeof(Severity));
    /* TagName and MitreTechnique omitted in legacy for simplicity */

    MonEtwWriteLegacy(
        (USHORT)MonEtwEvent_PoolSprayDetected,
        level,
        MON_ETW_KEYWORD_DETECTION | MON_ETW_KEYWORD_POOL,
        dataDesc,
        4
    );
#endif

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
        "[WIN11MON][ETW] PoolSprayDetected: Tag='%s' Count=%lu Threshold=%lu "
        "Sev=%u MITRE=%s\n",
        TagName ? TagName : "????", AllocationCount, Threshold,
        Severity, MitreTechnique ? MitreTechnique : "T1068");
}

#pragma warning(pop)
