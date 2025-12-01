/*
 * Cross-Process Communication Detection - Core Implementation
 *
 * Author: Colin MacRitchie
 * Organization: ziX Labs - Security Research Division
 * File: cross_process.c
 * Version: 1.0
 * Date: 2025-11-30
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and confidential.
 *   Redistribution or disclosure without prior written consent is prohibited.
 *
 * Summary:
 * Cross-process detection implementation. Provides relationship tracking,
 * process tree caching, risk scoring, and detection rules.
 *
 * Threading Model:
 * - g_XpState.RelationshipLock (ERESOURCE): Protects shared object list
 * - g_XpState.TreeLock (ERESOURCE): Protects process tree cache
 * - Statistics: Interlocked operations
 *
 * SECURITY PROPERTIES:
 * - Input: All process IDs validated, handles verified
 * - Output: All kernel addresses masked before user-mode export
 * - Memory Safety: SEH guards on process queries
 * - IRQL: Documented per-function, mostly PASSIVE_LEVEL
 */

#include <ntddk.h>
#include <ntstrsafe.h>
#include "cross_process.h"
#include "win11_monitor_public.h"
#include "addr_mask.h"
#include "telemetry_ringbuf.h"

#pragma warning(push)
#pragma warning(disable: 4201)   /* nameless struct/union */

/*--------------------------------------------------------------------------*/
/* Internal State Structures                                                */
/*--------------------------------------------------------------------------*/

typedef struct _MON_XP_STATE {
    volatile LONG   Initialized;

    /* Shared object tracking */
    ERESOURCE       RelationshipLock;
    LIST_ENTRY      SharedObjectList;
    ULONG           SharedObjectCount;

    /* Process tree cache */
    ERESOURCE       TreeLock;
    PMON_XP_PROCESS_ENTRY ProcessCache;
    ULONG           ProcessCacheCount;
    ULONG           ProcessCacheCapacity;
    ULONG64         LastTreeRefresh;

    /* Configuration */
    MON_XP_CONFIG   Config;

    /* Statistics (volatile for interlocked access) */
    volatile LONG   TotalSharedObjectsDetected;
    volatile LONG   TotalAlertsGenerated;
    volatile LONG   AlertsSuppressedByWhitelist;
    volatile LONG   TotalScans;
    volatile LONG   RuleHits[8];

    ULONG64         LastScanTime;

} MON_XP_STATE, *PMON_XP_STATE;

static MON_XP_STATE g_XpState = { 0 };

/*--------------------------------------------------------------------------*/
/* Built-in Detection Rules                                                 */
/*--------------------------------------------------------------------------*/

static const MON_XP_RULE g_XpBuiltinRules[] = {
    { MonXpRule_UnrelatedIoRingSharing, L"UnrelatedIoRingSharing",
      MonXpAlert_UnrelatedSharing, MonXpSeverity_High, 40, TRUE, {0}, "T1055" },
    { MonXpRule_SystemIoRingFromUser, L"SystemIoRingFromUser",
      MonXpAlert_SystemIoRingAccess, MonXpSeverity_Critical, 80, TRUE, {0}, "T1068" },
    { MonXpRule_CrossIntegrityIoRing, L"CrossIntegrityIoRing",
      MonXpAlert_CrossIntegrityShare, MonXpSeverity_High, 50, TRUE, {0}, "T1548" },
    { MonXpRule_SectionIoRingBuffer, L"SectionIoRingBuffer",
      MonXpAlert_SectionSharing, MonXpSeverity_Medium, 30, TRUE, {0}, "T1055" },
    { MonXpRule_UnexpectedInheritance, L"UnexpectedInheritance",
      MonXpAlert_InheritanceAnomaly, MonXpSeverity_Medium, 35, TRUE, {0}, "T1055" },
    { MonXpRule_RapidDuplication, L"RapidDuplication",
      MonXpAlert_HandleDuplication, MonXpSeverity_High, 45, TRUE, {0}, "T1499" },
};

#define MON_XP_BUILTIN_RULE_COUNT (sizeof(g_XpBuiltinRules) / sizeof(g_XpBuiltinRules[0]))

/*--------------------------------------------------------------------------*/
/* Forward Declarations                                                     */
/*--------------------------------------------------------------------------*/

static PMON_XP_SHARED_OBJECT MonXpFindSharedObjectLocked(_In_ ULONG64 ObjectAddr);
static PMON_XP_SHARED_OBJECT MonXpCreateSharedObject(_In_ ULONG64 ObjectAddr);
static VOID MonXpFreeSharedObject(_In_ PMON_XP_SHARED_OBJECT Object);
static PMON_XP_PROCESS_ENTRY MonXpFindProcessCached(_In_ ULONG ProcessId);
static NTSTATUS MonXpQueryProcessInfo(_In_ ULONG ProcessId, _Out_ PMON_XP_PROCESS_ENTRY Entry);
static VOID MonXpEmitAlert(_In_ const MON_XP_ALERT_EVENT* Event);
static ULONG MonXpCalculateRiskScore(_In_ const MON_XP_SHARED_OBJECT* Object);

/*--------------------------------------------------------------------------*/
/* Initialization & Shutdown                                                */
/*--------------------------------------------------------------------------*/

/**
 * @function   MonXpInitialize
 * @purpose    Initialize cross-process detection subsystem
 */
_Use_decl_annotations_
NTSTATUS
MonXpInitialize(VOID)
{
    NTSTATUS status;

    if (InterlockedCompareExchange(&g_XpState.Initialized, 1, 0) != 0) {
        return STATUS_ALREADY_INITIALIZED;
    }

    RtlZeroMemory(&g_XpState, sizeof(g_XpState));

    /* Initialize relationship lock */
    status = ExInitializeResourceLite(&g_XpState.RelationshipLock);
    if (!NT_SUCCESS(status)) {
        g_XpState.Initialized = 0;
        return status;
    }

    /* Initialize tree lock */
    status = ExInitializeResourceLite(&g_XpState.TreeLock);
    if (!NT_SUCCESS(status)) {
        ExDeleteResourceLite(&g_XpState.RelationshipLock);
        g_XpState.Initialized = 0;
        return status;
    }

    InitializeListHead(&g_XpState.SharedObjectList);

    /* Allocate process cache */
    g_XpState.ProcessCacheCapacity = MON_XP_MAX_CACHED_PROCESSES;
    g_XpState.ProcessCache = (PMON_XP_PROCESS_ENTRY)ExAllocatePool2(
        POOL_FLAG_PAGED,
        g_XpState.ProcessCacheCapacity * sizeof(MON_XP_PROCESS_ENTRY),
        MON_XP_TREE_TAG);

    if (g_XpState.ProcessCache == NULL) {
        ExDeleteResourceLite(&g_XpState.TreeLock);
        ExDeleteResourceLite(&g_XpState.RelationshipLock);
        g_XpState.Initialized = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(g_XpState.ProcessCache,
        g_XpState.ProcessCacheCapacity * sizeof(MON_XP_PROCESS_ENTRY));

    /* Set default configuration */
    g_XpState.Config.Size = sizeof(MON_XP_CONFIG);
    g_XpState.Config.Enabled = TRUE;
    g_XpState.Config.WhitelistEnabled = TRUE;
    g_XpState.Config.ScanIntervalMs = MON_XP_DEFAULT_SCAN_INTERVAL_MS;
    g_XpState.Config.TreeRefreshIntervalMs = MON_XP_DEFAULT_TREE_REFRESH_MS;
    g_XpState.Config.AlertThreshold = 40;
    g_XpState.Config.CriticalThreshold = 80;
    g_XpState.Config.MaxAlertsPerMinute = 100;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON] Cross-process detection initialized\n");

    return STATUS_SUCCESS;
}

/**
 * @function   MonXpShutdown
 * @purpose    Shutdown cross-process detection
 */
_Use_decl_annotations_
VOID
MonXpShutdown(VOID)
{
    PLIST_ENTRY entry;
    PMON_XP_SHARED_OBJECT object;

    if (InterlockedCompareExchange(&g_XpState.Initialized, 0, 1) != 1) {
        return;
    }

    /* Free all shared objects */
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&g_XpState.RelationshipLock, TRUE);

    while (!IsListEmpty(&g_XpState.SharedObjectList)) {
        entry = RemoveHeadList(&g_XpState.SharedObjectList);
        object = CONTAINING_RECORD(entry, MON_XP_SHARED_OBJECT, ListEntry);
        MonXpFreeSharedObject(object);
    }

    ExReleaseResourceLite(&g_XpState.RelationshipLock);
    KeLeaveCriticalRegion();

    /* Free process cache */
    if (g_XpState.ProcessCache != NULL) {
        ExFreePoolWithTag(g_XpState.ProcessCache, MON_XP_TREE_TAG);
        g_XpState.ProcessCache = NULL;
    }

    ExDeleteResourceLite(&g_XpState.TreeLock);
    ExDeleteResourceLite(&g_XpState.RelationshipLock);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON] Cross-process detection shutdown complete\n");
}

/**
 * @function   MonXpIsInitialized
 * @purpose    Check if cross-process detection is ready
 */
_Use_decl_annotations_
BOOLEAN
MonXpIsInitialized(VOID)
{
    return (InterlockedCompareExchange(&g_XpState.Initialized, 1, 1) == 1);
}

/*--------------------------------------------------------------------------*/
/* Shared Object Management                                                 */
/*--------------------------------------------------------------------------*/

/**
 * Find shared object by address (caller must hold lock)
 */
static
PMON_XP_SHARED_OBJECT
MonXpFindSharedObjectLocked(
    _In_ ULONG64 ObjectAddr
)
{
    PLIST_ENTRY entry;
    PMON_XP_SHARED_OBJECT object;

    for (entry = g_XpState.SharedObjectList.Flink;
         entry != &g_XpState.SharedObjectList;
         entry = entry->Flink) {

        object = CONTAINING_RECORD(entry, MON_XP_SHARED_OBJECT, ListEntry);
        if (object->ObjectAddressMasked == ObjectAddr) {
            return object;
        }
    }

    return NULL;
}

/**
 * Create new shared object record
 */
static
PMON_XP_SHARED_OBJECT
MonXpCreateSharedObject(
    _In_ ULONG64 ObjectAddr
)
{
    PMON_XP_SHARED_OBJECT object;

    object = (PMON_XP_SHARED_OBJECT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(MON_XP_SHARED_OBJECT),
        MON_XP_RELATIONSHIP_TAG);

    if (object == NULL) {
        return NULL;
    }

    RtlZeroMemory(object, sizeof(*object));
    object->ObjectAddressMasked = ObjectAddr;
    object->FirstDetectedTime = KeQueryInterruptTime();
    object->LastUpdatedTime = object->FirstDetectedTime;

    return object;
}

/**
 * Free shared object resources
 */
static
VOID
MonXpFreeSharedObject(
    _In_ PMON_XP_SHARED_OBJECT Object
)
{
    if (Object != NULL) {
        ExFreePoolWithTag(Object, MON_XP_RELATIONSHIP_TAG);
    }
}

/*--------------------------------------------------------------------------*/
/* Process Tree Cache                                                       */
/*--------------------------------------------------------------------------*/

/**
 * Find cached process entry (uses binary search)
 */
static
PMON_XP_PROCESS_ENTRY
MonXpFindProcessCached(
    _In_ ULONG ProcessId
)
{
    LONG low = 0;
    LONG high = (LONG)g_XpState.ProcessCacheCount - 1;
    LONG mid;

    while (low <= high) {
        mid = (low + high) / 2;
        if (g_XpState.ProcessCache[mid].ProcessId == ProcessId) {
            return &g_XpState.ProcessCache[mid];
        } else if (g_XpState.ProcessCache[mid].ProcessId < ProcessId) {
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }

    return NULL;
}

/**
 * Query process information from system
 */
static
NTSTATUS
MonXpQueryProcessInfo(
    _In_ ULONG ProcessId,
    _Out_ PMON_XP_PROCESS_ENTRY Entry
)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    HANDLE processHandle = NULL;

    RtlZeroMemory(Entry, sizeof(*Entry));
    Entry->ProcessId = ProcessId;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    __try {
        /* Get parent PID from inherited from unique ID */
        Entry->ParentProcessId = (ULONG)(ULONG_PTR)PsGetProcessInheritedFromUniqueProcessId(process);

        /* Get session ID */
        Entry->SessionId = PsGetProcessSessionId(process);

        /* Get image file name */
        PUNICODE_STRING imageName = NULL;
        status = SeLocateProcessImageName(process, &imageName);
        if (NT_SUCCESS(status) && imageName != NULL) {
            /* Extract just the filename from full path */
            PWCHAR lastSlash = wcsrchr(imageName->Buffer, L'\\');
            if (lastSlash != NULL) {
                RtlStringCbCopyW(Entry->ImageName, sizeof(Entry->ImageName), lastSlash + 1);
            } else {
                RtlStringCbCopyW(Entry->ImageName, sizeof(Entry->ImageName), imageName->Buffer);
            }
            ExFreePool(imageName);
        }

        /* Set flags based on process characteristics */
        if (Entry->SessionId == 0) {
            Entry->Flags |= MON_XP_PROC_FLAG_SERVICE;
        }

        if (ProcessId == 4) {
            Entry->Flags |= MON_XP_PROC_FLAG_SYSTEM;
            Entry->IntegrityLevel = MON_IL_SYSTEM;
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    ObDereferenceObject(process);
    return status;
}

/*--------------------------------------------------------------------------*/
/* Risk Scoring                                                             */
/*--------------------------------------------------------------------------*/

/**
 * Calculate risk score for a shared object
 */
static
ULONG
MonXpCalculateRiskScore(
    _In_ const MON_XP_SHARED_OBJECT* Object
)
{
    ULONG score = 0;

    /* Base score from triggered rules */
    if (Object->TriggeredRules & (1 << (MonXpRule_SystemIoRingFromUser - 100))) {
        score += 80;
    }
    if (Object->TriggeredRules & (1 << (MonXpRule_CrossIntegrityIoRing - 100))) {
        score += 50;
    }
    if (Object->TriggeredRules & (1 << (MonXpRule_UnrelatedIoRingSharing - 100))) {
        score += 40;
    }

    /* Aggravating factors */
    if (Object->Flags & MON_XP_FLAG_SYSTEM_INVOLVED) {
        score += 25;
    }
    if (Object->Flags & MON_XP_FLAG_CROSS_SESSION) {
        score += 15;
    }
    if (Object->Flags & MON_XP_FLAG_CROSS_INTEGRITY) {
        score += 10;
    }

    /* Mitigating factors */
    if (Object->HasParentChildRelation) {
        score = (score > 25) ? (score - 25) : 0;
    }
    if (Object->Flags & MON_XP_FLAG_INHERITED) {
        score = (score > 15) ? (score - 15) : 0;
    }
    if (Object->Flags & MON_XP_FLAG_WHITELISTED) {
        score = (score > 30) ? (score - 30) : 0;
    }

    /* Clamp to 0-100 */
    if (score > 100) {
        score = 100;
    }

    return score;
}

/*--------------------------------------------------------------------------*/
/* Alert Emission                                                           */
/*--------------------------------------------------------------------------*/

/**
 * Emit cross-process alert to ring buffer
 */
static
VOID
MonXpEmitAlert(
    _In_ const MON_XP_ALERT_EVENT* Event
)
{
    /* Write to ring buffer telemetry */
    MonRingBufWriteEvent(MonEvent_CrossProcess, Event, sizeof(*Event));

    InterlockedIncrement(&g_XpState.TotalAlertsGenerated);
}

/*--------------------------------------------------------------------------*/
/* Public API - Configuration                                               */
/*--------------------------------------------------------------------------*/

/**
 * @function   MonXpGetStats
 * @purpose    Get cross-process detection statistics
 */
_Use_decl_annotations_
VOID
MonXpGetStats(
    PMON_XP_STATS Stats
)
{
    ULONG i;

    if (Stats == NULL) {
        return;
    }

    RtlZeroMemory(Stats, sizeof(*Stats));
    Stats->Size = sizeof(MON_XP_STATS);

    Stats->ActiveSharedObjects = g_XpState.SharedObjectCount;
    Stats->TotalSharedObjectsDetected = (ULONG)g_XpState.TotalSharedObjectsDetected;
    Stats->TotalAlertsGenerated = (ULONG)g_XpState.TotalAlertsGenerated;
    Stats->AlertsSuppressedByWhitelist = (ULONG)g_XpState.AlertsSuppressedByWhitelist;
    Stats->TotalScans = (ULONG)g_XpState.TotalScans;
    Stats->CachedProcessCount = g_XpState.ProcessCacheCount;
    Stats->LastScanTime = g_XpState.LastScanTime;
    Stats->LastTreeRefreshTime = g_XpState.LastTreeRefresh;

    for (i = 0; i < 8; i++) {
        Stats->RuleHits[i] = (ULONG)g_XpState.RuleHits[i];
    }
}

/**
 * @function   MonXpGetConfig
 * @purpose    Get current configuration
 */
_Use_decl_annotations_
VOID
MonXpGetConfig(
    PMON_XP_CONFIG Config
)
{
    if (Config == NULL) {
        return;
    }

    RtlCopyMemory(Config, &g_XpState.Config, sizeof(MON_XP_CONFIG));
}

/**
 * @function   MonXpSetConfig
 * @purpose    Set configuration
 */
_Use_decl_annotations_
NTSTATUS
MonXpSetConfig(
    const MON_XP_CONFIG* Config
)
{
    if (Config == NULL || Config->Size != sizeof(MON_XP_CONFIG)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!MonXpIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&g_XpState.RelationshipLock, TRUE);

    RtlCopyMemory(&g_XpState.Config, Config, sizeof(MON_XP_CONFIG));
    g_XpState.Config.Size = sizeof(MON_XP_CONFIG);

    ExReleaseResourceLite(&g_XpState.RelationshipLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

/**
 * @function   MonXpResetStats
 * @purpose    Reset statistics
 */
_Use_decl_annotations_
VOID
MonXpResetStats(VOID)
{
    ULONG i;

    InterlockedExchange(&g_XpState.TotalSharedObjectsDetected, 0);
    InterlockedExchange(&g_XpState.TotalAlertsGenerated, 0);
    InterlockedExchange(&g_XpState.AlertsSuppressedByWhitelist, 0);
    InterlockedExchange(&g_XpState.TotalScans, 0);

    for (i = 0; i < 8; i++) {
        InterlockedExchange(&g_XpState.RuleHits[i], 0);
    }
}

/*--------------------------------------------------------------------------*/
/* Public API - Process Tree                                                */
/*--------------------------------------------------------------------------*/

/**
 * @function   MonXpIsProcessDescendant
 * @purpose    Check if one process is descendant of another
 */
_Use_decl_annotations_
BOOLEAN
MonXpIsProcessDescendant(
    ULONG AncestorPid,
    ULONG DescendantPid,
    ULONG MaxDepth
)
{
    PMON_XP_PROCESS_ENTRY entry;
    ULONG currentPid = DescendantPid;
    ULONG depth = 0;

    if (!MonXpIsInitialized() || AncestorPid == 0 || DescendantPid == 0) {
        return FALSE;
    }

    if (AncestorPid == DescendantPid) {
        return TRUE;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&g_XpState.TreeLock, TRUE);

    while (depth < MaxDepth && currentPid != 0) {
        entry = MonXpFindProcessCached(currentPid);
        if (entry == NULL) {
            break;
        }

        if (entry->ParentProcessId == AncestorPid) {
            ExReleaseResourceLite(&g_XpState.TreeLock);
            KeLeaveCriticalRegion();
            return TRUE;
        }

        currentPid = entry->ParentProcessId;
        depth++;
    }

    ExReleaseResourceLite(&g_XpState.TreeLock);
    KeLeaveCriticalRegion();

    return FALSE;
}

/**
 * @function   MonXpGetProcessIntegrity
 * @purpose    Query process integrity level
 */
_Use_decl_annotations_
NTSTATUS
MonXpGetProcessIntegrity(
    ULONG ProcessId,
    ULONG* IntegrityLevel
)
{
    PMON_XP_PROCESS_ENTRY entry;

    if (IntegrityLevel == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IntegrityLevel = MON_IL_MEDIUM; /* Default */

    if (!MonXpIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&g_XpState.TreeLock, TRUE);

    entry = MonXpFindProcessCached(ProcessId);
    if (entry != NULL) {
        *IntegrityLevel = entry->IntegrityLevel;
    }

    ExReleaseResourceLite(&g_XpState.TreeLock);
    KeLeaveCriticalRegion();

    return (entry != NULL) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/*--------------------------------------------------------------------------*/
/* Public API - Scanning & Detection                                        */
/*--------------------------------------------------------------------------*/

/**
 * @function   MonXpScanNow
 * @purpose    Trigger immediate scan (stub - full impl in handle_correlator.c)
 */
_Use_decl_annotations_
NTSTATUS
MonXpScanNow(VOID)
{
    if (!MonXpIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    if (!g_XpState.Config.Enabled) {
        return STATUS_SUCCESS;
    }

    InterlockedIncrement(&g_XpState.TotalScans);
    g_XpState.LastScanTime = KeQueryInterruptTime();

    /* Full implementation delegated to handle_correlator.c */
    /* extern NTSTATUS MonHcCorrelateHandles(VOID); */
    /* return MonHcCorrelateHandles(); */

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
        "[WIN11MON] Cross-process scan triggered\n");

    return STATUS_SUCCESS;
}

/**
 * @function   MonXpGetSharedObjects
 * @purpose    Get list of shared objects (allocates output array)
 */
_Use_decl_annotations_
NTSTATUS
MonXpGetSharedObjects(
    PMON_XP_SHARED_OBJECT* Objects,
    ULONG* Count
)
{
    PLIST_ENTRY entry;
    PMON_XP_SHARED_OBJECT object;
    PMON_XP_SHARED_OBJECT outArray = NULL;
    ULONG count = 0;
    ULONG i = 0;

    if (Objects == NULL || Count == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Objects = NULL;
    *Count = 0;

    if (!MonXpIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&g_XpState.RelationshipLock, TRUE);

    /* Count objects */
    count = g_XpState.SharedObjectCount;
    if (count == 0) {
        ExReleaseResourceLite(&g_XpState.RelationshipLock);
        KeLeaveCriticalRegion();
        return STATUS_SUCCESS;
    }

    /* Allocate output array */
    outArray = (PMON_XP_SHARED_OBJECT)ExAllocatePool2(
        POOL_FLAG_PAGED, count * sizeof(MON_XP_SHARED_OBJECT), MON_XP_TAG);
    if (outArray == NULL) {
        ExReleaseResourceLite(&g_XpState.RelationshipLock);
        KeLeaveCriticalRegion();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Copy objects */
    for (entry = g_XpState.SharedObjectList.Flink;
         entry != &g_XpState.SharedObjectList && i < count;
         entry = entry->Flink) {
        object = CONTAINING_RECORD(entry, MON_XP_SHARED_OBJECT, ListEntry);
        RtlCopyMemory(&outArray[i], object, sizeof(MON_XP_SHARED_OBJECT));
        i++;
    }

    ExReleaseResourceLite(&g_XpState.RelationshipLock);
    KeLeaveCriticalRegion();

    *Objects = outArray;
    *Count = i;
    return STATUS_SUCCESS;
}

/**
 * @function   MonXpGetProcessTree
 * @purpose    Get process tree snapshot (allocates output array)
 */
_Use_decl_annotations_
NTSTATUS
MonXpGetProcessTree(
    PMON_XP_PROCESS_ENTRY* Entries,
    ULONG* Count
)
{
    PMON_XP_PROCESS_ENTRY outArray = NULL;
    ULONG count;

    if (Entries == NULL || Count == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Entries = NULL;
    *Count = 0;

    if (!MonXpIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&g_XpState.TreeLock, TRUE);

    count = g_XpState.ProcessCacheCount;
    if (count == 0) {
        ExReleaseResourceLite(&g_XpState.TreeLock);
        KeLeaveCriticalRegion();
        return STATUS_SUCCESS;
    }

    /* Allocate output array */
    outArray = (PMON_XP_PROCESS_ENTRY)ExAllocatePool2(
        POOL_FLAG_PAGED, count * sizeof(MON_XP_PROCESS_ENTRY), MON_XP_TAG);
    if (outArray == NULL) {
        ExReleaseResourceLite(&g_XpState.TreeLock);
        KeLeaveCriticalRegion();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(outArray, g_XpState.ProcessCache,
        count * sizeof(MON_XP_PROCESS_ENTRY));

    ExReleaseResourceLite(&g_XpState.TreeLock);
    KeLeaveCriticalRegion();

    *Entries = outArray;
    *Count = count;
    return STATUS_SUCCESS;
}

/**
 * @function   MonXpGetAlerts
 * @purpose    Get pending alerts (allocates output array)
 */
_Use_decl_annotations_
NTSTATUS
MonXpGetAlerts(
    PMON_XP_ALERT_EVENT* Alerts,
    ULONG* Count
)
{
    if (Alerts == NULL || Count == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Alerts are routed through ring buffer (telemetry_ringbuf.c) */
    /* This stub returns empty - use MonRingBufReadEvents for actual alerts */

    *Alerts = NULL;
    *Count = 0;
    return STATUS_SUCCESS;
}

/**
 * @function   MonXpScanSections
 * @purpose    Enumerate section objects for a process (stub)
 */
_Use_decl_annotations_
NTSTATUS
MonXpScanSections(
    HANDLE ProcessId,
    PMON_XP_SECTION_INFO* Sections,
    ULONG* Count
)
{
    UNREFERENCED_PARAMETER(ProcessId);

    if (Sections == NULL || Count == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!MonXpIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    /* Section enumeration requires VAD walking - integration with mem_monitor.c */
    /* This is a stub implementation */

    *Sections = NULL;
    *Count = 0;
    return STATUS_SUCCESS;
}

/**
 * @function   MonXpConvertProcessEntryToPublic
 * @purpose    Convert internal process entry to public format
 */
_Use_decl_annotations_
VOID
MonXpConvertProcessEntryToPublic(
    const MON_XP_PROCESS_ENTRY* Internal,
    PVOID Public
)
{
    MON_XP_PROCESS_ENTRY_PUBLIC* pub = (MON_XP_PROCESS_ENTRY_PUBLIC*)Public;

    if (Internal == NULL || Public == NULL) {
        return;
    }

    pub->ProcessId = Internal->ProcessId;
    pub->ParentProcessId = Internal->ParentProcessId;
    pub->SessionId = Internal->SessionId;
    pub->IntegrityLevel = Internal->IntegrityLevel;
    pub->Flags = Internal->Flags;
    pub->Reserved = 0;
    pub->CreateTime = Internal->CreateTime;

    RtlCopyMemory(pub->ImageName, Internal->ImageName, sizeof(pub->ImageName));
}

/**
 * @function   MonXpConvertAlertToPublic
 * @purpose    Convert internal alert to public format
 */
_Use_decl_annotations_
VOID
MonXpConvertAlertToPublic(
    const MON_XP_ALERT_EVENT* Internal,
    PVOID Public
)
{
    MON_XP_ALERT_EVENT_PUBLIC* pub = (MON_XP_ALERT_EVENT_PUBLIC*)Public;

    if (Internal == NULL || Public == NULL) {
        return;
    }

    pub->Size = sizeof(MON_XP_ALERT_EVENT_PUBLIC);
    pub->AlertType = (MON_XP_ALERT_TYPE_PUBLIC)Internal->AlertType;
    pub->Severity = (MON_XP_SEVERITY_PUBLIC)Internal->Severity;
    pub->RuleId = Internal->RuleId;
    pub->Timestamp = Internal->Timestamp;
    pub->ObjectAddressMasked = Internal->ObjectAddressMasked;
    pub->ObjectTypeIndex = Internal->ObjectTypeIndex;
    pub->SourceProcessId = Internal->SourceProcessId;
    pub->TargetProcessId = Internal->TargetProcessId;
    pub->SourceHandle = Internal->SourceHandle;
    pub->TargetHandle = Internal->TargetHandle;
    pub->SourceAccess = Internal->SourceAccess;
    pub->TargetAccess = Internal->TargetAccess;
    pub->IsParentChild = Internal->IsParentChild;
    pub->SourceIntegrity = Internal->SourceIntegrity;
    pub->TargetIntegrity = Internal->TargetIntegrity;
    pub->RiskScore = Internal->RiskScore;

    RtlCopyMemory(pub->SourceProcessName, Internal->SourceProcessName,
        sizeof(pub->SourceProcessName));
    RtlCopyMemory(pub->TargetProcessName, Internal->TargetProcessName,
        sizeof(pub->TargetProcessName));
    RtlCopyMemory(pub->MitreTechnique, Internal->MitreTechnique,
        sizeof(pub->MitreTechnique));
    RtlCopyMemory(pub->Description, Internal->Description,
        sizeof(pub->Description));
}

#pragma warning(pop)
