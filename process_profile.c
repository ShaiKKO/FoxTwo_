/*
 * Process Behavior Profiling Module - Implementation
 *
 * Author: Colin MacRitchie | ziX Labs
 * Organization: ziX Labs - Security Research Division
 * File: process_profile.c
 * Version: 1.0
 * Date: 2025-11-30
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and confidential.
 *   Redistribution or disclosure without prior written consent is prohibited.
 *
 * Summary
 * -------
 * Implements per-process IoRing behavior profiling with anomaly detection.
 * Tracks operations, buffers, handles, and generates ML-ready features.
 *
 * Threading Model:
 * - Profile list: ERESOURCE (reader-writer lock)
 * - Individual counters: Interlocked operations
 * - Config: Lock-free reads, exclusive writes
 */

#include <ntddk.h>
#include <ntstrsafe.h>
#include "process_profile.h"
#include "telemetry_ringbuf.h"
#include "ioring_intercept.h"

#pragma warning(push)
#pragma warning(disable: 4201) /* nameless struct/union */

/*--------------------------------------------------------------------------
 * Module State
 *-------------------------------------------------------------------------*/
typedef struct _MON_PROFILE_STATE {
    volatile LONG   Initialized;
    ERESOURCE       ListLock;               /* Reader-writer lock for list */
    LIST_ENTRY      ProfileList;            /* List of MON_PROCESS_PROFILE */
    volatile LONG   ProfileCount;

    /* Global statistics */
    volatile LONG   TotalProfilesCreated;
    volatile LONG   TotalProfilesDestroyed;
    volatile LONG   TotalAnomaliesDetected;
    volatile LONG64 TotalUpdates;
    volatile LONG64 TotalExports;

    /* Configuration */
    MON_PROFILE_CONFIG Config;

} MON_PROFILE_STATE, *PMON_PROFILE_STATE;

static MON_PROFILE_STATE g_ProfileState = {0};

/*--------------------------------------------------------------------------
 * Forward Declarations
 *-------------------------------------------------------------------------*/
static PMON_PROCESS_PROFILE MonProfileFindByPidLocked(_In_ ULONG ProcessId);
static VOID MonProfileUpdateOpsPerSecond(_Inout_ PMON_PROCESS_PROFILE Profile);
static ULONG MonProfileCalculateAverageOps(_In_ const MON_PROCESS_PROFILE* Profile);
static VOID MonProfileCheckAnomalies(_Inout_ PMON_PROCESS_PROFILE Profile);
static VOID MonProfileLogAnomalyEvent(
    _In_ PMON_PROCESS_PROFILE Profile,
    _In_ MON_ANOMALY_RULE_ID RuleId,
    _In_ ULONG ActualValue,
    _In_ ULONG Threshold
);

/*==========================================================================
 * Initialization and Shutdown
 *=========================================================================*/

_Use_decl_annotations_
NTSTATUS MonProfileInitialize(VOID)
{
    NTSTATUS status;

    if (InterlockedCompareExchange(&g_ProfileState.Initialized, 0, 0) != 0) {
        return STATUS_SUCCESS;
    }

    /* Initialize ERESOURCE */
    status = ExInitializeResourceLite(&g_ProfileState.ListLock);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WIN11MON][PROFILE] Failed to init ERESOURCE: 0x%08X\n", status);
        return status;
    }

    /* Initialize list */
    InitializeListHead(&g_ProfileState.ProfileList);
    g_ProfileState.ProfileCount = 0;

    /* Initialize statistics */
    g_ProfileState.TotalProfilesCreated = 0;
    g_ProfileState.TotalProfilesDestroyed = 0;
    g_ProfileState.TotalAnomaliesDetected = 0;
    g_ProfileState.TotalUpdates = 0;
    g_ProfileState.TotalExports = 0;

    /* Default configuration */
    g_ProfileState.Config.Size = sizeof(MON_PROFILE_CONFIG);
    g_ProfileState.Config.Enabled = TRUE;
    g_ProfileState.Config.AutoExport = FALSE;
    g_ProfileState.Config.AutoBlacklist = FALSE;
    g_ProfileState.Config.AnomalyThreshold = 70;
    g_ProfileState.Config.BlacklistThreshold = 90;
    g_ProfileState.Config.HistoryWindowSec = MON_PROFILE_HISTORY_SLOTS;

    InterlockedExchange(&g_ProfileState.Initialized, 1);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][PROFILE] Initialized (max=%u profiles)\n",
        MON_PROFILE_MAX_PROCESSES);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID MonProfileShutdown(VOID)
{
    PLIST_ENTRY entry;
    PMON_PROCESS_PROFILE profile;

    if (InterlockedCompareExchange(&g_ProfileState.Initialized, 0, 0) == 0) {
        return;
    }

    /* Mark as shutting down */
    InterlockedExchange(&g_ProfileState.Initialized, 0);

    /* Acquire exclusive lock */
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&g_ProfileState.ListLock, TRUE);

    /* Free all profiles */
    while (!IsListEmpty(&g_ProfileState.ProfileList)) {
        entry = RemoveHeadList(&g_ProfileState.ProfileList);
        profile = CONTAINING_RECORD(entry, MON_PROCESS_PROFILE, ListEntry);
        ExFreePoolWithTag(profile, MON_PROFILE_TAG);
    }

    ExReleaseResourceLite(&g_ProfileState.ListLock);
    KeLeaveCriticalRegion();

    /* Delete ERESOURCE */
    ExDeleteResourceLite(&g_ProfileState.ListLock);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][PROFILE] Shutdown (created=%ld, destroyed=%ld)\n",
        g_ProfileState.TotalProfilesCreated,
        g_ProfileState.TotalProfilesDestroyed);
}

_Use_decl_annotations_
BOOLEAN MonProfileIsInitialized(VOID)
{
    return InterlockedCompareExchange(&g_ProfileState.Initialized, 0, 0) != 0;
}

/*==========================================================================
 * Profile Creation and Destruction
 *=========================================================================*/

_Use_decl_annotations_
NTSTATUS
MonProfileCreate(
    ULONG ProcessId,
    PCWSTR ImageName
)
{
    PMON_PROCESS_PROFILE profile;
    LARGE_INTEGER currentTime;

    if (!MonProfileIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    if (ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Check capacity */
    if (g_ProfileState.ProfileCount >= MON_PROFILE_MAX_PROCESSES) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Check if already exists */
    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&g_ProfileState.ListLock, TRUE);

    profile = MonProfileFindByPidLocked(ProcessId);

    ExReleaseResourceLite(&g_ProfileState.ListLock);
    KeLeaveCriticalRegion();

    if (profile != NULL) {
        return STATUS_SUCCESS;  /* Already exists */
    }

    /* Allocate new profile */
    profile = (PMON_PROCESS_PROFILE)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(MON_PROCESS_PROFILE),
        MON_PROFILE_TAG
    );

    if (profile == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Initialize profile */
    RtlZeroMemory(profile, sizeof(MON_PROCESS_PROFILE));
    profile->Magic = MON_PROFILE_MAGIC;
    profile->ProcessId = ProcessId;

    KeQuerySystemTime(&currentTime);
    profile->ProcessStartTime = currentTime.QuadPart;
    profile->FirstSeenTime = currentTime.QuadPart;
    profile->LastActivityTime = currentTime.QuadPart;
    profile->LastSecondBoundary = currentTime;
    profile->LastUpdateTime = currentTime;

    if (ImageName != NULL) {
        RtlStringCchCopyW(profile->ImageName,
                          RTL_NUMBER_OF(profile->ImageName),
                          ImageName);
    }

    /* Insert into list */
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&g_ProfileState.ListLock, TRUE);

    /* Double-check under exclusive lock */
    if (MonProfileFindByPidLocked(ProcessId) == NULL) {
        InsertTailList(&g_ProfileState.ProfileList, &profile->ListEntry);
        InterlockedIncrement(&g_ProfileState.ProfileCount);
        InterlockedIncrement(&g_ProfileState.TotalProfilesCreated);
    } else {
        /* Race condition - another thread created it */
        ExFreePoolWithTag(profile, MON_PROFILE_TAG);
        profile = NULL;
    }

    ExReleaseResourceLite(&g_ProfileState.ListLock);
    KeLeaveCriticalRegion();

    if (profile != NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[WIN11MON][PROFILE] Created PID=%lu (%ws)\n",
            ProcessId, profile->ImageName);
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
BOOLEAN
MonProfileDestroy(
    ULONG ProcessId
)
{
    PMON_PROCESS_PROFILE profile = NULL;
    BOOLEAN found = FALSE;

    if (!MonProfileIsInitialized() || ProcessId == 0) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&g_ProfileState.ListLock, TRUE);

    profile = MonProfileFindByPidLocked(ProcessId);
    if (profile != NULL) {
        RemoveEntryList(&profile->ListEntry);
        InterlockedDecrement(&g_ProfileState.ProfileCount);
        InterlockedIncrement(&g_ProfileState.TotalProfilesDestroyed);
        found = TRUE;
    }

    ExReleaseResourceLite(&g_ProfileState.ListLock);
    KeLeaveCriticalRegion();

    if (found && profile != NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[WIN11MON][PROFILE] Destroyed PID=%lu (ops=%lld, score=%ld)\n",
            ProcessId, profile->TotalOperations, profile->AnomalyScore);

        ExFreePoolWithTag(profile, MON_PROFILE_TAG);
    }

    return found;
}

/*==========================================================================
 * Profile Lookup
 *=========================================================================*/

static PMON_PROCESS_PROFILE
MonProfileFindByPidLocked(_In_ ULONG ProcessId)
{
    PLIST_ENTRY entry;
    PMON_PROCESS_PROFILE profile;

    for (entry = g_ProfileState.ProfileList.Flink;
         entry != &g_ProfileState.ProfileList;
         entry = entry->Flink) {

        profile = CONTAINING_RECORD(entry, MON_PROCESS_PROFILE, ListEntry);
        if (profile->ProcessId == ProcessId) {
            return profile;
        }
    }

    return NULL;
}

_Use_decl_annotations_
PMON_PROCESS_PROFILE
MonProfileGetByPid(
    ULONG ProcessId
)
{
    PMON_PROCESS_PROFILE profile;

    if (!MonProfileIsInitialized() || ProcessId == 0) {
        return NULL;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&g_ProfileState.ListLock, TRUE);

    profile = MonProfileFindByPidLocked(ProcessId);

    ExReleaseResourceLite(&g_ProfileState.ListLock);
    KeLeaveCriticalRegion();

    return profile;
}

/*==========================================================================
 * Profile Updates
 *=========================================================================*/

_Use_decl_annotations_
VOID
MonProfileRecordOperation(
    ULONG ProcessId,
    ULONG OpCode,
    ULONG BufferSize
)
{
    PMON_PROCESS_PROFILE profile;
    LARGE_INTEGER currentTime;

    if (!MonProfileIsInitialized() || !g_ProfileState.Config.Enabled) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&g_ProfileState.ListLock, TRUE);

    profile = MonProfileFindByPidLocked(ProcessId);

    if (profile != NULL) {
        KeQuerySystemTime(&currentTime);

        /* Update operation counters */
        InterlockedIncrement64(&profile->TotalOperations);
        InterlockedIncrement64(&g_ProfileState.TotalUpdates);

        /* Categorize by opcode */
        switch (OpCode) {
            case 1:  /* Read */
                InterlockedIncrement64((volatile LONG64*)&profile->TotalReads);
                break;
            case 5:  /* Write */
                InterlockedIncrement64((volatile LONG64*)&profile->TotalWrites);
                break;
            case 4:  /* Cancel */
                InterlockedIncrement64((volatile LONG64*)&profile->TotalCancels);
                break;
            default:
                InterlockedIncrement64((volatile LONG64*)&profile->TotalOther);
                break;
        }

        /* Buffer statistics */
        if (BufferSize > 0) {
            if (OpCode == 3) {  /* RegisterBuffers */
                InterlockedAdd64((volatile LONG64*)&profile->TotalBufferBytesRegistered,
                                 BufferSize);
                InterlockedIncrement((volatile LONG*)&profile->TotalBuffersRegistered);

                if (BufferSize > profile->MaxBufferSize) {
                    InterlockedExchange((volatile LONG*)&profile->MaxBufferSize, BufferSize);
                }
            }
        }

        /* Update sliding window */
        MonProfileUpdateOpsPerSecond(profile);

        /* Update timestamps */
        profile->LastActivityTime = currentTime.QuadPart;
        profile->LastUpdateTime = currentTime;

        /* Check for anomalies periodically */
        if ((profile->TotalOperations % 100) == 0) {
            MonProfileCheckAnomalies(profile);
        }
    }

    ExReleaseResourceLite(&g_ProfileState.ListLock);
    KeLeaveCriticalRegion();
}

_Use_decl_annotations_
VOID
MonProfileRecordHandle(
    ULONG ProcessId,
    BOOLEAN Created
)
{
    PMON_PROCESS_PROFILE profile;

    if (!MonProfileIsInitialized()) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&g_ProfileState.ListLock, TRUE);

    profile = MonProfileFindByPidLocked(ProcessId);

    if (profile != NULL) {
        if (Created) {
            InterlockedIncrement(&profile->ActiveHandleCount);
            InterlockedIncrement((volatile LONG*)&profile->TotalHandlesCreated);
        } else {
            InterlockedDecrement(&profile->ActiveHandleCount);
            InterlockedIncrement((volatile LONG*)&profile->TotalHandlesClosed);
        }
    }

    ExReleaseResourceLite(&g_ProfileState.ListLock);
    KeLeaveCriticalRegion();
}

_Use_decl_annotations_
VOID
MonProfileRecordViolation(
    ULONG ProcessId
)
{
    PMON_PROCESS_PROFILE profile;

    if (!MonProfileIsInitialized()) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&g_ProfileState.ListLock, TRUE);

    profile = MonProfileFindByPidLocked(ProcessId);

    if (profile != NULL) {
        InterlockedIncrement((volatile LONG*)&profile->ViolationCount);
        InterlockedAdd(&profile->AnomalyScore, 5);

        if (profile->AnomalyScore > 100) {
            InterlockedExchange(&profile->AnomalyScore, 100);
        }
    }

    ExReleaseResourceLite(&g_ProfileState.ListLock);
    KeLeaveCriticalRegion();
}

/*==========================================================================
 * Sliding Window Operations Per Second
 *=========================================================================*/

static VOID
MonProfileUpdateOpsPerSecond(_Inout_ PMON_PROCESS_PROFILE Profile)
{
    LARGE_INTEGER currentTime;
    LONGLONG elapsedTicks;
    LONGLONG ticksPerSecond = 10000000LL;  /* 100ns units per second */

    KeQuerySystemTime(&currentTime);
    elapsedTicks = currentTime.QuadPart - Profile->LastSecondBoundary.QuadPart;

    if (elapsedTicks >= ticksPerSecond) {
        /* Advance to next second slot */
        Profile->HistoryIndex = (Profile->HistoryIndex + 1) % MON_PROFILE_HISTORY_SLOTS;
        Profile->OpsHistory[Profile->HistoryIndex] = Profile->OpsCurrentSecond;
        Profile->OpsCurrentSecond = 1;
        Profile->LastSecondBoundary = currentTime;
    } else {
        Profile->OpsCurrentSecond++;
    }
}

static ULONG
MonProfileCalculateAverageOps(_In_ const MON_PROCESS_PROFILE* Profile)
{
    ULONG sum = 0;
    ULONG count = 0;

    for (ULONG i = 0; i < MON_PROFILE_HISTORY_SLOTS; i++) {
        if (Profile->OpsHistory[i] > 0) {
            sum += Profile->OpsHistory[i];
            count++;
        }
    }

    if (count == 0) {
        return Profile->OpsCurrentSecond;
    }

    return sum / count;
}

/*==========================================================================
 * Anomaly Detection
 *=========================================================================*/

static VOID
MonProfileCheckAnomalies(_Inout_ PMON_PROCESS_PROFILE Profile)
{
    ULONG avgOps = MonProfileCalculateAverageOps(Profile);
    LONG oldScore = Profile->AnomalyScore;
    LONG scoreAdjust = 0;

    /* Rule 1: High ops frequency (>1000 ops/sec) */
    if (avgOps > 1000) {
        if (!(Profile->TriggeredRules & (1 << MonAnomalyRule_HighOpsFrequency))) {
            Profile->TriggeredRules |= (1 << MonAnomalyRule_HighOpsFrequency);
            scoreAdjust += 20;
            MonProfileLogAnomalyEvent(Profile, MonAnomalyRule_HighOpsFrequency, avgOps, 1000);
        }
    }

    /* Rule 2: Large buffer (>100MB) */
    if (Profile->MaxBufferSize > 100 * 1024 * 1024) {
        if (!(Profile->TriggeredRules & (1 << MonAnomalyRule_LargeBufferRegistration))) {
            Profile->TriggeredRules |= (1 << MonAnomalyRule_LargeBufferRegistration);
            scoreAdjust += 15;
            MonProfileLogAnomalyEvent(Profile, MonAnomalyRule_LargeBufferRegistration,
                Profile->MaxBufferSize / (1024 * 1024), 100);
        }
    }

    /* Rule 3: Rapid handle creation (>10 in history) */
    if (Profile->TotalHandlesCreated > 10 && Profile->ActiveHandleCount > 5) {
        if (!(Profile->TriggeredRules & (1 << MonAnomalyRule_RapidHandleCreation))) {
            Profile->TriggeredRules |= (1 << MonAnomalyRule_RapidHandleCreation);
            scoreAdjust += 10;
            MonProfileLogAnomalyEvent(Profile, MonAnomalyRule_RapidHandleCreation,
                Profile->TotalHandlesCreated, 10);
        }
    }

    /* Rule 7: Violation accumulation (>5 violations) */
    if (Profile->ViolationCount > 5) {
        if (!(Profile->TriggeredRules & (1 << MonAnomalyRule_ViolationAccumulation))) {
            Profile->TriggeredRules |= (1 << MonAnomalyRule_ViolationAccumulation);
            scoreAdjust += 25;
            MonProfileLogAnomalyEvent(Profile, MonAnomalyRule_ViolationAccumulation,
                Profile->ViolationCount, 5);
        }
    }

    /* Apply score adjustment */
    if (scoreAdjust > 0) {
        LONG newScore = InterlockedAdd(&Profile->AnomalyScore, scoreAdjust);
        if (newScore > 100) {
            InterlockedExchange(&Profile->AnomalyScore, 100);
        }
        InterlockedIncrement(&g_ProfileState.TotalAnomaliesDetected);
        InterlockedIncrement((volatile LONG*)&Profile->AnomalyEventCount);
    }

    /* Decay score over time (gradual recovery) */
    if (oldScore > 0 && scoreAdjust == 0) {
        if (Profile->TotalOperations % 1000 == 0) {
            InterlockedDecrement(&Profile->AnomalyScore);
        }
    }

    /* Auto-blacklist check */
    if (g_ProfileState.Config.AutoBlacklist &&
        Profile->AnomalyScore >= (LONG)g_ProfileState.Config.BlacklistThreshold) {
        if (!(Profile->Flags & MON_PROFILE_FLAG_BLACKLISTED)) {
            Profile->Flags |= MON_PROFILE_FLAG_BLACKLISTED;
            if (MonInterceptIsInitialized()) {
                MonInterceptAddToBlacklist(Profile->ProcessId, Profile->ImageName,
                    "Auto-blacklisted due to high anomaly score");
            }
        }
    }
}

static VOID
MonProfileLogAnomalyEvent(
    _In_ PMON_PROCESS_PROFILE Profile,
    _In_ MON_ANOMALY_RULE_ID RuleId,
    _In_ ULONG ActualValue,
    _In_ ULONG Threshold
)
{
    MON_ANOMALY_EVENT_DATA eventData;
    LARGE_INTEGER currentTime;

    if (!MonRingBufferIsInitialized()) {
        return;
    }

    KeQuerySystemTime(&currentTime);

    RtlZeroMemory(&eventData, sizeof(eventData));
    eventData.Size = sizeof(eventData);
    eventData.ProcessId = Profile->ProcessId;
    eventData.RuleId = (ULONG)RuleId;
    eventData.AnomalyScore = (ULONG)Profile->AnomalyScore;
    eventData.ThresholdExceeded = Threshold;
    eventData.ActualValue = ActualValue;
    eventData.Timestamp = currentTime.QuadPart;

    /* Set rule name based on ID */
    switch (RuleId) {
        case MonAnomalyRule_HighOpsFrequency:
            RtlStringCchCopyW(eventData.RuleName, 32, L"HighOpsFrequency");
            RtlStringCchCopyA(eventData.MitreTechnique, 16, "T1499");
            eventData.Severity = MonSeverity_Medium;
            break;
        case MonAnomalyRule_LargeBufferRegistration:
            RtlStringCchCopyW(eventData.RuleName, 32, L"LargeBuffer");
            RtlStringCchCopyA(eventData.MitreTechnique, 16, "T1068");
            eventData.Severity = MonSeverity_Medium;
            break;
        case MonAnomalyRule_RapidHandleCreation:
            RtlStringCchCopyW(eventData.RuleName, 32, L"RapidHandles");
            RtlStringCchCopyA(eventData.MitreTechnique, 16, "T1499");
            eventData.Severity = MonSeverity_Low;
            break;
        case MonAnomalyRule_ViolationAccumulation:
            RtlStringCchCopyW(eventData.RuleName, 32, L"ViolationAccum");
            RtlStringCchCopyA(eventData.MitreTechnique, 16, "T1068");
            eventData.Severity = MonSeverity_High;
            break;
        default:
            RtlStringCchCopyW(eventData.RuleName, 32, L"Unknown");
            break;
    }

    MonRingBufferWrite(
        MonEvent_ProcessAnomalyDetected,
        &eventData,
        sizeof(eventData)
    );

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
        "[WIN11MON][PROFILE] Anomaly PID=%lu Rule=%ws Value=%lu>%lu Score=%ld\n",
        Profile->ProcessId, eventData.RuleName, ActualValue, Threshold,
        Profile->AnomalyScore);
}

/*==========================================================================
 * Profile Query APIs
 *=========================================================================*/

_Use_decl_annotations_
NTSTATUS
MonProfileGetSummary(
    ULONG ProcessId,
    PMON_PROFILE_SUMMARY Summary
)
{
    PMON_PROCESS_PROFILE profile;
    LARGE_INTEGER currentTime;

    if (Summary == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!MonProfileIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    RtlZeroMemory(Summary, sizeof(MON_PROFILE_SUMMARY));
    Summary->Size = sizeof(MON_PROFILE_SUMMARY);

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&g_ProfileState.ListLock, TRUE);

    profile = MonProfileFindByPidLocked(ProcessId);

    if (profile == NULL) {
        ExReleaseResourceLite(&g_ProfileState.ListLock);
        KeLeaveCriticalRegion();
        return STATUS_NOT_FOUND;
    }

    KeQuerySystemTime(&currentTime);

    /* Copy sanitized data */
    Summary->ProcessId = profile->ProcessId;
    RtlCopyMemory(Summary->ProcessName, profile->ImageName, sizeof(Summary->ProcessName));
    Summary->ActiveHandles = (ULONG)profile->ActiveHandleCount;
    Summary->TotalOperations = profile->TotalOperations;
    Summary->OpsPerSecond = MonProfileCalculateAverageOps(profile);
    Summary->TotalMemoryBytes = profile->TotalBufferBytesRegistered;
    Summary->AnomalyScore = (ULONG)profile->AnomalyScore;
    Summary->AnomalyEventCount = profile->AnomalyEventCount;
    Summary->ViolationCount = profile->ViolationCount;
    Summary->TriggeredRules = profile->TriggeredRules;
    Summary->FirstSeenTime = profile->FirstSeenTime;
    Summary->LastActivityTime = profile->LastActivityTime;
    Summary->Flags = profile->Flags;

    /* Calculate active duration */
    if (profile->FirstSeenTime > 0) {
        ULONG64 durationTicks = currentTime.QuadPart - profile->FirstSeenTime;
        Summary->ActiveDurationSec = (ULONG)(durationTicks / 10000000ULL);
    }

    ExReleaseResourceLite(&g_ProfileState.ListLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
MonProfileEnumerate(
    PMON_PROFILE_SUMMARY Buffer,
    ULONG MaxCount,
    ULONG* ActualCount
)
{
    PLIST_ENTRY entry;
    PMON_PROCESS_PROFILE profile;
    ULONG count = 0;
    LARGE_INTEGER currentTime;

    if (Buffer == NULL || ActualCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ActualCount = 0;

    if (!MonProfileIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    if (MaxCount == 0) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    KeQuerySystemTime(&currentTime);

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&g_ProfileState.ListLock, TRUE);

    for (entry = g_ProfileState.ProfileList.Flink;
         entry != &g_ProfileState.ProfileList && count < MaxCount;
         entry = entry->Flink) {

        profile = CONTAINING_RECORD(entry, MON_PROCESS_PROFILE, ListEntry);

        Buffer[count].Size = sizeof(MON_PROFILE_SUMMARY);
        Buffer[count].ProcessId = profile->ProcessId;
        RtlCopyMemory(Buffer[count].ProcessName, profile->ImageName,
                      sizeof(Buffer[count].ProcessName));
        Buffer[count].ActiveHandles = (ULONG)profile->ActiveHandleCount;
        Buffer[count].TotalOperations = profile->TotalOperations;
        Buffer[count].OpsPerSecond = MonProfileCalculateAverageOps(profile);
        Buffer[count].TotalMemoryBytes = profile->TotalBufferBytesRegistered;
        Buffer[count].AnomalyScore = (ULONG)profile->AnomalyScore;
        Buffer[count].AnomalyEventCount = profile->AnomalyEventCount;
        Buffer[count].ViolationCount = profile->ViolationCount;
        Buffer[count].TriggeredRules = profile->TriggeredRules;
        Buffer[count].FirstSeenTime = profile->FirstSeenTime;
        Buffer[count].LastActivityTime = profile->LastActivityTime;
        Buffer[count].Flags = profile->Flags;

        if (profile->FirstSeenTime > 0) {
            ULONG64 durationTicks = currentTime.QuadPart - profile->FirstSeenTime;
            Buffer[count].ActiveDurationSec = (ULONG)(durationTicks / 10000000ULL);
        }

        count++;
    }

    ExReleaseResourceLite(&g_ProfileState.ListLock);
    KeLeaveCriticalRegion();

    *ActualCount = count;
    return STATUS_SUCCESS;
}

/*==========================================================================
 * ML Feature Export
 *=========================================================================*/

_Use_decl_annotations_
NTSTATUS
MonProfileExportFeatures(
    ULONG ProcessId,
    PMON_ML_FEATURE_VECTOR Features
)
{
    PMON_PROCESS_PROFILE profile;
    LARGE_INTEGER currentTime;

    if (Features == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!MonProfileIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    RtlZeroMemory(Features, sizeof(MON_ML_FEATURE_VECTOR));
    Features->Size = sizeof(MON_ML_FEATURE_VECTOR);
    Features->Version = MON_PROFILE_ML_FEATURE_VERSION;

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&g_ProfileState.ListLock, TRUE);

    profile = MonProfileFindByPidLocked(ProcessId);

    if (profile == NULL) {
        ExReleaseResourceLite(&g_ProfileState.ListLock);
        KeLeaveCriticalRegion();
        return STATUS_NOT_FOUND;
    }

    KeQuerySystemTime(&currentTime);
    Features->Timestamp = currentTime.QuadPart;
    Features->ProcessId = profile->ProcessId;

    /* Calculate normalized features */
    Features->OpsPerSecond = (float)MonProfileCalculateAverageOps(profile);
    Features->HandleCount = (float)profile->ActiveHandleCount;
    Features->MaxBufferSizeMB = (float)profile->MaxBufferSize / (1024.0f * 1024.0f);
    Features->TotalMemoryMB = (float)profile->TotalBufferBytesRegistered / (1024.0f * 1024.0f);

    /* Read/Write ratio (0.0 to 1.0) */
    ULONG64 totalRW = profile->TotalReads + profile->TotalWrites;
    if (totalRW > 0) {
        Features->ReadWriteRatio = (float)profile->TotalReads / (float)totalRW;
    }

    /* Average buffer size */
    if (profile->TotalBuffersRegistered > 0) {
        Features->AvgBufferSizeKB = (float)(profile->TotalBufferBytesRegistered /
            profile->TotalBuffersRegistered) / 1024.0f;
    }

    Features->RegisteredFiles = (float)profile->TotalFilesRegistered;
    Features->BurstFrequency = (float)profile->BurstCount;
    Features->AnomalyScore = (ULONG)profile->AnomalyScore;

    /* Violation rate per 1000 ops */
    if (profile->TotalOperations > 0) {
        Features->ViolationRate = (float)profile->ViolationCount * 1000.0f /
            (float)profile->TotalOperations;
    }

    /* Active duration in minutes */
    if (profile->FirstSeenTime > 0) {
        ULONG64 durationTicks = currentTime.QuadPart - profile->FirstSeenTime;
        Features->ActiveDurationMin = (float)(durationTicks / 10000000ULL) / 60.0f;
    }

    /* Categorical features */
    Features->ProcessElevation = (profile->Flags & MON_PROFILE_FLAG_ELEVATED) ? 1 : 0;
    Features->ProcessInteractive = (profile->Flags & MON_PROFILE_FLAG_NON_INTERACTIVE) ? 0 : 1;
    Features->ProcessIsService = (profile->Flags & MON_PROFILE_FLAG_SERVICE) ? 1 : 0;

    /* Mark as exported */
    profile->Flags |= MON_PROFILE_FLAG_EXPORTED;
    profile->LastExportTime = currentTime.QuadPart;
    InterlockedIncrement64(&g_ProfileState.TotalExports);

    ExReleaseResourceLite(&g_ProfileState.ListLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

/*==========================================================================
 * Statistics and Configuration
 *=========================================================================*/

_Use_decl_annotations_
VOID
MonProfileGetStats(
    PMON_PROFILE_STATS Stats
)
{
    if (Stats == NULL) {
        return;
    }

    RtlZeroMemory(Stats, sizeof(MON_PROFILE_STATS));
    Stats->Size = sizeof(MON_PROFILE_STATS);

    if (!MonProfileIsInitialized()) {
        return;
    }

    Stats->ActiveProfiles = (ULONG)g_ProfileState.ProfileCount;
    Stats->TotalProfilesCreated = (ULONG)g_ProfileState.TotalProfilesCreated;
    Stats->TotalProfilesDestroyed = (ULONG)g_ProfileState.TotalProfilesDestroyed;
    Stats->TotalAnomaliesDetected = (ULONG)g_ProfileState.TotalAnomaliesDetected;
    Stats->TotalUpdates = g_ProfileState.TotalUpdates;
    Stats->TotalExports = g_ProfileState.TotalExports;
}

_Use_decl_annotations_
NTSTATUS
MonProfileSetConfig(
    PMON_PROFILE_CONFIG Config
)
{
    if (Config == NULL || Config->Size != sizeof(MON_PROFILE_CONFIG)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!MonProfileIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&g_ProfileState.ListLock, TRUE);

    RtlCopyMemory(&g_ProfileState.Config, Config, sizeof(MON_PROFILE_CONFIG));

    ExReleaseResourceLite(&g_ProfileState.ListLock);
    KeLeaveCriticalRegion();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][PROFILE] Config updated (enabled=%d, threshold=%lu)\n",
        Config->Enabled, Config->AnomalyThreshold);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
MonProfileGetConfig(
    PMON_PROFILE_CONFIG Config
)
{
    if (Config == NULL) {
        return;
    }

    if (!MonProfileIsInitialized()) {
        RtlZeroMemory(Config, sizeof(MON_PROFILE_CONFIG));
        Config->Size = sizeof(MON_PROFILE_CONFIG);
        return;
    }

    RtlCopyMemory(Config, &g_ProfileState.Config, sizeof(MON_PROFILE_CONFIG));
}

_Use_decl_annotations_
VOID MonProfileResetAll(VOID)
{
    PLIST_ENTRY entry;
    PMON_PROCESS_PROFILE profile;

    if (!MonProfileIsInitialized()) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&g_ProfileState.ListLock, TRUE);

    for (entry = g_ProfileState.ProfileList.Flink;
         entry != &g_ProfileState.ProfileList;
         entry = entry->Flink) {

        profile = CONTAINING_RECORD(entry, MON_PROCESS_PROFILE, ListEntry);

        /* Reset counters but keep profile */
        InterlockedExchange64(&profile->TotalOperations, 0);
        InterlockedExchange64((volatile LONG64*)&profile->TotalReads, 0);
        InterlockedExchange64((volatile LONG64*)&profile->TotalWrites, 0);
        InterlockedExchange64((volatile LONG64*)&profile->TotalCancels, 0);
        InterlockedExchange64((volatile LONG64*)&profile->TotalOther, 0);
        InterlockedExchange(&profile->AnomalyScore, 0);
        profile->AnomalyEventCount = 0;
        profile->ViolationCount = 0;
        profile->BurstCount = 0;
        profile->TriggeredRules = 0;

        RtlZeroMemory(profile->OpsHistory, sizeof(profile->OpsHistory));
        profile->OpsCurrentSecond = 0;
        profile->HistoryIndex = 0;
    }

    ExReleaseResourceLite(&g_ProfileState.ListLock);
    KeLeaveCriticalRegion();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][PROFILE] All profiles reset\n");
}

#pragma warning(pop)
