/*
 * Anomaly Rules Engine - Implementation
 *
 * Author: Colin MacRitchie | ziX Labs
 * Organization: ziX Labs - Security Research Division
 * File: anomaly_rules.c
 * Version: 1.0
 * Date: 2025-11-30
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and confidential.
 *   Redistribution or disclosure without prior written consent is prohibited.
 *
 * Summary
 * -------
 * Extensible rule evaluation engine for process behavior anomaly detection.
 * Supports built-in rules, custom rules, and threshold configuration.
 *
 * Threading Model:
 * - Rule list: FAST_MUTEX for modifications (infrequent)
 * - Evaluation: Lock-free snapshot-based
 */

#include <ntddk.h>
#include <ntstrsafe.h>
#include "anomaly_rules.h"
#include "process_profile.h"
#include "telemetry_ringbuf.h"

#pragma warning(push)
#pragma warning(disable: 4201) /* nameless struct/union */

/*--------------------------------------------------------------------------
 * Module State
 *-------------------------------------------------------------------------*/
typedef struct _MON_ANOMALY_STATE {
    volatile LONG   Initialized;
    FAST_MUTEX      RuleMutex;          /* Protects rule modifications */
    MON_ANOMALY_RULE Rules[MON_ANOMALY_MAX_RULES];
    ULONG           RuleCount;

    /* Statistics */
    volatile LONG   TotalEvaluations;
    volatile LONG   TotalMatches;
    volatile LONG   RulesDisabled;

} MON_ANOMALY_STATE, *PMON_ANOMALY_STATE;

static MON_ANOMALY_STATE g_AnomalyState = {0};

/*--------------------------------------------------------------------------
 * Built-in Rule Definitions
 *-------------------------------------------------------------------------*/
typedef struct _BUILTIN_RULE_DEF {
    MON_ANOMALY_RULE_ID RuleId;
    const WCHAR*        Name;
    ULONG               Threshold;
    ULONG               WindowSec;
    MON_ANOMALY_SEVERITY Severity;
    ULONG               ScoreImpact;
    const CHAR*         MitreTechnique;
} BUILTIN_RULE_DEF;

static const BUILTIN_RULE_DEF g_BuiltinRules[] = {
    { MonAnomalyRule_HighOpsFrequency,
      L"HighOpsFrequency", 1000, 5, MonSeverity_Medium, 20, "T1499" },

    { MonAnomalyRule_LargeBufferRegistration,
      L"LargeBuffer", 100 * 1024 * 1024, 0, MonSeverity_Medium, 15, "T1068" },

    { MonAnomalyRule_RapidHandleCreation,
      L"RapidHandles", 10, 1, MonSeverity_Low, 10, "T1499" },

    { MonAnomalyRule_ElevatedIoRingAbuse,
      L"ElevatedAbuse", 1, 0, MonSeverity_High, 25, "T1548" },

    { MonAnomalyRule_BurstPattern,
      L"BurstPattern", 500, 0, MonSeverity_Medium, 15, "T1499" },

    { MonAnomalyRule_ConcurrentTargets,
      L"ConcurrentFiles", 50, 60, MonSeverity_Medium, 15, "T1083" },

    { MonAnomalyRule_ViolationAccumulation,
      L"ViolationAccum", 5, 0, MonSeverity_High, 25, "T1068" },
};

#define BUILTIN_RULE_COUNT (sizeof(g_BuiltinRules) / sizeof(g_BuiltinRules[0]))

/*--------------------------------------------------------------------------
 * Forward Declarations
 *-------------------------------------------------------------------------*/
static BOOLEAN MonAnomalyEvaluateSingleRule(
    _In_ const MON_ANOMALY_RULE* Rule,
    _In_ const MON_PROCESS_PROFILE* Profile,
    _In_ ULONG OpsPerSecond,
    _Out_ ULONG* ActualValue
);

/*==========================================================================
 * Initialization and Shutdown
 *=========================================================================*/

_Use_decl_annotations_
NTSTATUS MonAnomalyInitialize(VOID)
{
    ULONG i;

    if (InterlockedCompareExchange(&g_AnomalyState.Initialized, 0, 0) != 0) {
        return STATUS_SUCCESS;
    }

    /* Initialize mutex */
    ExInitializeFastMutex(&g_AnomalyState.RuleMutex);

    /* Initialize rule storage */
    RtlZeroMemory(g_AnomalyState.Rules, sizeof(g_AnomalyState.Rules));
    g_AnomalyState.RuleCount = 0;

    /* Register built-in rules */
    for (i = 0; i < BUILTIN_RULE_COUNT; i++) {
        const BUILTIN_RULE_DEF* def = &g_BuiltinRules[i];
        MON_ANOMALY_RULE* rule = &g_AnomalyState.Rules[g_AnomalyState.RuleCount];

        rule->RuleId = def->RuleId;
        RtlStringCchCopyW(rule->RuleName, 32, def->Name);
        rule->Threshold = def->Threshold;
        rule->WindowSeconds = def->WindowSec;
        rule->Severity = def->Severity;
        rule->ScoreImpact = def->ScoreImpact;
        rule->Enabled = TRUE;
        RtlStringCchCopyA(rule->MitreTechnique, 16, def->MitreTechnique);

        g_AnomalyState.RuleCount++;
    }

    InterlockedExchange(&g_AnomalyState.Initialized, 1);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][ANOMALY] Initialized with %lu built-in rules\n",
        g_AnomalyState.RuleCount);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID MonAnomalyShutdown(VOID)
{
    if (InterlockedCompareExchange(&g_AnomalyState.Initialized, 0, 0) == 0) {
        return;
    }

    InterlockedExchange(&g_AnomalyState.Initialized, 0);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][ANOMALY] Shutdown (evals=%ld, matches=%ld)\n",
        g_AnomalyState.TotalEvaluations,
        g_AnomalyState.TotalMatches);
}

_Use_decl_annotations_
BOOLEAN MonAnomalyIsInitialized(VOID)
{
    return InterlockedCompareExchange(&g_AnomalyState.Initialized, 0, 0) != 0;
}

/*==========================================================================
 * Rule Evaluation Engine
 *=========================================================================*/

_Use_decl_annotations_
ULONG
MonAnomalyEvaluate(
    const MON_PROCESS_PROFILE* Profile,
    ULONG OpsPerSecond,
    ULONG* TriggeredRules,
    MON_ANOMALY_RESULT* Results,
    ULONG MaxResults
)
{
    ULONG matchCount = 0;
    ULONG triggeredMask = 0;
    ULONG i;

    if (Profile == NULL || !MonAnomalyIsInitialized()) {
        if (TriggeredRules) *TriggeredRules = 0;
        return 0;
    }

    InterlockedIncrement(&g_AnomalyState.TotalEvaluations);

    /* Evaluate each enabled rule */
    for (i = 0; i < g_AnomalyState.RuleCount && matchCount < MaxResults; i++) {
        const MON_ANOMALY_RULE* rule = &g_AnomalyState.Rules[i];
        ULONG actualValue = 0;

        if (!rule->Enabled) {
            continue;
        }

        if (MonAnomalyEvaluateSingleRule(rule, Profile, OpsPerSecond, &actualValue)) {
            triggeredMask |= (1 << rule->RuleId);

            if (Results != NULL && matchCount < MaxResults) {
                Results[matchCount].RuleId = rule->RuleId;
                Results[matchCount].Threshold = rule->Threshold;
                Results[matchCount].ActualValue = actualValue;
                Results[matchCount].Severity = rule->Severity;
                Results[matchCount].ScoreImpact = rule->ScoreImpact;
            }

            matchCount++;
            InterlockedIncrement(&g_AnomalyState.TotalMatches);
        }
    }

    if (TriggeredRules != NULL) {
        *TriggeredRules = triggeredMask;
    }

    return matchCount;
}

static BOOLEAN
MonAnomalyEvaluateSingleRule(
    _In_ const MON_ANOMALY_RULE* Rule,
    _In_ const MON_PROCESS_PROFILE* Profile,
    _In_ ULONG OpsPerSecond,
    _Out_ ULONG* ActualValue
)
{
    *ActualValue = 0;

    switch (Rule->RuleId) {

    case MonAnomalyRule_HighOpsFrequency:
        *ActualValue = OpsPerSecond;
        return (OpsPerSecond > Rule->Threshold);

    case MonAnomalyRule_LargeBufferRegistration:
        *ActualValue = Profile->MaxBufferSize;
        return (Profile->MaxBufferSize > Rule->Threshold);

    case MonAnomalyRule_RapidHandleCreation:
        *ActualValue = Profile->TotalHandlesCreated;
        return (Profile->TotalHandlesCreated > Rule->Threshold &&
                Profile->ActiveHandleCount > 5);

    case MonAnomalyRule_ElevatedIoRingAbuse:
        if ((Profile->Flags & MON_PROFILE_FLAG_ELEVATED) &&
            (Profile->Flags & MON_PROFILE_FLAG_NON_INTERACTIVE)) {
            *ActualValue = 1;
            return TRUE;
        }
        return FALSE;

    case MonAnomalyRule_BurstPattern:
        *ActualValue = Profile->BurstCount;
        return (Profile->BurstCount >= 3);

    case MonAnomalyRule_ConcurrentTargets:
        *ActualValue = Profile->TotalFilesRegistered;
        return (Profile->TotalFilesRegistered > Rule->Threshold);

    case MonAnomalyRule_ViolationAccumulation:
        *ActualValue = Profile->ViolationCount;
        return (Profile->ViolationCount > Rule->Threshold);

    default:
        return FALSE;
    }
}

/*==========================================================================
 * Rule Management
 *=========================================================================*/

_Use_decl_annotations_
NTSTATUS
MonAnomalyGetRule(
    MON_ANOMALY_RULE_ID RuleId,
    PMON_ANOMALY_RULE Rule
)
{
    ULONG i;

    if (Rule == NULL || !MonAnomalyIsInitialized()) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquireFastMutex(&g_AnomalyState.RuleMutex);

    for (i = 0; i < g_AnomalyState.RuleCount; i++) {
        if (g_AnomalyState.Rules[i].RuleId == RuleId) {
            RtlCopyMemory(Rule, &g_AnomalyState.Rules[i], sizeof(MON_ANOMALY_RULE));
            ExReleaseFastMutex(&g_AnomalyState.RuleMutex);
            return STATUS_SUCCESS;
        }
    }

    ExReleaseFastMutex(&g_AnomalyState.RuleMutex);
    return STATUS_NOT_FOUND;
}

_Use_decl_annotations_
NTSTATUS
MonAnomalySetThreshold(
    MON_ANOMALY_RULE_ID RuleId,
    ULONG Threshold
)
{
    ULONG i;

    if (!MonAnomalyIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    ExAcquireFastMutex(&g_AnomalyState.RuleMutex);

    for (i = 0; i < g_AnomalyState.RuleCount; i++) {
        if (g_AnomalyState.Rules[i].RuleId == RuleId) {
            g_AnomalyState.Rules[i].Threshold = Threshold;
            ExReleaseFastMutex(&g_AnomalyState.RuleMutex);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[WIN11MON][ANOMALY] Rule %lu threshold set to %lu\n",
                (ULONG)RuleId, Threshold);

            return STATUS_SUCCESS;
        }
    }

    ExReleaseFastMutex(&g_AnomalyState.RuleMutex);
    return STATUS_NOT_FOUND;
}

_Use_decl_annotations_
NTSTATUS
MonAnomalyEnableRule(
    MON_ANOMALY_RULE_ID RuleId,
    BOOLEAN Enable
)
{
    ULONG i;

    if (!MonAnomalyIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    ExAcquireFastMutex(&g_AnomalyState.RuleMutex);

    for (i = 0; i < g_AnomalyState.RuleCount; i++) {
        if (g_AnomalyState.Rules[i].RuleId == RuleId) {
            BOOLEAN wasEnabled = g_AnomalyState.Rules[i].Enabled;
            g_AnomalyState.Rules[i].Enabled = Enable;

            if (wasEnabled && !Enable) {
                InterlockedIncrement(&g_AnomalyState.RulesDisabled);
            } else if (!wasEnabled && Enable) {
                InterlockedDecrement(&g_AnomalyState.RulesDisabled);
            }

            ExReleaseFastMutex(&g_AnomalyState.RuleMutex);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[WIN11MON][ANOMALY] Rule %lu %s\n",
                (ULONG)RuleId, Enable ? "enabled" : "disabled");

            return STATUS_SUCCESS;
        }
    }

    ExReleaseFastMutex(&g_AnomalyState.RuleMutex);
    return STATUS_NOT_FOUND;
}

_Use_decl_annotations_
NTSTATUS
MonAnomalyAddRule(
    const MON_ANOMALY_RULE* NewRule
)
{
    ULONG i;

    if (NewRule == NULL || !MonAnomalyIsInitialized()) {
        return STATUS_INVALID_PARAMETER;
    }

    if (NewRule->RuleId == MonAnomalyRule_None ||
        NewRule->RuleId >= MonAnomalyRule_Max) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquireFastMutex(&g_AnomalyState.RuleMutex);

    /* Check for duplicate */
    for (i = 0; i < g_AnomalyState.RuleCount; i++) {
        if (g_AnomalyState.Rules[i].RuleId == NewRule->RuleId) {
            ExReleaseFastMutex(&g_AnomalyState.RuleMutex);
            return STATUS_DUPLICATE_OBJECTID;
        }
    }

    /* Check capacity */
    if (g_AnomalyState.RuleCount >= MON_ANOMALY_MAX_RULES) {
        ExReleaseFastMutex(&g_AnomalyState.RuleMutex);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Add rule */
    RtlCopyMemory(&g_AnomalyState.Rules[g_AnomalyState.RuleCount],
                  NewRule, sizeof(MON_ANOMALY_RULE));
    g_AnomalyState.RuleCount++;

    ExReleaseFastMutex(&g_AnomalyState.RuleMutex);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][ANOMALY] Added rule %lu: %ws\n",
        (ULONG)NewRule->RuleId, NewRule->RuleName);

    return STATUS_SUCCESS;
}

/*==========================================================================
 * Rule Enumeration
 *=========================================================================*/

_Use_decl_annotations_
NTSTATUS
MonAnomalyEnumerateRules(
    PMON_ANOMALY_RULE Buffer,
    ULONG MaxCount,
    ULONG* ActualCount
)
{
    ULONG copyCount;

    if (Buffer == NULL || ActualCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ActualCount = 0;

    if (!MonAnomalyIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    ExAcquireFastMutex(&g_AnomalyState.RuleMutex);

    copyCount = min(MaxCount, g_AnomalyState.RuleCount);
    if (copyCount > 0) {
        RtlCopyMemory(Buffer, g_AnomalyState.Rules,
                      copyCount * sizeof(MON_ANOMALY_RULE));
    }
    *ActualCount = copyCount;

    ExReleaseFastMutex(&g_AnomalyState.RuleMutex);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
ULONG MonAnomalyGetRuleCount(VOID)
{
    if (!MonAnomalyIsInitialized()) {
        return 0;
    }
    return g_AnomalyState.RuleCount;
}

/*==========================================================================
 * Statistics
 *=========================================================================*/

_Use_decl_annotations_
VOID
MonAnomalyGetStats(
    PMON_ANOMALY_STATS Stats
)
{
    if (Stats == NULL) {
        return;
    }

    RtlZeroMemory(Stats, sizeof(MON_ANOMALY_STATS));
    Stats->Size = sizeof(MON_ANOMALY_STATS);

    if (!MonAnomalyIsInitialized()) {
        return;
    }

    Stats->TotalRules = g_AnomalyState.RuleCount;
    Stats->EnabledRules = g_AnomalyState.RuleCount -
                          (ULONG)g_AnomalyState.RulesDisabled;
    Stats->TotalEvaluations = (ULONG)g_AnomalyState.TotalEvaluations;
    Stats->TotalMatches = (ULONG)g_AnomalyState.TotalMatches;
}

_Use_decl_annotations_
VOID MonAnomalyResetStats(VOID)
{
    if (!MonAnomalyIsInitialized()) {
        return;
    }

    InterlockedExchange(&g_AnomalyState.TotalEvaluations, 0);
    InterlockedExchange(&g_AnomalyState.TotalMatches, 0);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][ANOMALY] Statistics reset\n");
}

#pragma warning(pop)
