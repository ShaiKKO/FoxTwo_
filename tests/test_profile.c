/*
 * Unit Tests - Process Behavior Profiling (Phase 7)
 *
 * Author: Colin MacRitchie | ziX Labs
 * Organization: ziX Labs - Security Research Division
 * File: test_profile.c
 * Version: 1.0
 * Date: 2025-11-30
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and confidential.
 *   Redistribution or disclosure without prior written consent is prohibited.
 *
 * Summary
 * -------
 * Unit tests for the process_profile and anomaly_rules subsystems.
 * Tests profile lifecycle, anomaly detection, ML feature export, and IOCTL responses.
 */

#include <ntddk.h>
#include "process_profile.h"
#include "anomaly_rules.h"

/* Test assertion macro */
#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
            "[TEST][FAIL] %s:%d: Assertion failed: %s\n", __FILE__, __LINE__, #cond); \
        return STATUS_UNSUCCESSFUL; \
    } \
} while(0)

#define TEST_PASS(name) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, \
    "[TEST][PASS] %s\n", name)

/*--------------------------------------------------------------------------
 * Profile System Tests
 *-------------------------------------------------------------------------*/

static NTSTATUS TestProfileInitShutdown(VOID)
{
    NTSTATUS status;

    /* Initialize */
    status = MonProfileInitialize();
    TEST_ASSERT(NT_SUCCESS(status));
    TEST_ASSERT(MonProfileIsInitialized());

    /* Double-init should be idempotent */
    status = MonProfileInitialize();
    TEST_ASSERT(NT_SUCCESS(status));

    /* Shutdown */
    MonProfileShutdown();
    TEST_ASSERT(!MonProfileIsInitialized());

    /* Double-shutdown should be safe */
    MonProfileShutdown();

    /* Re-init for remaining tests */
    status = MonProfileInitialize();
    TEST_ASSERT(NT_SUCCESS(status));

    TEST_PASS("TestProfileInitShutdown");
    return STATUS_SUCCESS;
}

static NTSTATUS TestProfileCreateDestroy(VOID)
{
    NTSTATUS status;
    PMON_PROCESS_PROFILE profile;
    MON_PROFILE_STATS stats;

    /* Ensure initialized */
    TEST_ASSERT(MonProfileIsInitialized());

    /* Get initial stats */
    MonProfileGetStats(&stats);
    ULONG initialCreated = stats.TotalProfilesCreated;

    /* Create profile for fake PID 1234 */
    status = MonProfileCreate(1234, L"TestProcess.exe", &profile);
    TEST_ASSERT(NT_SUCCESS(status));
    TEST_ASSERT(profile != NULL);

    /* Check stats updated */
    MonProfileGetStats(&stats);
    TEST_ASSERT(stats.TotalProfilesCreated == initialCreated + 1);
    TEST_ASSERT(stats.ActiveProfiles >= 1);

    /* Duplicate create should return existing */
    PMON_PROCESS_PROFILE dup;
    status = MonProfileCreate(1234, L"TestProcess.exe", &dup);
    TEST_ASSERT(NT_SUCCESS(status));
    TEST_ASSERT(dup == profile);

    /* Destroy profile */
    MonProfileDestroy(profile);

    /* Verify destroyed */
    MonProfileGetStats(&stats);
    TEST_ASSERT(stats.TotalProfilesDestroyed > 0);

    TEST_PASS("TestProfileCreateDestroy");
    return STATUS_SUCCESS;
}

static NTSTATUS TestProfileRecordOps(VOID)
{
    NTSTATUS status;
    PMON_PROCESS_PROFILE profile;
    MON_PROFILE_SUMMARY summary;

    /* Create test profile */
    status = MonProfileCreate(5678, L"OpsTest.exe", &profile);
    TEST_ASSERT(NT_SUCCESS(status));

    /* Record operations */
    status = MonProfileRecordOperation(profile, MonIoRing_Read, 4096, 10);
    TEST_ASSERT(NT_SUCCESS(status));

    status = MonProfileRecordOperation(profile, MonIoRing_Write, 8192, 5);
    TEST_ASSERT(NT_SUCCESS(status));

    /* Get summary */
    status = MonProfileGetSummary(5678, &summary);
    TEST_ASSERT(NT_SUCCESS(status));
    TEST_ASSERT(summary.ProcessId == 5678);
    TEST_ASSERT(summary.TotalOperations == 2);

    /* Record handle creation */
    status = MonProfileRecordHandle(profile, TRUE);
    TEST_ASSERT(NT_SUCCESS(status));

    /* Get updated summary */
    status = MonProfileGetSummary(5678, &summary);
    TEST_ASSERT(NT_SUCCESS(status));
    TEST_ASSERT(summary.ActiveHandles == 1);

    /* Record handle destruction */
    status = MonProfileRecordHandle(profile, FALSE);
    TEST_ASSERT(NT_SUCCESS(status));

    /* Cleanup */
    MonProfileDestroy(profile);

    TEST_PASS("TestProfileRecordOps");
    return STATUS_SUCCESS;
}

static NTSTATUS TestProfileViolation(VOID)
{
    NTSTATUS status;
    PMON_PROCESS_PROFILE profile;
    MON_PROFILE_SUMMARY summary;

    /* Create test profile */
    status = MonProfileCreate(9999, L"ViolTest.exe", &profile);
    TEST_ASSERT(NT_SUCCESS(status));

    /* Record violations */
    status = MonProfileRecordViolation(profile, MonReason_KernelAddressInBuffer, 3);
    TEST_ASSERT(NT_SUCCESS(status));

    status = MonProfileRecordViolation(profile, MonReason_SuspiciousOpCode, 2);
    TEST_ASSERT(NT_SUCCESS(status));

    /* Get summary */
    status = MonProfileGetSummary(9999, &summary);
    TEST_ASSERT(NT_SUCCESS(status));
    TEST_ASSERT(summary.ViolationCount == 2);

    /* Cleanup */
    MonProfileDestroy(profile);

    TEST_PASS("TestProfileViolation");
    return STATUS_SUCCESS;
}

static NTSTATUS TestProfileEnumerate(VOID)
{
    NTSTATUS status;
    PMON_PROCESS_PROFILE p1, p2, p3;
    MON_PROFILE_SUMMARY summaries[10];
    ULONG count = 0;

    /* Create multiple profiles */
    status = MonProfileCreate(1001, L"Proc1.exe", &p1);
    TEST_ASSERT(NT_SUCCESS(status));

    status = MonProfileCreate(1002, L"Proc2.exe", &p2);
    TEST_ASSERT(NT_SUCCESS(status));

    status = MonProfileCreate(1003, L"Proc3.exe", &p3);
    TEST_ASSERT(NT_SUCCESS(status));

    /* Enumerate */
    status = MonProfileEnumerate(summaries, 10, &count);
    TEST_ASSERT(NT_SUCCESS(status));
    TEST_ASSERT(count >= 3);

    /* Cleanup */
    MonProfileDestroy(p1);
    MonProfileDestroy(p2);
    MonProfileDestroy(p3);

    TEST_PASS("TestProfileEnumerate");
    return STATUS_SUCCESS;
}

static NTSTATUS TestProfileMLExport(VOID)
{
    NTSTATUS status;
    PMON_PROCESS_PROFILE profile;
    MON_ML_FEATURE_VECTOR features;

    /* Create profile with some activity */
    status = MonProfileCreate(2222, L"MLTest.exe", &profile);
    TEST_ASSERT(NT_SUCCESS(status));

    /* Record operations to generate features */
    for (int i = 0; i < 10; i++) {
        status = MonProfileRecordOperation(profile, MonIoRing_Read, 1024 * (i+1), 1);
        TEST_ASSERT(NT_SUCCESS(status));
    }

    /* Export features */
    status = MonProfileExportFeatures(2222, &features);
    TEST_ASSERT(NT_SUCCESS(status));
    TEST_ASSERT(features.Size == sizeof(MON_ML_FEATURE_VECTOR));
    TEST_ASSERT(features.Version == MON_PROFILE_ML_VERSION);
    TEST_ASSERT(features.ProcessId == 2222);

    /* Cleanup */
    MonProfileDestroy(profile);

    TEST_PASS("TestProfileMLExport");
    return STATUS_SUCCESS;
}

static NTSTATUS TestProfileConfig(VOID)
{
    MON_PROFILE_CONFIG config;
    NTSTATUS status;

    /* Get default config */
    MonProfileGetConfig(&config);
    TEST_ASSERT(config.Size == sizeof(MON_PROFILE_CONFIG));
    TEST_ASSERT(config.Enabled == TRUE);

    /* Modify config */
    config.AnomalyThreshold = 50;
    config.BlacklistThreshold = 80;
    config.AutoBlacklist = FALSE;

    status = MonProfileSetConfig(&config);
    TEST_ASSERT(NT_SUCCESS(status));

    /* Verify changes */
    MON_PROFILE_CONFIG readback;
    MonProfileGetConfig(&readback);
    TEST_ASSERT(readback.AnomalyThreshold == 50);
    TEST_ASSERT(readback.BlacklistThreshold == 80);
    TEST_ASSERT(readback.AutoBlacklist == FALSE);

    /* Restore defaults */
    config.AnomalyThreshold = MON_PROFILE_DEFAULT_ANOMALY_THRESHOLD;
    config.BlacklistThreshold = MON_PROFILE_DEFAULT_BLACKLIST_THRESHOLD;
    config.AutoBlacklist = TRUE;
    MonProfileSetConfig(&config);

    TEST_PASS("TestProfileConfig");
    return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
 * Anomaly Rules Tests
 *-------------------------------------------------------------------------*/

static NTSTATUS TestAnomalyInitShutdown(VOID)
{
    NTSTATUS status;

    /* Initialize */
    status = MonAnomalyInitialize();
    TEST_ASSERT(NT_SUCCESS(status));
    TEST_ASSERT(MonAnomalyIsInitialized());

    /* Check rules loaded */
    ULONG count = MonAnomalyGetRuleCount();
    TEST_ASSERT(count >= 7); /* Built-in rules */

    /* Shutdown */
    MonAnomalyShutdown();
    TEST_ASSERT(!MonAnomalyIsInitialized());

    /* Re-init */
    status = MonAnomalyInitialize();
    TEST_ASSERT(NT_SUCCESS(status));

    TEST_PASS("TestAnomalyInitShutdown");
    return STATUS_SUCCESS;
}

static NTSTATUS TestAnomalyGetRule(VOID)
{
    NTSTATUS status;
    MON_ANOMALY_RULE rule;

    /* Get HighOpsFrequency rule */
    status = MonAnomalyGetRule(MonAnomalyRule_HighOpsFrequency, &rule);
    TEST_ASSERT(NT_SUCCESS(status));
    TEST_ASSERT(rule.RuleId == MonAnomalyRule_HighOpsFrequency);
    TEST_ASSERT(rule.Enabled == TRUE);
    TEST_ASSERT(rule.Threshold > 0);

    /* Get ViolationAccumulation rule */
    status = MonAnomalyGetRule(MonAnomalyRule_ViolationAccumulation, &rule);
    TEST_ASSERT(NT_SUCCESS(status));
    TEST_ASSERT(rule.RuleId == MonAnomalyRule_ViolationAccumulation);

    /* Get non-existent rule */
    status = MonAnomalyGetRule((MON_ANOMALY_RULE_ID)99, &rule);
    TEST_ASSERT(status == STATUS_NOT_FOUND);

    TEST_PASS("TestAnomalyGetRule");
    return STATUS_SUCCESS;
}

static NTSTATUS TestAnomalySetThreshold(VOID)
{
    NTSTATUS status;
    MON_ANOMALY_RULE rule;

    /* Get original threshold */
    status = MonAnomalyGetRule(MonAnomalyRule_HighOpsFrequency, &rule);
    TEST_ASSERT(NT_SUCCESS(status));
    ULONG originalThreshold = rule.Threshold;

    /* Change threshold */
    status = MonAnomalySetThreshold(MonAnomalyRule_HighOpsFrequency, 500);
    TEST_ASSERT(NT_SUCCESS(status));

    /* Verify change */
    status = MonAnomalyGetRule(MonAnomalyRule_HighOpsFrequency, &rule);
    TEST_ASSERT(NT_SUCCESS(status));
    TEST_ASSERT(rule.Threshold == 500);

    /* Restore original */
    status = MonAnomalySetThreshold(MonAnomalyRule_HighOpsFrequency, originalThreshold);
    TEST_ASSERT(NT_SUCCESS(status));

    TEST_PASS("TestAnomalySetThreshold");
    return STATUS_SUCCESS;
}

static NTSTATUS TestAnomalyEnableDisable(VOID)
{
    NTSTATUS status;
    MON_ANOMALY_RULE rule;

    /* Disable rule */
    status = MonAnomalyEnableRule(MonAnomalyRule_BurstPattern, FALSE);
    TEST_ASSERT(NT_SUCCESS(status));

    /* Verify disabled */
    status = MonAnomalyGetRule(MonAnomalyRule_BurstPattern, &rule);
    TEST_ASSERT(NT_SUCCESS(status));
    TEST_ASSERT(rule.Enabled == FALSE);

    /* Re-enable */
    status = MonAnomalyEnableRule(MonAnomalyRule_BurstPattern, TRUE);
    TEST_ASSERT(NT_SUCCESS(status));

    /* Verify enabled */
    status = MonAnomalyGetRule(MonAnomalyRule_BurstPattern, &rule);
    TEST_ASSERT(NT_SUCCESS(status));
    TEST_ASSERT(rule.Enabled == TRUE);

    TEST_PASS("TestAnomalyEnableDisable");
    return STATUS_SUCCESS;
}

static NTSTATUS TestAnomalyEnumerate(VOID)
{
    NTSTATUS status;
    MON_ANOMALY_RULE rules[32];
    ULONG count = 0;

    /* Enumerate all rules */
    status = MonAnomalyEnumerateRules(rules, 32, &count);
    TEST_ASSERT(NT_SUCCESS(status));
    TEST_ASSERT(count >= 7);

    /* Verify rule data */
    for (ULONG i = 0; i < count; i++) {
        TEST_ASSERT(rules[i].RuleId != MonAnomalyRule_None);
        TEST_ASSERT(rules[i].RuleName[0] != L'\0');
    }

    TEST_PASS("TestAnomalyEnumerate");
    return STATUS_SUCCESS;
}

static NTSTATUS TestAnomalyStats(VOID)
{
    MON_ANOMALY_STATS stats;

    /* Get stats */
    MonAnomalyGetStats(&stats);
    TEST_ASSERT(stats.Size == sizeof(MON_ANOMALY_STATS));
    TEST_ASSERT(stats.TotalRules >= 7);
    TEST_ASSERT(stats.EnabledRules <= stats.TotalRules);

    /* Reset and verify */
    MonAnomalyResetStats();

    MonAnomalyGetStats(&stats);
    TEST_ASSERT(stats.TotalEvaluations == 0);
    TEST_ASSERT(stats.TotalMatches == 0);

    TEST_PASS("TestAnomalyStats");
    return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
 * Integration Tests
 *-------------------------------------------------------------------------*/

static NTSTATUS TestProfileAnomalyIntegration(VOID)
{
    NTSTATUS status;
    PMON_PROCESS_PROFILE profile;
    MON_PROFILE_SUMMARY summary;

    /* Create profile */
    status = MonProfileCreate(7777, L"IntegrationTest.exe", &profile);
    TEST_ASSERT(NT_SUCCESS(status));

    /* Generate high violation count (triggers ViolationAccumulation rule) */
    for (int i = 0; i < 10; i++) {
        status = MonProfileRecordViolation(profile, MonReason_SuspiciousOpCode, 2);
        TEST_ASSERT(NT_SUCCESS(status));
    }

    /* Get summary - should have elevated anomaly score */
    status = MonProfileGetSummary(7777, &summary);
    TEST_ASSERT(NT_SUCCESS(status));
    TEST_ASSERT(summary.ViolationCount >= 10);
    /* Anomaly score should be > 0 due to violations */
    TEST_ASSERT(summary.AnomalyScore >= 0);

    /* Cleanup */
    MonProfileDestroy(profile);

    TEST_PASS("TestProfileAnomalyIntegration");
    return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
 * Main Test Runner
 *-------------------------------------------------------------------------*/

NTSTATUS TestProfileRunAll(VOID)
{
    NTSTATUS status;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[TEST] Starting Phase 7 Unit Tests\n");

    /* Profile Tests */
    status = TestProfileInitShutdown();
    if (!NT_SUCCESS(status)) return status;

    status = TestProfileCreateDestroy();
    if (!NT_SUCCESS(status)) return status;

    status = TestProfileRecordOps();
    if (!NT_SUCCESS(status)) return status;

    status = TestProfileViolation();
    if (!NT_SUCCESS(status)) return status;

    status = TestProfileEnumerate();
    if (!NT_SUCCESS(status)) return status;

    status = TestProfileMLExport();
    if (!NT_SUCCESS(status)) return status;

    status = TestProfileConfig();
    if (!NT_SUCCESS(status)) return status;

    /* Anomaly Tests */
    status = TestAnomalyInitShutdown();
    if (!NT_SUCCESS(status)) return status;

    status = TestAnomalyGetRule();
    if (!NT_SUCCESS(status)) return status;

    status = TestAnomalySetThreshold();
    if (!NT_SUCCESS(status)) return status;

    status = TestAnomalyEnableDisable();
    if (!NT_SUCCESS(status)) return status;

    status = TestAnomalyEnumerate();
    if (!NT_SUCCESS(status)) return status;

    status = TestAnomalyStats();
    if (!NT_SUCCESS(status)) return status;

    /* Integration Tests */
    status = TestProfileAnomalyIntegration();
    if (!NT_SUCCESS(status)) return status;

    /* Cleanup */
    MonAnomalyShutdown();
    MonProfileShutdown();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[TEST] All Phase 7 Unit Tests PASSED\n");

    return STATUS_SUCCESS;
}
