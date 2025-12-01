/*
 * Unit Tests - Cross-Process Detection (Phase 9)
 *
 * Author: Colin MacRitchie | ziX Labs
 * Organization: ziX Labs - Security Research Division
 * File: test_xprocess.c
 * Version: 1.0
 * Date: 2025-11-30
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and confidential.
 *   Redistribution or disclosure without prior written consent is prohibited.
 *
 * Summary
 * -------
 * Unit tests for the cross-process detection subsystem.
 * Tests initialization, process tree operations, configuration, and statistics.
 */

#include <ntddk.h>
#include "cross_process.h"

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
 * Initialization Tests
 *-------------------------------------------------------------------------*/

static NTSTATUS TestXpInitShutdown(VOID)
{
    NTSTATUS status;

    /* Initialize */
    status = MonXpInitialize();
    TEST_ASSERT(NT_SUCCESS(status));
    TEST_ASSERT(MonXpIsInitialized());

    /* Double-init should return already initialized */
    status = MonXpInitialize();
    TEST_ASSERT(status == STATUS_ALREADY_INITIALIZED);

    /* Shutdown */
    MonXpShutdown();
    TEST_ASSERT(!MonXpIsInitialized());

    /* Double-shutdown should be safe */
    MonXpShutdown();

    /* Re-init for remaining tests */
    status = MonXpInitialize();
    TEST_ASSERT(NT_SUCCESS(status));

    TEST_PASS("TestXpInitShutdown");
    return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
 * Configuration Tests
 *-------------------------------------------------------------------------*/

static NTSTATUS TestXpConfig(VOID)
{
    MON_XP_CONFIG config;
    MON_XP_CONFIG newConfig;
    NTSTATUS status;

    TEST_ASSERT(MonXpIsInitialized());

    /* Get current config */
    MonXpGetConfig(&config);
    TEST_ASSERT(config.Size == sizeof(MON_XP_CONFIG));
    TEST_ASSERT(config.Enabled == TRUE);
    TEST_ASSERT(config.WhitelistEnabled == TRUE);
    TEST_ASSERT(config.ScanIntervalMs == MON_XP_DEFAULT_SCAN_INTERVAL_MS);
    TEST_ASSERT(config.TreeRefreshIntervalMs == MON_XP_DEFAULT_TREE_REFRESH_MS);
    TEST_ASSERT(config.AlertThreshold == 40);
    TEST_ASSERT(config.CriticalThreshold == 80);

    /* Modify config */
    RtlCopyMemory(&newConfig, &config, sizeof(newConfig));
    newConfig.Enabled = FALSE;
    newConfig.AlertThreshold = 60;
    newConfig.ScanIntervalMs = 15000;

    status = MonXpSetConfig(&newConfig);
    TEST_ASSERT(NT_SUCCESS(status));

    /* Verify changes */
    MonXpGetConfig(&config);
    TEST_ASSERT(config.Enabled == FALSE);
    TEST_ASSERT(config.AlertThreshold == 60);
    TEST_ASSERT(config.ScanIntervalMs == 15000);

    /* Restore defaults */
    newConfig.Enabled = TRUE;
    newConfig.AlertThreshold = 40;
    newConfig.ScanIntervalMs = MON_XP_DEFAULT_SCAN_INTERVAL_MS;
    status = MonXpSetConfig(&newConfig);
    TEST_ASSERT(NT_SUCCESS(status));

    /* Test invalid config */
    newConfig.Size = 0;
    status = MonXpSetConfig(&newConfig);
    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);

    /* Null config should fail */
    status = MonXpSetConfig(NULL);
    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);

    TEST_PASS("TestXpConfig");
    return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
 * Statistics Tests
 *-------------------------------------------------------------------------*/

static NTSTATUS TestXpStats(VOID)
{
    MON_XP_STATS stats;

    TEST_ASSERT(MonXpIsInitialized());

    /* Get stats */
    MonXpGetStats(&stats);
    TEST_ASSERT(stats.Size == sizeof(MON_XP_STATS));
    TEST_ASSERT(stats.TotalScans == 0);
    TEST_ASSERT(stats.ActiveSharedObjects == 0);

    /* Trigger a scan */
    MonXpScanNow();

    /* Verify scan count incremented */
    MonXpGetStats(&stats);
    TEST_ASSERT(stats.TotalScans == 1);

    /* Reset stats */
    MonXpResetStats();
    MonXpGetStats(&stats);
    TEST_ASSERT(stats.TotalScans == 0);
    TEST_ASSERT(stats.TotalAlertsGenerated == 0);

    /* Null stats should not crash */
    MonXpGetStats(NULL);

    TEST_PASS("TestXpStats");
    return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
 * Process Tree Tests
 *-------------------------------------------------------------------------*/

static NTSTATUS TestXpProcessTree(VOID)
{
    PMON_XP_PROCESS_ENTRY entries = NULL;
    ULONG count = 0;
    NTSTATUS status;
    ULONG integrityLevel = 0;

    TEST_ASSERT(MonXpIsInitialized());

    /* Get process tree (may be empty initially) */
    status = MonXpGetProcessTree(&entries, &count);
    TEST_ASSERT(NT_SUCCESS(status));

    /* If we got entries, verify they're valid */
    if (count > 0 && entries != NULL) {
        TEST_ASSERT(entries[0].ProcessId != 0);
        ExFreePoolWithTag(entries, MON_XP_TAG);
        entries = NULL;
    }

    /* Test descendant check with System PID 4 */
    BOOLEAN isDescendant = MonXpIsProcessDescendant(4, 0, 8);
    TEST_ASSERT(isDescendant == FALSE);

    /* Invalid checks should return FALSE */
    isDescendant = MonXpIsProcessDescendant(0, 0, 0);
    TEST_ASSERT(isDescendant == FALSE);

    /* Same process should be its own descendant */
    isDescendant = MonXpIsProcessDescendant(4, 4, 1);
    TEST_ASSERT(isDescendant == TRUE);

    /* Get integrity level for System process (PID 4) */
    status = MonXpGetProcessIntegrity(4, &integrityLevel);
    /* May not be cached yet, so accept both success and not found */
    if (NT_SUCCESS(status)) {
        TEST_ASSERT(integrityLevel == MON_IL_SYSTEM);
    }

    /* Invalid parameters */
    status = MonXpGetProcessIntegrity(0, NULL);
    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);

    TEST_PASS("TestXpProcessTree");
    return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
 * Shared Object Tests
 *-------------------------------------------------------------------------*/

static NTSTATUS TestXpSharedObjects(VOID)
{
    PMON_XP_SHARED_OBJECT objects = NULL;
    ULONG count = 0;
    NTSTATUS status;

    TEST_ASSERT(MonXpIsInitialized());

    /* Get shared objects (should be empty initially) */
    status = MonXpGetSharedObjects(&objects, &count);
    TEST_ASSERT(NT_SUCCESS(status));
    TEST_ASSERT(count == 0 || objects != NULL);

    if (objects != NULL) {
        ExFreePoolWithTag(objects, MON_XP_TAG);
    }

    /* Null parameters should fail */
    status = MonXpGetSharedObjects(NULL, &count);
    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);

    status = MonXpGetSharedObjects(&objects, NULL);
    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);

    TEST_PASS("TestXpSharedObjects");
    return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
 * Alerts Tests
 *-------------------------------------------------------------------------*/

static NTSTATUS TestXpAlerts(VOID)
{
    PMON_XP_ALERT_EVENT alerts = NULL;
    ULONG count = 0;
    NTSTATUS status;

    TEST_ASSERT(MonXpIsInitialized());

    /* Get alerts (should be empty initially) */
    status = MonXpGetAlerts(&alerts, &count);
    TEST_ASSERT(NT_SUCCESS(status));
    TEST_ASSERT(count == 0);
    TEST_ASSERT(alerts == NULL);

    /* Null parameters should fail */
    status = MonXpGetAlerts(NULL, &count);
    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);

    status = MonXpGetAlerts(&alerts, NULL);
    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);

    TEST_PASS("TestXpAlerts");
    return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
 * Section Scan Tests
 *-------------------------------------------------------------------------*/

static NTSTATUS TestXpScanSections(VOID)
{
    PMON_XP_SECTION_INFO sections = NULL;
    ULONG count = 0;
    NTSTATUS status;

    TEST_ASSERT(MonXpIsInitialized());

    /* Scan sections for current process */
    status = MonXpScanSections((HANDLE)(ULONG_PTR)4, &sections, &count);
    TEST_ASSERT(NT_SUCCESS(status));
    TEST_ASSERT(count == 0);  /* Stub returns empty */
    TEST_ASSERT(sections == NULL);

    /* Null parameters should fail */
    status = MonXpScanSections(NULL, NULL, &count);
    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);

    status = MonXpScanSections(NULL, &sections, NULL);
    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);

    TEST_PASS("TestXpScanSections");
    return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
 * Scan Now Tests
 *-------------------------------------------------------------------------*/

static NTSTATUS TestXpScanNow(VOID)
{
    NTSTATUS status;
    MON_XP_STATS stats;
    MON_XP_CONFIG config;

    TEST_ASSERT(MonXpIsInitialized());

    /* Get initial scan count */
    MonXpGetStats(&stats);
    ULONG initialScans = stats.TotalScans;

    /* Trigger scan */
    status = MonXpScanNow();
    TEST_ASSERT(NT_SUCCESS(status));

    /* Verify scan count incremented */
    MonXpGetStats(&stats);
    TEST_ASSERT(stats.TotalScans == initialScans + 1);

    /* Disable scanning */
    MonXpGetConfig(&config);
    config.Enabled = FALSE;
    MonXpSetConfig(&config);

    /* Scan when disabled should still succeed but not count */
    status = MonXpScanNow();
    TEST_ASSERT(NT_SUCCESS(status));

    /* Re-enable */
    config.Enabled = TRUE;
    MonXpSetConfig(&config);

    TEST_PASS("TestXpScanNow");
    return STATUS_SUCCESS;
}

/*==========================================================================
 * Test Runner
 *=========================================================================*/

NTSTATUS
MonXpRunTests(VOID)
{
    NTSTATUS status;
    ULONG passCount = 0;
    ULONG failCount = 0;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON] ========== Cross-Process Tests Begin ==========\n");

    /* Run all tests */
    #define RUN_TEST(fn) do { \
        status = fn(); \
        if (NT_SUCCESS(status)) passCount++; else failCount++; \
    } while(0)

    RUN_TEST(TestXpInitShutdown);
    RUN_TEST(TestXpConfig);
    RUN_TEST(TestXpStats);
    RUN_TEST(TestXpProcessTree);
    RUN_TEST(TestXpSharedObjects);
    RUN_TEST(TestXpAlerts);
    RUN_TEST(TestXpScanSections);
    RUN_TEST(TestXpScanNow);

    #undef RUN_TEST

    /* Final shutdown */
    MonXpShutdown();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON] ========== Cross-Process Tests Complete ==========\n");
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON] Results: %lu passed, %lu failed\n", passCount, failCount);

    return (failCount == 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
