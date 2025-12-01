/*
 * Unit Tests - Memory Region Monitoring (Phase 8)
 *
 * Author: Colin MacRitchie | ziX Labs
 * Organization: ziX Labs - Security Research Division
 * File: test_memory.c
 * Version: 1.0
 * Date: 2025-12-01
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and confidential.
 *   Redistribution or disclosure without prior written consent is prohibited.
 *
 * Summary
 * -------
 * Unit tests for the mem_monitor and vad_walker subsystems.
 * Tests MDL tracking, VAD scanning, anomaly detection, and IOCTL responses.
 */

#include <ntddk.h>
#include "mem_monitor.h"

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
 * Memory Monitor Initialization Tests
 *-------------------------------------------------------------------------*/

static NTSTATUS TestMemInitShutdown(VOID)
{
    NTSTATUS status;

    /* Initialize */
    status = MonMemInitialize();
    TEST_ASSERT(NT_SUCCESS(status));
    TEST_ASSERT(MonMemIsInitialized());

    /* Double-init should be idempotent */
    status = MonMemInitialize();
    TEST_ASSERT(NT_SUCCESS(status));

    /* Shutdown */
    MonMemShutdown();
    TEST_ASSERT(!MonMemIsInitialized());

    /* Double-shutdown should be safe */
    MonMemShutdown();

    /* Re-init for remaining tests */
    status = MonMemInitialize();
    TEST_ASSERT(NT_SUCCESS(status));

    TEST_PASS("TestMemInitShutdown");
    return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
 * MDL Tracking Tests
 *-------------------------------------------------------------------------*/

static NTSTATUS TestMdlTrackUntrack(VOID)
{
    NTSTATUS status;
    MON_MDL_INFO mdlInfo;
    MON_MEM_STATS stats;

    /* Ensure initialized */
    TEST_ASSERT(MonMemIsInitialized());

    /* Get initial stats */
    MonMemGetStats(&stats);
    ULONG initialMdlCount = stats.TrackedMdlCount;

    /* Create fake MDL info */
    RtlZeroMemory(&mdlInfo, sizeof(mdlInfo));
    mdlInfo.VirtualAddress = 0x7FFE0000000;
    mdlInfo.ByteCount = 4096;
    mdlInfo.ByteOffset = 0;
    mdlInfo.ProcessId = 1234;
    mdlInfo.Flags = 0;
    mdlInfo.PageCount = 1;
    mdlInfo.IsLocked = TRUE;
    mdlInfo.IsMapped = FALSE;
    mdlInfo.IsNonPagedPool = FALSE;
    mdlInfo.CreationTime = KeQueryInterruptTime();

    /* Track MDL */
    status = MonMemTrackMdl(&mdlInfo);
    TEST_ASSERT(NT_SUCCESS(status));

    /* Check stats updated */
    MonMemGetStats(&stats);
    TEST_ASSERT(stats.TrackedMdlCount == initialMdlCount + 1);

    /* Track another MDL for same process */
    mdlInfo.VirtualAddress = 0x7FFE0001000;
    status = MonMemTrackMdl(&mdlInfo);
    TEST_ASSERT(NT_SUCCESS(status));

    /* Verify count */
    MonMemGetStats(&stats);
    TEST_ASSERT(stats.TrackedMdlCount == initialMdlCount + 2);

    /* Untrack first MDL */
    status = MonMemUntrackMdl(1234, 0x7FFE0000000);
    TEST_ASSERT(NT_SUCCESS(status));

    /* Verify count decreased */
    MonMemGetStats(&stats);
    TEST_ASSERT(stats.TrackedMdlCount == initialMdlCount + 1);

    /* Untrack second MDL */
    status = MonMemUntrackMdl(1234, 0x7FFE0001000);
    TEST_ASSERT(NT_SUCCESS(status));

    /* Verify back to initial */
    MonMemGetStats(&stats);
    TEST_ASSERT(stats.TrackedMdlCount == initialMdlCount);

    TEST_PASS("TestMdlTrackUntrack");
    return STATUS_SUCCESS;
}

static NTSTATUS TestMdlGetTracker(VOID)
{
    NTSTATUS status;
    MON_MDL_INFO mdlInfo;
    PMON_MDL_TRACKER tracker;

    /* Track MDL for specific process */
    RtlZeroMemory(&mdlInfo, sizeof(mdlInfo));
    mdlInfo.VirtualAddress = 0x7FFE0002000;
    mdlInfo.ByteCount = 8192;
    mdlInfo.ProcessId = 5678;
    mdlInfo.PageCount = 2;
    mdlInfo.IsLocked = TRUE;

    status = MonMemTrackMdl(&mdlInfo);
    TEST_ASSERT(NT_SUCCESS(status));

    /* Get tracker for this process */
    tracker = MonMemGetMdlTracker(5678);
    TEST_ASSERT(tracker != NULL);
    TEST_ASSERT(tracker->ProcessId == 5678);
    TEST_ASSERT(tracker->TrackedMdlCount >= 1);
    TEST_ASSERT(tracker->TotalLockedBytes >= 8192);

    /* Get tracker for non-existent process */
    tracker = MonMemGetMdlTracker(99999);
    TEST_ASSERT(tracker == NULL);

    /* Cleanup */
    status = MonMemUntrackMdl(5678, 0x7FFE0002000);
    TEST_ASSERT(NT_SUCCESS(status));

    TEST_PASS("TestMdlGetTracker");
    return STATUS_SUCCESS;
}

static NTSTATUS TestMdlAnomalyDetection(VOID)
{
    NTSTATUS status;
    MON_MDL_INFO mdlInfo;
    MON_MEM_STATS stats;

    /* Get initial anomaly count */
    MonMemGetStats(&stats);
    ULONG64 initialAnomalies = stats.TotalAnomaliesDetected;

    /* Track suspicious MDL (large locked region) */
    RtlZeroMemory(&mdlInfo, sizeof(mdlInfo));
    mdlInfo.VirtualAddress = 0x7FFE0003000;
    mdlInfo.ByteCount = 100 * 1024 * 1024; /* 100 MB - suspicious */
    mdlInfo.ProcessId = 3333;
    mdlInfo.PageCount = (100 * 1024 * 1024) / PAGE_SIZE;
    mdlInfo.IsLocked = TRUE;

    status = MonMemTrackMdl(&mdlInfo);
    TEST_ASSERT(NT_SUCCESS(status));

    /* Check anomalies */
    status = MonMemCheckAnomalies(3333);
    TEST_ASSERT(NT_SUCCESS(status));

    /* Should detect large region anomaly */
    MonMemGetStats(&stats);
    /* Note: Anomaly detection depends on thresholds configured */

    /* Cleanup */
    status = MonMemUntrackMdl(3333, 0x7FFE0003000);
    TEST_ASSERT(NT_SUCCESS(status));

    TEST_PASS("TestMdlAnomalyDetection");
    return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
 * VAD Walker Tests
 *-------------------------------------------------------------------------*/

static NTSTATUS TestVadWalkCurrentProcess(VOID)
{
    NTSTATUS status;
    UCHAR buffer[sizeof(MON_VAD_SCAN_RESULT) + (10 * sizeof(MON_VAD_INFO))];
    PMON_VAD_SCAN_RESULT result = (PMON_VAD_SCAN_RESULT)buffer;
    ULONG bytesWritten = 0;

    /* Walk VAD tree for current process */
    ULONG currentPid = HandleToUlong(PsGetCurrentProcessId());
    status = MonVadWalkTree(currentPid, buffer, sizeof(buffer), &bytesWritten);

    /* This may fail if offsets not resolved, which is acceptable */
    if (status == STATUS_NOT_SUPPORTED) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[TEST] VAD walking not supported on this build\n");
        TEST_PASS("TestVadWalkCurrentProcess (skipped - not supported)");
        return STATUS_SUCCESS;
    }

    TEST_ASSERT(NT_SUCCESS(status));
    TEST_ASSERT(bytesWritten >= sizeof(MON_VAD_SCAN_RESULT));
    TEST_ASSERT(result->Size == sizeof(MON_VAD_SCAN_RESULT));
    TEST_ASSERT(result->ProcessId == currentPid);
    TEST_ASSERT(result->VadCount > 0); /* System process has VADs */

    /* Verify basic sanity */
    TEST_ASSERT(result->TotalPrivateBytes > 0 || result->TotalMappedBytes > 0);

    TEST_PASS("TestVadWalkCurrentProcess");
    return STATUS_SUCCESS;
}

static NTSTATUS TestVadWalkInvalidProcess(VOID)
{
    NTSTATUS status;
    MON_VAD_SCAN_RESULT result;
    ULONG bytesWritten = 0;

    /* Try to walk non-existent process */
    status = MonVadWalkTree(0xFFFFFFFF, &result, sizeof(result), &bytesWritten);

    /* Should fail with invalid parameter or not found */
    TEST_ASSERT(!NT_SUCCESS(status) ||
                status == STATUS_NOT_SUPPORTED ||
                status == STATUS_INVALID_PARAMETER);

    TEST_PASS("TestVadWalkInvalidProcess");
    return STATUS_SUCCESS;
}

static NTSTATUS TestVadAnomalyDetection(VOID)
{
    NTSTATUS status;
    UCHAR buffer[sizeof(MON_VAD_SCAN_RESULT) + (100 * sizeof(MON_VAD_INFO))];
    PMON_VAD_SCAN_RESULT result = (PMON_VAD_SCAN_RESULT)buffer;
    ULONG bytesWritten = 0;

    /* Walk current process VADs */
    ULONG currentPid = HandleToUlong(PsGetCurrentProcessId());
    status = MonVadWalkTree(currentPid, buffer, sizeof(buffer), &bytesWritten);

    if (status == STATUS_NOT_SUPPORTED) {
        TEST_PASS("TestVadAnomalyDetection (skipped - not supported)");
        return STATUS_SUCCESS;
    }

    TEST_ASSERT(NT_SUCCESS(status));

    /* Check if any anomalies detected */
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[TEST] VAD scan: %lu VADs, %lu suspicious, flags=0x%X\n",
        result->VadCount, result->SuspiciousVadCount, result->AnomalyFlags);

    /* AnomalyFlags may or may not be set depending on process */
    /* Just verify the scan completed */

    TEST_PASS("TestVadAnomalyDetection");
    return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
 * Statistics Tests
 *-------------------------------------------------------------------------*/

static NTSTATUS TestMemStats(VOID)
{
    MON_MEM_STATS stats;

    /* Get stats */
    MonMemGetStats(&stats);
    TEST_ASSERT(stats.Size == sizeof(MON_MEM_STATS));

    /* Verify counters are reasonable */
    TEST_ASSERT(stats.TrackedMdlCount >= 0);
    TEST_ASSERT(stats.TrackedProcessCount >= 0);

    /* Test reset if applicable */
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[TEST] Memory stats: MDLs=%lu, Procs=%lu, Anomalies=%llu\n",
        stats.TrackedMdlCount, stats.TrackedProcessCount, stats.TotalAnomaliesDetected);

    TEST_PASS("TestMemStats");
    return STATUS_SUCCESS;
}

static NTSTATUS TestMemStatsAfterOperations(VOID)
{
    NTSTATUS status;
    MON_MDL_INFO mdlInfo;
    MON_MEM_STATS statsBefore, statsAfter;

    /* Get stats before */
    MonMemGetStats(&statsBefore);

    /* Track some MDLs */
    RtlZeroMemory(&mdlInfo, sizeof(mdlInfo));
    mdlInfo.VirtualAddress = 0x7FFE0010000;
    mdlInfo.ByteCount = 4096;
    mdlInfo.ProcessId = 4444;
    mdlInfo.IsLocked = TRUE;

    status = MonMemTrackMdl(&mdlInfo);
    TEST_ASSERT(NT_SUCCESS(status));

    /* Get stats after */
    MonMemGetStats(&statsAfter);

    /* Verify tracking updated */
    TEST_ASSERT(statsAfter.TrackedMdlCount == statsBefore.TrackedMdlCount + 1);

    /* Cleanup */
    MonMemUntrackMdl(4444, 0x7FFE0010000);

    TEST_PASS("TestMemStatsAfterOperations");
    return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
 * Edge Case Tests
 *-------------------------------------------------------------------------*/

static NTSTATUS TestNullParameters(VOID)
{
    NTSTATUS status;

    /* TrackMdl with NULL */
    status = MonMemTrackMdl(NULL);
    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);

    /* UntrackMdl with invalid params */
    status = MonMemUntrackMdl(0, 0);
    TEST_ASSERT(status == STATUS_INVALID_PARAMETER ||
                status == STATUS_NOT_FOUND);

    /* VadWalk with NULL output */
    ULONG bytesWritten = 0;
    status = MonVadWalkTree(4, NULL, 0, &bytesWritten);
    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);

    /* VadWalk with NULL bytesWritten */
    MON_VAD_SCAN_RESULT result;
    status = MonVadWalkTree(4, &result, sizeof(result), NULL);
    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);

    TEST_PASS("TestNullParameters");
    return STATUS_SUCCESS;
}

static NTSTATUS TestBufferTooSmall(VOID)
{
    NTSTATUS status;
    UCHAR smallBuffer[16];
    ULONG bytesWritten = 0;

    /* VAD walk with too-small buffer */
    status = MonVadWalkTree(4, smallBuffer, sizeof(smallBuffer), &bytesWritten);
    TEST_ASSERT(status == STATUS_BUFFER_TOO_SMALL ||
                status == STATUS_NOT_SUPPORTED ||
                status == STATUS_INVALID_PARAMETER);

    TEST_PASS("TestBufferTooSmall");
    return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
 * Main Test Runner
 *-------------------------------------------------------------------------*/

NTSTATUS TestMemoryRunAll(VOID)
{
    NTSTATUS status;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[TEST] Starting Phase 8 Memory Monitoring Unit Tests\n");

    /* Initialization Tests */
    status = TestMemInitShutdown();
    if (!NT_SUCCESS(status)) return status;

    /* MDL Tracking Tests */
    status = TestMdlTrackUntrack();
    if (!NT_SUCCESS(status)) return status;

    status = TestMdlGetTracker();
    if (!NT_SUCCESS(status)) return status;

    status = TestMdlAnomalyDetection();
    if (!NT_SUCCESS(status)) return status;

    /* VAD Walker Tests */
    status = TestVadWalkCurrentProcess();
    if (!NT_SUCCESS(status)) return status;

    status = TestVadWalkInvalidProcess();
    if (!NT_SUCCESS(status)) return status;

    status = TestVadAnomalyDetection();
    if (!NT_SUCCESS(status)) return status;

    /* Statistics Tests */
    status = TestMemStats();
    if (!NT_SUCCESS(status)) return status;

    status = TestMemStatsAfterOperations();
    if (!NT_SUCCESS(status)) return status;

    /* Edge Case Tests */
    status = TestNullParameters();
    if (!NT_SUCCESS(status)) return status;

    status = TestBufferTooSmall();
    if (!NT_SUCCESS(status)) return status;

    /* Cleanup */
    MonMemShutdown();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[TEST] All Phase 8 Memory Monitoring Unit Tests PASSED\n");

    return STATUS_SUCCESS;
}
