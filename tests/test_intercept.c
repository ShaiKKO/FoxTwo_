/*
 * IoRing Interception Unit Tests
 *
 * Author: Colin MacRitchie | ziX Labs
 * Organization: ziX Labs — Security Research Division
 * File: test_intercept.c
 * Version: 1.0
 * Date: 2025-11-30
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and confidential.
 *   Redistribution or disclosure without prior written consent is prohibited.
 *
 * Summary
 * -------
 * Unit tests for the IoRing interception subsystem (Phase 6).
 * Tests validation logic, policy enforcement, blacklist management,
 * and statistics tracking.
 *
 * Test Coverage
 * -------------
 * INT-T01: Clean submission validation
 * INT-T02: Kernel address in buffer detection
 * INT-T03: Excessive operations detection
 * INT-T04: Audit mode behavior
 * INT-T05: Blacklist enforcement
 * INT-T06: Policy enable/disable
 * INT-T07: Statistics tracking
 * INT-T08: MITRE ATT&CK technique mapping
 */

#include <ntifs.h>
#include <ntstrsafe.h>
#include "ioring_intercept.h"

/*--------------------------------------------------------------------------
 * Test Framework
 *-------------------------------------------------------------------------*/

#define TEST_TAG 'tseT'

static ULONG g_TestsRun = 0;
static ULONG g_TestsPassed = 0;
static ULONG g_TestsFailed = 0;

#define TEST_ASSERT(cond, msg) do { \
    g_TestsRun++; \
    if (!(cond)) { \
        g_TestsFailed++; \
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
            "[TEST] FAIL: %s - %s\n", __FUNCTION__, msg); \
        return FALSE; \
    } else { \
        g_TestsPassed++; \
    } \
} while (0)

#define TEST_LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, \
    "[TEST] " fmt "\n", ##__VA_ARGS__)

/*--------------------------------------------------------------------------
 * Helper Functions
 *-------------------------------------------------------------------------*/

static PMON_INTERCEPT_REQUEST
AllocateTestRequest(
    _In_ ULONG OperationCount
)
{
    ULONG size = MON_INTERCEPT_REQUEST_HEADER_SIZE +
                 (OperationCount * sizeof(MON_SERIALIZED_SQE));

    PMON_INTERCEPT_REQUEST request = (PMON_INTERCEPT_REQUEST)
        ExAllocatePool2(POOL_FLAG_NON_PAGED, size, TEST_TAG);

    if (request != NULL) {
        RtlZeroMemory(request, size);
        request->Size = size;
        request->Version = MON_INTERCEPT_REQUEST_VERSION;
        request->ProcessId = HandleToUlong(PsGetCurrentProcessId());
        request->ThreadId = HandleToUlong(PsGetCurrentThreadId());
        request->IoRingHandle = 0x12345678;
        request->OperationCount = OperationCount;
    }

    return request;
}

static PMON_SERIALIZED_SQE
GetSqeFromRequest(
    _In_ PMON_INTERCEPT_REQUEST Request,
    _In_ ULONG Index
)
{
    if (Index >= Request->OperationCount) {
        return NULL;
    }

    return (PMON_SERIALIZED_SQE)((PUCHAR)Request +
                                 MON_INTERCEPT_REQUEST_HEADER_SIZE +
                                 (Index * sizeof(MON_SERIALIZED_SQE)));
}

static VOID
FreeTestRequest(
    _In_ PMON_INTERCEPT_REQUEST Request
)
{
    if (Request != NULL) {
        ExFreePoolWithTag(Request, TEST_TAG);
    }
}

/*--------------------------------------------------------------------------
 * INT-T01: Clean Submission Validation
 *-------------------------------------------------------------------------*/

static BOOLEAN
TestCleanSubmission(VOID)
{
    NTSTATUS status;
    MON_INTERCEPT_RESPONSE response = {0};

    TEST_LOG("INT-T01: Testing clean submission validation");

    /* Create a valid request with 2 read operations */
    PMON_INTERCEPT_REQUEST request = AllocateTestRequest(2);
    TEST_ASSERT(request != NULL, "Failed to allocate request");

    /* Fill with valid read operations */
    PMON_SERIALIZED_SQE sqe0 = GetSqeFromRequest(request, 0);
    PMON_SERIALIZED_SQE sqe1 = GetSqeFromRequest(request, 1);

    sqe0->OpCode = MonIoRingOp_Read;
    sqe0->Flags = 0;
    sqe0->FileRef = 0x1234;
    sqe0->BufferAddress = 0x00007FFE00000000;  /* Valid user address */
    sqe0->BufferSize = 4096;

    sqe1->OpCode = MonIoRingOp_Write;
    sqe1->Flags = 0;
    sqe1->FileRef = 0x5678;
    sqe1->BufferAddress = 0x00007FFE00001000;  /* Valid user address */
    sqe1->BufferSize = 8192;

    /* Validate */
    status = MonInterceptValidateSubmission(request, request->Size, &response);

    TEST_ASSERT(NT_SUCCESS(status), "Validation failed unexpectedly");
    TEST_ASSERT(response.Action == MonIntercept_Allow, "Expected Allow action");
    TEST_ASSERT(response.Reason == MonReason_None ||
                response.Reason == MonReason_PolicyDisabled, "Expected no violation");

    FreeTestRequest(request);
    return TRUE;
}

/*--------------------------------------------------------------------------
 * INT-T02: Kernel Address Detection
 *-------------------------------------------------------------------------*/

static BOOLEAN
TestKernelAddressDetection(VOID)
{
    NTSTATUS status;
    MON_INTERCEPT_RESPONSE response = {0};
    MON_INTERCEPT_POLICY policy = {0};

    TEST_LOG("INT-T02: Testing kernel address detection");

    /* First ensure policy is enabled */
    policy.Size = sizeof(MON_INTERCEPT_POLICY);
    policy.Enabled = TRUE;
    policy.BlockKernelAddresses = TRUE;
    policy.AuditMode = FALSE;

    status = MonInterceptSetPolicy(&policy);
    TEST_ASSERT(NT_SUCCESS(status), "Failed to set policy");

    /* Create request with kernel address in buffer */
    PMON_INTERCEPT_REQUEST request = AllocateTestRequest(1);
    TEST_ASSERT(request != NULL, "Failed to allocate request");

    PMON_SERIALIZED_SQE sqe = GetSqeFromRequest(request, 0);
    sqe->OpCode = MonIoRingOp_Read;
    sqe->BufferAddress = 0xFFFF800000000000;  /* Kernel address */
    sqe->BufferSize = 4096;

    /* Validate - should detect and block */
    status = MonInterceptValidateSubmission(request, request->Size, &response);

    TEST_ASSERT(response.Action == MonIntercept_Block, "Expected Block action");
    TEST_ASSERT(response.Reason == MonReason_KernelAddressInBuffer,
                "Expected KernelAddressInBuffer reason");
    TEST_ASSERT(response.ViolatingOpIndex == 0, "Expected violation at index 0");

    /* Verify MITRE technique is set */
    TEST_ASSERT(response.MitreTechnique[0] == 'T', "Expected MITRE technique");

    FreeTestRequest(request);
    return TRUE;
}

/*--------------------------------------------------------------------------
 * INT-T03: Excessive Operations Detection
 *-------------------------------------------------------------------------*/

static BOOLEAN
TestExcessiveOperations(VOID)
{
    NTSTATUS status;
    MON_INTERCEPT_RESPONSE response = {0};
    MON_INTERCEPT_POLICY policy = {0};

    TEST_LOG("INT-T03: Testing excessive operations detection");

    /* Set policy with low operation limit */
    policy.Size = sizeof(MON_INTERCEPT_POLICY);
    policy.Enabled = TRUE;
    policy.EnforceOperationLimit = TRUE;
    policy.MaxOperationsPerSubmit = 5;
    policy.AuditMode = FALSE;

    status = MonInterceptSetPolicy(&policy);
    TEST_ASSERT(NT_SUCCESS(status), "Failed to set policy");

    /* Create request with too many operations */
    PMON_INTERCEPT_REQUEST request = AllocateTestRequest(10);
    TEST_ASSERT(request != NULL, "Failed to allocate request");

    /* Fill with valid operations */
    for (ULONG i = 0; i < 10; i++) {
        PMON_SERIALIZED_SQE sqe = GetSqeFromRequest(request, i);
        sqe->OpCode = MonIoRingOp_Nop;
    }

    /* Validate - should block due to excessive ops */
    status = MonInterceptValidateSubmission(request, request->Size, &response);

    TEST_ASSERT(response.Action == MonIntercept_Block, "Expected Block action");
    TEST_ASSERT(response.Reason == MonReason_ExcessiveOperations,
                "Expected ExcessiveOperations reason");

    FreeTestRequest(request);
    return TRUE;
}

/*--------------------------------------------------------------------------
 * INT-T04: Audit Mode Behavior
 *-------------------------------------------------------------------------*/

static BOOLEAN
TestAuditMode(VOID)
{
    NTSTATUS status;
    MON_INTERCEPT_RESPONSE response = {0};
    MON_INTERCEPT_POLICY policy = {0};

    TEST_LOG("INT-T04: Testing audit mode behavior");

    /* Set policy in audit mode with kernel address blocking */
    policy.Size = sizeof(MON_INTERCEPT_POLICY);
    policy.Enabled = TRUE;
    policy.BlockKernelAddresses = TRUE;
    policy.AuditMode = TRUE;  /* Log but don't block */

    status = MonInterceptSetPolicy(&policy);
    TEST_ASSERT(NT_SUCCESS(status), "Failed to set policy");

    /* Create request with kernel address */
    PMON_INTERCEPT_REQUEST request = AllocateTestRequest(1);
    TEST_ASSERT(request != NULL, "Failed to allocate request");

    PMON_SERIALIZED_SQE sqe = GetSqeFromRequest(request, 0);
    sqe->OpCode = MonIoRingOp_Read;
    sqe->BufferAddress = 0xFFFF800000000000;  /* Kernel address */
    sqe->BufferSize = 4096;

    /* Validate - should log but not block */
    status = MonInterceptValidateSubmission(request, request->Size, &response);

    TEST_ASSERT(response.Action == MonIntercept_LogOnly, "Expected LogOnly action");
    TEST_ASSERT(response.Reason == MonReason_KernelAddressInBuffer,
                "Expected KernelAddressInBuffer reason (logged)");

    FreeTestRequest(request);
    return TRUE;
}

/*--------------------------------------------------------------------------
 * INT-T05: Blacklist Enforcement
 *-------------------------------------------------------------------------*/

static BOOLEAN
TestBlacklistEnforcement(VOID)
{
    NTSTATUS status;
    MON_INTERCEPT_RESPONSE response = {0};
    MON_INTERCEPT_POLICY policy = {0};
    ULONG testPid = 12345;

    TEST_LOG("INT-T05: Testing blacklist enforcement");

    /* Enable policy */
    policy.Size = sizeof(MON_INTERCEPT_POLICY);
    policy.Enabled = TRUE;
    policy.AuditMode = FALSE;

    status = MonInterceptSetPolicy(&policy);
    TEST_ASSERT(NT_SUCCESS(status), "Failed to set policy");

    /* Add PID to blacklist */
    status = MonInterceptAddToBlacklist(testPid, L"TestProcess", "Unit test");
    TEST_ASSERT(NT_SUCCESS(status), "Failed to add to blacklist");

    /* Verify it's blacklisted */
    TEST_ASSERT(MonInterceptIsBlacklisted(testPid), "PID should be blacklisted");

    /* Create request from blacklisted PID */
    PMON_INTERCEPT_REQUEST request = AllocateTestRequest(1);
    TEST_ASSERT(request != NULL, "Failed to allocate request");
    request->ProcessId = testPid;

    PMON_SERIALIZED_SQE sqe = GetSqeFromRequest(request, 0);
    sqe->OpCode = MonIoRingOp_Read;
    sqe->BufferAddress = 0x00007FFE00000000;
    sqe->BufferSize = 4096;

    /* Validate - should be blocked */
    status = MonInterceptValidateSubmission(request, request->Size, &response);

    TEST_ASSERT(response.Action == MonIntercept_Block, "Expected Block action");
    TEST_ASSERT(response.Reason == MonReason_ProcessBlacklisted,
                "Expected ProcessBlacklisted reason");

    /* Remove from blacklist */
    TEST_ASSERT(MonInterceptRemoveFromBlacklist(testPid), "Failed to remove from blacklist");
    TEST_ASSERT(!MonInterceptIsBlacklisted(testPid), "PID should not be blacklisted");

    FreeTestRequest(request);
    return TRUE;
}

/*--------------------------------------------------------------------------
 * INT-T06: Policy Enable/Disable
 *-------------------------------------------------------------------------*/

static BOOLEAN
TestPolicyEnableDisable(VOID)
{
    MON_INTERCEPT_RESPONSE response = {0};
    MON_INTERCEPT_POLICY policy = {0};
    NTSTATUS status;

    TEST_LOG("INT-T06: Testing policy enable/disable");

    /* Disable policy */
    policy.Size = sizeof(MON_INTERCEPT_POLICY);
    policy.Enabled = FALSE;

    status = MonInterceptSetPolicy(&policy);
    TEST_ASSERT(NT_SUCCESS(status), "Failed to set policy");

    TEST_ASSERT(!MonInterceptIsEnabled(), "Interception should be disabled");

    /* Create request with kernel address (would be blocked if enabled) */
    PMON_INTERCEPT_REQUEST request = AllocateTestRequest(1);
    TEST_ASSERT(request != NULL, "Failed to allocate request");

    PMON_SERIALIZED_SQE sqe = GetSqeFromRequest(request, 0);
    sqe->OpCode = MonIoRingOp_Read;
    sqe->BufferAddress = 0xFFFF800000000000;
    sqe->BufferSize = 4096;

    /* Validate - should be allowed when disabled */
    status = MonInterceptValidateSubmission(request, request->Size, &response);

    TEST_ASSERT(response.Action == MonIntercept_Allow, "Expected Allow when disabled");
    TEST_ASSERT(response.Reason == MonReason_PolicyDisabled,
                "Expected PolicyDisabled reason");

    /* Re-enable */
    MonInterceptEnable(TRUE);
    TEST_ASSERT(MonInterceptIsEnabled(), "Interception should be enabled");

    FreeTestRequest(request);
    return TRUE;
}

/*--------------------------------------------------------------------------
 * INT-T07: Statistics Tracking
 *-------------------------------------------------------------------------*/

static BOOLEAN
TestStatisticsTracking(VOID)
{
    MON_INTERCEPT_RESPONSE response = {0};
    MON_INTERCEPT_STATS statsBefore = {0};
    MON_INTERCEPT_STATS statsAfter = {0};
    MON_INTERCEPT_POLICY policy = {0};
    NTSTATUS status;

    TEST_LOG("INT-T07: Testing statistics tracking");

    /* Reset stats */
    MonInterceptResetStats();

    /* Get baseline */
    MonInterceptGetStats(&statsBefore);
    TEST_ASSERT(statsBefore.TotalValidationRequests == 0, "Expected zero requests initially");

    /* Enable policy */
    policy.Size = sizeof(MON_INTERCEPT_POLICY);
    policy.Enabled = TRUE;
    policy.BlockKernelAddresses = TRUE;

    status = MonInterceptSetPolicy(&policy);
    TEST_ASSERT(NT_SUCCESS(status), "Failed to set policy");

    /* Create and validate a request */
    PMON_INTERCEPT_REQUEST request = AllocateTestRequest(2);
    TEST_ASSERT(request != NULL, "Failed to allocate request");

    PMON_SERIALIZED_SQE sqe0 = GetSqeFromRequest(request, 0);
    sqe0->OpCode = MonIoRingOp_Read;
    sqe0->BufferAddress = 0x00007FFE00000000;
    sqe0->BufferSize = 4096;

    PMON_SERIALIZED_SQE sqe1 = GetSqeFromRequest(request, 1);
    sqe1->OpCode = MonIoRingOp_Write;
    sqe1->BufferAddress = 0x00007FFE00001000;
    sqe1->BufferSize = 4096;

    /* Validate */
    status = MonInterceptValidateSubmission(request, request->Size, &response);

    /* Check stats increased */
    MonInterceptGetStats(&statsAfter);
    TEST_ASSERT(statsAfter.TotalValidationRequests > statsBefore.TotalValidationRequests,
                "Validation requests should increase");
    TEST_ASSERT(statsAfter.TotalOperationsValidated >= 2,
                "Operations validated should be at least 2");

    /* Verify timing recorded */
    TEST_ASSERT(response.ValidationTimeNs > 0, "Expected non-zero validation time");

    FreeTestRequest(request);
    return TRUE;
}

/*--------------------------------------------------------------------------
 * INT-T08: MITRE ATT&CK Technique Mapping
 *-------------------------------------------------------------------------*/

static BOOLEAN
TestMitreTechniqueMapping(VOID)
{
    MON_INTERCEPT_RESPONSE response = {0};
    MON_INTERCEPT_POLICY policy = {0};
    NTSTATUS status;

    TEST_LOG("INT-T08: Testing MITRE ATT&CK technique mapping");

    /* Enable policy with kernel address blocking */
    policy.Size = sizeof(MON_INTERCEPT_POLICY);
    policy.Enabled = TRUE;
    policy.BlockKernelAddresses = TRUE;
    policy.AuditMode = FALSE;

    status = MonInterceptSetPolicy(&policy);
    TEST_ASSERT(NT_SUCCESS(status), "Failed to set policy");

    /* Create request with kernel address (T1068) */
    PMON_INTERCEPT_REQUEST request = AllocateTestRequest(1);
    TEST_ASSERT(request != NULL, "Failed to allocate request");

    PMON_SERIALIZED_SQE sqe = GetSqeFromRequest(request, 0);
    sqe->OpCode = MonIoRingOp_Read;
    sqe->BufferAddress = 0xFFFF800000000000;
    sqe->BufferSize = 4096;

    /* Validate */
    status = MonInterceptValidateSubmission(request, request->Size, &response);

    /* Verify MITRE technique for privilege escalation */
    TEST_ASSERT(response.MitreTechnique[0] != '\0', "Expected MITRE technique");
    TEST_ASSERT(response.MitreTechnique[0] == 'T', "Expected technique starting with T");

    /* T1068 = Exploitation for Privilege Escalation */
    CHAR expectedTech[] = "T1068";
    BOOLEAN techMatches = (RtlCompareMemory(response.MitreTechnique, expectedTech, 5) == 5);
    TEST_ASSERT(techMatches, "Expected T1068 technique for kernel address exploit");

    FreeTestRequest(request);
    return TRUE;
}

/*--------------------------------------------------------------------------
 * Test Runner
 *-------------------------------------------------------------------------*/

NTSTATUS
RunInterceptTests(VOID)
{
    NTSTATUS status;

    TEST_LOG("========================================");
    TEST_LOG("IoRing Interception Unit Tests - Phase 6");
    TEST_LOG("========================================");

    /* Initialize subsystem */
    status = MonInterceptInitialize();
    if (!NT_SUCCESS(status)) {
        TEST_LOG("Failed to initialize interception: 0x%08X", status);
        return status;
    }

    /* Reset test counters */
    g_TestsRun = 0;
    g_TestsPassed = 0;
    g_TestsFailed = 0;

    /* Run tests */
    TestCleanSubmission();
    TestKernelAddressDetection();
    TestExcessiveOperations();
    TestAuditMode();
    TestBlacklistEnforcement();
    TestPolicyEnableDisable();
    TestStatisticsTracking();
    TestMitreTechniqueMapping();

    /* Report results */
    TEST_LOG("========================================");
    TEST_LOG("Test Results:");
    TEST_LOG("  Total:  %lu", g_TestsRun);
    TEST_LOG("  Passed: %lu", g_TestsPassed);
    TEST_LOG("  Failed: %lu", g_TestsFailed);
    TEST_LOG("========================================");

    /* Cleanup */
    MonInterceptShutdown();

    return (g_TestsFailed == 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

/*--------------------------------------------------------------------------
 * Export for test harness integration
 *-------------------------------------------------------------------------*/

NTSTATUS
TestIntercept_Entry(VOID)
{
    return RunInterceptTests();
}
