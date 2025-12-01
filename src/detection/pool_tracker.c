/*
 * Pool Tracker – Big Pool scanning for target tags (e.g., 'IrRB', 'Wnf', 'NpFr')
 *
 * Author: Colin MacRitchie
 * Organization: ziX Performance Labs
 * File: pool_tracker.c
 * Version: 2.0
 * Original Date: 2025-07-20
 * Revision Date: 2025-12-01
 * Copyright:
 *   © 2025 ziX Performance Labs. All rights reserved. Proprietary and confidential.
 *   Redistribution or disclosure without prior written consent is prohibited.
 *
 * Summary
 * -------
 * Periodically queries SystemBigPoolInformation to identify interesting
 * pool allocations by tag. Monitors multiple exploitation-relevant tags:
 *
 * - 'IrRB' (IoRing RegBuffers) - IoRing exploitation primitives
 * - 'IoRg' (IoRing Object)     - IoRing object spray
 * - 'Wnf ' (WNF State Data)    - WNF heap spray (CVE-2021-31956 style)
 * - 'NpFr' (Named Pipe)        - Pipe-based pool spray
 * - 'Toke' (Token Object)      - Token spray/manipulation
 *
 * Phase 2 A3 adds spray detection heuristics to alert on suspicious
 * allocation patterns indicative of heap feng shui attacks.
 *
 * Security
 * --------
 * - Read-only access. No modification of target allocations.
 * - All target addresses are treated as hostile; analysis wraps SEH.
 *
 * References:
 * - CVE-2021-31956: https://www.nccgroup.com/research-blog/cve-2021-31956-exploiting-the-windows-kernel-ntfs-with-wnf-part-1/
 * - Pipe Spray: https://github.com/vp777/Windows-Non-Paged-Pool-Overflow-Exploitation
 */

#include <ntifs.h>
#include "monitor_internal.h"

#pragma warning(push)
#pragma warning(disable: 4201 4214)

/* SystemBigPoolInformation (partial) */
typedef struct _SYSTEM_BIGPOOL_ENTRY {
    union {
        PVOID VirtualAddress;
        ULONG_PTR NonPaged : 1;
    };
    ULONG_PTR SizeInBytes;
    union {
        UCHAR  Tag[4];
        ULONG  TagUlong;
    };
} SYSTEM_BIGPOOL_ENTRY, *PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
    ULONG Count;
    SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
} SYSTEM_BIGPOOL_INFORMATION, *PSYSTEM_BIGPOOL_INFORMATION;

#pragma warning(pop)

#ifndef SystemBigPoolInformation
#define SystemBigPoolInformation 66
#endif

NTKERNELAPI NTSTATUS ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

/*--------------------------------------------------------------------------
 * A3: Extended Pool Tag Definitions
 *
 * Pool tags are stored in little-endian format.
 * 'IrRB' on disk appears as 'BrRI' in memory.
 *-------------------------------------------------------------------------*/

/* IoRing Registered Buffers - primary IoRing exploitation target */
#define TAG_IORING_REGBUF       'BrRI'  /* 'IrRB' */

/* IoRing Object - IoRing object spray */
#define TAG_IORING_OBJECT       'gRoI'  /* 'IoRg' */

/* WNF State Data - CVE-2021-31956 style heap spray */
#define TAG_WNF_STATE           ' fnW'  /* 'Wnf ' */

/* WNF Name Instance - additional WNF structure */
#define TAG_WNF_NAME            'mNnW'  /* 'WnNm' */

/* Named Pipe DATA_ENTRY - pipe-based pool spray */
#define TAG_PIPE_DATA           'rFpN'  /* 'NpFr' */

/* Named Pipe Attribute - PipeAttribute corruption target */
#define TAG_PIPE_ATTR           'ApPN'  /* 'NPpA' - approximate, varies */

/* Token Object - privilege escalation target */
#define TAG_TOKEN               'ekoT'  /* 'Toke' */

/*--------------------------------------------------------------------------
 * A3: Pool Tag Configuration Table
 *
 * Each entry defines a tag to monitor with its properties.
 *-------------------------------------------------------------------------*/
typedef struct _MON_POOL_TAG_CONFIG {
    ULONG       Tag;                /* Pool tag (little-endian) */
    const char* TagName;            /* Human-readable name */
    BOOLEAN     AlertOnFind;        /* Emit alert when found */
    BOOLEAN     TrackForSpray;      /* Include in spray detection */
    ULONG       SprayThreshold;     /* Allocations/scan triggering spray alert */
    const char* MitreTechnique;     /* MITRE ATT&CK technique ID */
} MON_POOL_TAG_CONFIG, *PMON_POOL_TAG_CONFIG;

static const MON_POOL_TAG_CONFIG g_MonitoredTags[] = {
    { TAG_IORING_REGBUF,  "IrRB", TRUE,  TRUE,  50,  "T1068" },
    { TAG_IORING_OBJECT,  "IoRg", FALSE, TRUE,  100, "T1068" },
    { TAG_WNF_STATE,      "Wnf ", FALSE, TRUE,  200, "T1068" },
    { TAG_WNF_NAME,       "WnNm", FALSE, TRUE,  100, "T1068" },
    { TAG_PIPE_DATA,      "NpFr", FALSE, TRUE,  300, "T1068" },
    { TAG_TOKEN,          "Toke", TRUE,  TRUE,  50,  "T1134" },
    { 0, NULL, FALSE, FALSE, 0, NULL }  /* Sentinel */
};

#define MON_TAG_COUNT (ARRAYSIZE(g_MonitoredTags) - 1)

/*--------------------------------------------------------------------------
 * Cached Buffer Size for SystemBigPoolInformation
 *
 * Optimization: Cache the last known buffer size to reduce the number of
 * failed allocations and re-queries. The big pool size tends to be stable
 * between scans, so we start with the cached size + margin.
 *
 * Reference: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/managing-hardware-priorities
 *-------------------------------------------------------------------------*/
static volatile ULONG g_CachedBigPoolBufferSize = 0;
#define MON_BIGPOOL_INITIAL_SIZE        (64 * 1024)     /* 64KB initial guess */
#define MON_BIGPOOL_GROWTH_MARGIN       (16 * 1024)     /* 16KB growth margin */

/*--------------------------------------------------------------------------
 * A3: Spray Detection State
 *
 * Tracks allocation counts per tag across scan windows.
 *-------------------------------------------------------------------------*/
typedef struct _MON_SPRAY_STATE {
    ULONG       TagCounts[MON_TAG_COUNT];       /* Current scan counts */
    ULONG       PrevTagCounts[MON_TAG_COUNT];   /* Previous scan counts */
    LARGE_INTEGER LastScanTime;                 /* Timestamp of last scan */
    BOOLEAN     SprayAlertSent[MON_TAG_COUNT];  /* Prevent alert flood */
} MON_SPRAY_STATE, *PMON_SPRAY_STATE;

static MON_SPRAY_STATE g_SprayState = {0};

/* Local state: single global analysis callback, installed at initialize and
 * cleared at shutdown. Access is unsynchronized; the small race window where
 * a scan may observe the old value during shutdown is acceptable.
 */
static PFN_MON_ANALYZE_REGARRAY g_AnalyzeCb = NULL;

static BOOLEAN TagEquals(ULONG TagUlong, ULONG TagConst)
{
    return TagUlong == TagConst;
}

/*--------------------------------------------------------------------------
 * A3: Helper to find tag index in configuration table
 *-------------------------------------------------------------------------*/
static LONG FindTagIndex(ULONG Tag)
{
    for (ULONG i = 0; i < MON_TAG_COUNT; ++i) {
        if (g_MonitoredTags[i].Tag == Tag) {
            return (LONG)i;
        }
    }
    return -1;
}

/*--------------------------------------------------------------------------
 * A3: Spray Detection - Check thresholds and emit alerts
 *
 * Uses a sliding window approach: compares current scan allocation counts
 * against configured thresholds. Delta detection identifies sudden bursts
 * indicative of heap feng shui preparation.
 *
 * Heuristics based on observed exploitation patterns:
 * - CVE-2021-31956: WNF spray uses hundreds of allocations (threshold: 200)
 * - Pipe spray: May use thousands of allocations (threshold: 300)
 * - IoRing exploitation: Typically smaller, targeted sprays (threshold: 50-100)
 * - Token spray: Low threshold due to high-value target (threshold: 50)
 *
 * References:
 * - https://3sjay.github.io/2024/09/20/Windows-Kernel-Pool-Exploitation-CVE-2021-31956-Part2.html
 * - https://whiteknightlabs.com/2025/03/24/understanding-windows-kernel-pool-memory/
 *-------------------------------------------------------------------------*/
static VOID MonCheckSprayThresholds(VOID)
{
    LARGE_INTEGER now;
    KeQuerySystemTime(&now);

    for (ULONG i = 0; i < MON_TAG_COUNT; ++i) {
        const MON_POOL_TAG_CONFIG* cfg = &g_MonitoredTags[i];
        ULONG count = g_SprayState.TagCounts[i];
        ULONG prevCount = g_SprayState.PrevTagCounts[i];

        if (!cfg->TrackForSpray || cfg->SprayThreshold == 0) {
            continue;
        }

        /*
         * Spray Detection Heuristics:
         *
         * 1. Absolute threshold: Current count exceeds configured threshold
         * 2. Delta detection: Significant increase from previous scan
         *    (2x increase indicates rapid allocation burst)
         */
        BOOLEAN thresholdExceeded = (count >= cfg->SprayThreshold);
        BOOLEAN deltaSpike = (prevCount > 0) && (count >= prevCount * 2) &&
                             (count >= cfg->SprayThreshold / 2);

        if ((thresholdExceeded || deltaSpike) && !g_SprayState.SprayAlertSent[i]) {
            /* Calculate severity based on how far over threshold */
            UCHAR severity = 3;  /* Default: Medium */
            if (count >= cfg->SprayThreshold * 3) {
                severity = 5;  /* Critical */
            } else if (count >= cfg->SprayThreshold * 2) {
                severity = 4;  /* High */
            }

            /* Emit ETW alert */
            MonEtwLogPoolSpray(
                cfg->Tag,
                cfg->TagName,
                count,
                cfg->SprayThreshold,
                severity,
                cfg->MitreTechnique
            );

            /* Prevent alert flood until counts reset */
            g_SprayState.SprayAlertSent[i] = TRUE;
        }

        /* Reset alert flag if count drops significantly */
        if (count < cfg->SprayThreshold / 4) {
            g_SprayState.SprayAlertSent[i] = FALSE;
        }
    }

    /* Store current counts as previous for next scan */
    RtlCopyMemory(g_SprayState.PrevTagCounts, g_SprayState.TagCounts,
                  sizeof(g_SprayState.TagCounts));
    g_SprayState.LastScanTime = now;
}

/**
 * @function   MonPoolTrackerInitialize
 * @purpose    Installs analysis callback and prepares pool tracker state
 * @precondition IRQL <= PASSIVE_LEVEL; Ctx non-NULL (currently unused)
 * @postcondition g_AnalyzeCb set to AnalyzeCb; returns STATUS_SUCCESS
 * @thread-safety Single-threaded init; not re-entrant
 * @side-effects Sets global analysis callback
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS MonPoolTrackerInitialize(_Inout_ PMONITOR_CONTEXT Ctx, _In_ PFN_MON_ANALYZE_REGARRAY AnalyzeCb)
{
    UNREFERENCED_PARAMETER(Ctx);

    /* A3: Initialize spray detection state */
    RtlZeroMemory(&g_SprayState, sizeof(g_SprayState));

    g_AnalyzeCb = AnalyzeCb;
    return STATUS_SUCCESS;
}

/**
 * @function   MonPoolTrackerShutdown
 * @purpose    Clears analysis callback; pairs with MonPoolTrackerInitialize
 * @precondition IRQL <= PASSIVE_LEVEL; Ctx non-NULL (currently unused)
 * @postcondition g_AnalyzeCb set to NULL
 * @thread-safety Called during teardown; not concurrent with scans by design
 * @side-effects Resets global analysis callback
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID MonPoolTrackerShutdown(_Inout_ PMONITOR_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
    g_AnalyzeCb = NULL;
}

/**
 * @function   MonPoolScanSchedule
 * @purpose    Arms timer/DPC to schedule a pool scan after a millisecond delay
 * @precondition IRQL <= DISPATCH_LEVEL; Ctx->ScanTimer and Ctx->ScanDpc initialized
 * @postcondition Timer set to fire; DPC enqueues work item when fired
 * @thread-safety May be called concurrently; timer/DPC are kernel synchronized
 * @side-effects Sets kernel timer
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID MonPoolScanSchedule(
    _Inout_ PMONITOR_CONTEXT Ctx,
    _In_range_(1, 60 * 60 * 1000) ULONG MillisecondsDelay
    )
{
    if (!Ctx) return;
    LARGE_INTEGER due = {0};
    /* Relative time in 100ns units */
    due.QuadPart = -((LONGLONG)MillisecondsDelay * 10000LL);
    KeSetTimer(&Ctx->ScanTimer, due, &Ctx->ScanDpc);
}

/**
 * @function   MonPoolScanNow
 * @purpose    Queries SystemBigPoolInformation and invokes analysis for target-tag allocations
 * @precondition IRQL <= PASSIVE_LEVEL; Ctx non-NULL; g_AnalyzeCb installed
 * @postcondition Iterates big pool entries and invokes g_AnalyzeCb on matches; frees temp buffer
 * @thread-safety Should be invoked from single work item; not re-entrant by design
 * @side-effects Allocates/frees NonPagedPoolNx buffer; may enqueue telemetry via callback
 *
 * A3 Enhancement: Now tracks all monitored tags and performs spray detection
 * heuristics at end of scan.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS MonPoolScanNow(_Inout_ PMONITOR_CONTEXT Ctx)
{
    if (!Ctx || !g_AnalyzeCb) return STATUS_INVALID_PARAMETER;
    if (!Ctx->MonitoringEnabled) return STATUS_SUCCESS;

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG bytes = 0;
    PSYSTEM_BIGPOOL_INFORMATION info = NULL;

    /* A3: Reset tag counts for this scan window */
    RtlZeroMemory(g_SprayState.TagCounts, sizeof(g_SprayState.TagCounts));

    /*
     * Optimization: Use cached buffer size to reduce allocation churn
     *
     * The big pool size is relatively stable between scans, so we start with
     * the cached size plus a growth margin. If the allocation is too small,
     * we fall back to the probe-and-allocate pattern.
     */
    ULONG cachedSize = InterlockedCompareExchange(
        (volatile LONG*)&g_CachedBigPoolBufferSize, 0, 0);

    if (cachedSize > 0) {
        /* Try cached size first with margin for growth */
        ULONG trySize = cachedSize + MON_BIGPOOL_GROWTH_MARGIN;

        info = (PSYSTEM_BIGPOOL_INFORMATION)
            MonAllocatePoolNonPaged(trySize, MON_POOL_TAG);

        if (info != NULL) {
            status = ZwQuerySystemInformation(
                SystemBigPoolInformation, info, trySize, &bytes);

            if (NT_SUCCESS(status)) {
                /* Success! Update cache with actual size */
                InterlockedExchange(
                    (volatile LONG*)&g_CachedBigPoolBufferSize, bytes);
                goto ProcessEntries;
            }

            /* Buffer too small, free and retry with probe */
            ExFreePoolWithTag(info, MON_POOL_TAG);
            info = NULL;
        }
    }

    /* Probe for required buffer size */
    status = ZwQuerySystemInformation(SystemBigPoolInformation, NULL, 0, &bytes);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return status;
    }

    /* Add margin for entries that may be added during allocation */
    bytes += MON_BIGPOOL_GROWTH_MARGIN;

    info = (PSYSTEM_BIGPOOL_INFORMATION)
        MonAllocatePoolNonPaged(bytes, MON_POOL_TAG);
    if (!info) return STATUS_INSUFFICIENT_RESOURCES;

    status = ZwQuerySystemInformation(SystemBigPoolInformation, info, bytes, &bytes);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(info, MON_POOL_TAG);
        return status;
    }

    /* Update cache for next scan */
    InterlockedExchange((volatile LONG*)&g_CachedBigPoolBufferSize, bytes);

ProcessEntries:

    /* Iterate entries and count all monitored tags */
    for (ULONG i = 0; i < info->Count; ++i) {
        const SYSTEM_BIGPOOL_ENTRY* e = &info->AllocatedInfo[i];

        /* e->VirtualAddress may have low bit used to mark NonPaged in some builds; mask it */
        PVOID va = (PVOID)((ULONG_PTR)e->VirtualAddress & ~1ull);
        ULONG tag = e->TagUlong;
        SIZE_T sz = (SIZE_T)e->SizeInBytes;

        /* A3: Check against all monitored tags */
        LONG tagIndex = FindTagIndex(tag);
        if (tagIndex >= 0) {
            /* Increment count for spray detection */
            g_SprayState.TagCounts[tagIndex]++;

            /* Emit alert-on-find for high-priority tags (IrRB, Toke) */
            if (g_MonitoredTags[tagIndex].AlertOnFind && va != NULL) {
                MonEtwLogPoolAllocation(tag, (ULONG64)sz, (ULONG64)va, FALSE);
            }
        }

        /* Special handling for IrRB: invoke analysis callback for IoRing RegBuffers */
        if (TagEquals(tag, TAG_IORING_REGBUF) && va != NULL && sz >= sizeof(PVOID)) {
            /* PERF: limit maximum bytes inspected per entry to bound latency */
            SIZE_T inspect = sz;
            if (inspect > 4 * 1024 * 1024) inspect = 4 * 1024 * 1024;

            NTSTATUS st = g_AnalyzeCb(va, inspect);
            UNREFERENCED_PARAMETER(st);
        }
    }

    /* A3: Check spray thresholds and emit alerts */
    MonCheckSprayThresholds();

    ExFreePoolWithTag(info, MON_POOL_TAG);
    return STATUS_SUCCESS;
}
