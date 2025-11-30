/*
 * Telemetry Subsystem (ETW/Logging) – Stub with runtime enablement
 *
 * Author: Colin MacRitchie | ziX Labs
 * File: telemetry.c
 * Version: 1.0
 * Date: 2025-11-18
 *
 * Summary
 * -------
 * Lightweight logging facade. In the current release, implements
 * structured event queuing and optional DbgPrintEx. ETW registration
 * can be added later without touching call sites.
 *
 * Security
 * --------
 * - No PII; addresses are numeric and treated as sensitive.
 * - Optional "encryption" flag is a stub for future FIPS enablement.
 */

#include <ntddk.h>
#include "monitor_internal.h"

/* Queue an EVENT_BLOB into the global SLIST (if telemetry enabled) */
/**
 * @function   EnqueueEventBlob
 * @purpose    Internal helper to allocate and queue an EVENT_BLOB if telemetry is enabled
 * @precondition IRQL <= DISPATCH_LEVEL; PayloadLen <= MON_MAX_EVENT_BLOB_BYTES
 * @postcondition On success, pushes node to EventQueue and increments EventCount; on failure increments DroppedEvents
 * @thread-safety Lock-free via interlocked operations
 * @side-effects Allocates from NPaged lookaside; updates global counters/queue
 */
static VOID EnqueueEventBlob(
    _In_ MONITOR_EVENT_TYPE Type,
    _In_reads_bytes_opt_(PayloadLen) const VOID* Payload,
    _In_range_(0, MON_MAX_EVENT_BLOB_BYTES) ULONG PayloadLen
    )
{
    if (!g_Mon.TelemetryEnabled) return;
    if (PayloadLen > MON_MAX_EVENT_BLOB_BYTES) return;

    PMON_EVENT_NODE node = (PMON_EVENT_NODE)ExAllocateFromNPagedLookasideList(&g_Mon.EventLookaside);
    if (!node) {
        InterlockedIncrement64(&g_Mon.DroppedEvents);
        return;
    }

    node->NodeSize = sizeof(MON_EVENT_NODE) + PayloadLen;
    node->Event.Size = sizeof(EVENT_BLOB) + PayloadLen;
    node->Event.Type = Type;
    node->Event.PayloadLength = PayloadLen;
    if (PayloadLen && Payload) {
        RtlCopyMemory(node->Event.Payload, Payload, PayloadLen);
    }

    InterlockedPushEntrySList(&g_Mon.EventQueue, &node->SListEntry);
    InterlockedIncrement(&g_Mon.EventCount);

    /* Optional DEBUG echo for development */
#if DBG
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][TEL] queued type=%u len=%lu\n", Type, PayloadLen);
#endif
}

/**
 * @function   MonTelemetryInitialize
 * @purpose    Initializes telemetry subsystem (ETW registration stub)
 * @precondition IRQL <= PASSIVE_LEVEL; Ctx non-NULL
 * @postcondition Returns STATUS_SUCCESS; no allocations beyond future ETW registration
 * @thread-safety Called during driver init; not concurrent
 * @side-effects None in current stub implementation
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS MonTelemetryInitialize(_Inout_ PMONITOR_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
    /* ETW provider registration would occur here (TraceLoggingRegister) */
    return STATUS_SUCCESS;
}

/**
 * @function   MonTelemetryShutdown
 * @purpose    Disables telemetry and drains the event queue
 * @precondition IRQL <= PASSIVE_LEVEL; Ctx non-NULL
 * @postcondition TelemetryEnabled set to 0; queued events freed from lookaside
 * @thread-safety Single-threaded shutdown; queue drains under local loop
 * @side-effects Frees lookaside-allocated nodes
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID MonTelemetryShutdown(_Inout_ PMONITOR_CONTEXT Ctx)
{
    if (Ctx == NULL) {
        return;
    }

    InterlockedExchange(&Ctx->TelemetryEnabled, 0);

    PSLIST_ENTRY le;
    while ((le = InterlockedPopEntrySList(&Ctx->EventQueue)) != NULL) {
        PMON_EVENT_NODE node = CONTAINING_RECORD(le, MON_EVENT_NODE, SListEntry);
        ExFreeToNPagedLookasideList(&Ctx->EventLookaside, node);
    }

    /* TraceLoggingUnregister if ETW was registered */
}

/**
 * @function   MonTelemetryLogBlob
 * @purpose    Rate-limited logging: enqueues an event blob if within the current window
 * @precondition IRQL <= DISPATCH_LEVEL; Payload is optional and fits within configured max size
 * @postcondition Event enqueued or dropped; global rate counters updated
 * @thread-safety Lock-free via interlocked ops; global window maintained atomically
 * @side-effects Updates DroppedEvents on over-limit
 *
 * B3 Enhancement: Now integrates per-process rate limiting via MonRateLimitCheckEvent().
 * Events are dropped if either global or per-process limits are exceeded.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID MonTelemetryLogBlob(_In_ MONITOR_EVENT_TYPE Type, _In_reads_bytes_opt_(PayloadLen) const VOID* Payload, _In_ ULONG PayloadLen)
{
    /* B3: Per-process rate limiting check */
    ULONG processId = HandleToUlong(PsGetCurrentProcessId());
    MON_RATE_RESULT rateResult = MonRateLimitCheckEvent(processId);
    if (rateResult == MonRateResult_ProcessLimited) {
        InterlockedIncrement64(&g_Mon.DroppedEvents);
        return;
    }
    if (rateResult == MonRateResult_GlobalLimited) {
        InterlockedIncrement64(&g_Mon.DroppedEvents);
        return;
    }

    /* Legacy global rate limiting (fallback if B3 disabled or for backward compat) */
    LARGE_INTEGER now;
    KeQuerySystemTime(&now);

    if (g_Mon.RateWindowStart.QuadPart == 0 ||
        (now.QuadPart - g_Mon.RateWindowStart.QuadPart) > 10 * 1000 * 1000 /* 1s */) {
        g_Mon.RateWindowStart = now;
        InterlockedExchange(&g_Mon.EventsThisWindow, 0);
    }

    LONG n = InterlockedIncrement(&g_Mon.EventsThisWindow);
    if ((ULONG)n > g_Mon.RateLimitPerSec) {
        InterlockedIncrement64(&g_Mon.DroppedEvents);
        return;
    }

    EnqueueEventBlob(Type, Payload, PayloadLen);
}
