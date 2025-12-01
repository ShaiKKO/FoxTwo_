/*
 * Telemetry Ring Buffer – Implementation
 *
 * Author: Colin MacRitchie
 * Organization: ziX Performance Labs
 * File: telemetry_ringbuf.c
 * Version: 1.1
 * Date: 2025-12-01
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and confidential.
 *   Redistribution or disclosure without prior written consent is prohibited.
 *
 * Summary
 * -------
 * Implements a fixed-size circular buffer for telemetry event storage.
 *
 * Architecture:
 * - Single contiguous NonPaged allocation for cache efficiency
 * - Lock-free write path using InterlockedCompareExchange64
 * - Spinlock-protected read path for multi-reader safety
 * - Automatic overwrite of oldest events when full
 *
 * Memory Layout:
 * +--------------------------------------------------+
 * |  Event 1  |  Event 2  |  ... Free ...  | Event N |
 * +--------------------------------------------------+
 *             ^WriteOffset              ^ReadOffset
 *
 * When WriteOffset catches up to ReadOffset, oldest events are overwritten.
 *
 * References:
 * - Microsoft ring buffer pattern: https://github.com/microsoft/Windows-driver-samples/blob/main/serial/VirtualSerial2/ringbuffer.h
 * - Lock-free design: https://github.com/stuxnet147/Win-Kernel-Logger
 * - InterlockedCompareExchange64: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-interlockedcompareexchange64
 */

#include <ntifs.h>
#include "telemetry_ringbuf.h"
#include "monitor_internal.h"

#pragma warning(push)
#pragma warning(disable: 4201 4214)

/*--------------------------------------------------------------------------
 * Internal Ring Buffer State
 *-------------------------------------------------------------------------*/

typedef struct _MON_RING_BUFFER_STATE {
    /* Buffer memory */
    PUCHAR              Base;               /* Buffer start */
    ULONG               BufferSize;         /* Total allocation size */

    /* Write position (lock-free via interlocked) */
    volatile LONG64     WriteOffset;        /* Next write position */

    /* Read position (protected by ReadLock) */
    volatile LONG64     ReadOffset;         /* Consumer read position */

    /* Statistics (volatile atomics) */
    volatile LONG       EventCount;         /* Events currently in buffer */
    volatile LONG       SequenceNumber;     /* Next sequence number */
    volatile LONG       WrapCount;          /* Buffer wrap-around count */
    volatile LONG       TotalEventsWritten; /* Lifetime event count */
    volatile LONG       EventsOverwritten;  /* Events lost to overwrite */
    volatile LONG       EventsDropped;      /* Events dropped (too large) */

    /* Timestamps (updated on write) */
    volatile LONG64     OldestTimestamp;    /* Oldest event time */
    volatile LONG64     NewestTimestamp;    /* Newest event time */

    /* Synchronization */
    KSPIN_LOCK          ReadLock;           /* Multi-reader serialization */
    KSPIN_LOCK          WriteLock;          /* Write serialization (simple approach) */

    /* Initialization flag */
    volatile BOOLEAN    Initialized;

} MON_RING_BUFFER_STATE, *PMON_RING_BUFFER_STATE;

static MON_RING_BUFFER_STATE g_RingState = {0};

/* Pool tag for ring buffer allocation */
#define MON_RINGBUF_TAG     'fBRM'  /* 'MRBf' - Monitor Ring Buffer */

/*--------------------------------------------------------------------------
 * Internal Helper Functions
 *-------------------------------------------------------------------------*/

/**
 * @function   MonRingAlignUp
 * @purpose    Align a size up to MON_RINGBUF_ALIGNMENT boundary
 */
static FORCEINLINE ULONG MonRingAlignUp(_In_ ULONG Size)
{
    return (Size + MON_RINGBUF_ALIGNMENT - 1) & ~(MON_RINGBUF_ALIGNMENT - 1);
}

/**
 * @function   MonRingWrapOffset
 * @purpose    Wrap offset around buffer boundary
 */
static FORCEINLINE LONG64 MonRingWrapOffset(_In_ LONG64 Offset, _In_ ULONG BufferSize)
{
    /* Use modulo for wrap-around */
    while (Offset >= (LONG64)BufferSize) {
        Offset -= BufferSize;
    }
    return Offset;
}

/**
 * @function   MonRingGetEventSize
 * @purpose    Calculate total event size with header and alignment
 */
static FORCEINLINE ULONG MonRingGetEventSize(_In_ ULONG PayloadSize)
{
    return MonRingAlignUp(sizeof(MON_RING_EVENT_HEADER) + PayloadSize);
}

/**
 * @function   MonRingGetFreeSpace
 * @purpose    Calculate available space in ring buffer
 * @note       Must be called with appropriate synchronization
 */
static ULONG MonRingGetFreeSpace(VOID)
{
    LONG64 writeOffset = InterlockedCompareExchange64(&g_RingState.WriteOffset, 0, 0);
    LONG64 readOffset = InterlockedCompareExchange64(&g_RingState.ReadOffset, 0, 0);

    if (writeOffset >= readOffset) {
        /* Write ahead of read: free = total - (write - read) */
        return g_RingState.BufferSize - (ULONG)(writeOffset - readOffset);
    } else {
        /* Read ahead of write (wrapped): free = read - write */
        return (ULONG)(readOffset - writeOffset);
    }
}

/**
 * @function   MonRingGetUsedSpace
 * @purpose    Calculate used space in ring buffer
 */
static ULONG MonRingGetUsedSpace(VOID)
{
    return g_RingState.BufferSize - MonRingGetFreeSpace();
}

/**
 * @function   MonRingAdvanceReadOffset
 * @purpose    Skip oldest event to make room for new event
 * @precondition Write lock held
 */
static VOID MonRingAdvanceReadOffset(_In_ ULONG BytesNeeded)
{
    LONG64 readOffset = g_RingState.ReadOffset;
    ULONG bytesFreed = 0;

    while (bytesFreed < BytesNeeded && g_RingState.EventCount > 0) {
        /* Read event header at current read position */
        PMON_RING_EVENT_HEADER header = (PMON_RING_EVENT_HEADER)
            (g_RingState.Base + (readOffset % g_RingState.BufferSize));

        /* Validate magic */
        if (header->Magic != MON_RING_EVENT_MAGIC) {
            /* Corruption detected - reset buffer */
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[WIN11MON][RING] Corruption detected at offset %lld, resetting\n",
                readOffset);
            g_RingState.ReadOffset = g_RingState.WriteOffset;
            g_RingState.EventCount = 0;
            return;
        }

        /* Advance past this event */
        readOffset += header->TotalSize;
        bytesFreed += header->TotalSize;

        InterlockedDecrement(&g_RingState.EventCount);
        InterlockedIncrement(&g_RingState.EventsOverwritten);
    }

    /* Update read offset */
    g_RingState.ReadOffset = MonRingWrapOffset(readOffset, g_RingState.BufferSize);
}

/*--------------------------------------------------------------------------
 * Public API Implementation
 *-------------------------------------------------------------------------*/

_Use_decl_annotations_
NTSTATUS MonRingBufferInitialize(ULONG BufferSizeBytes)
{
    if (g_RingState.Initialized) {
        return STATUS_SUCCESS;
    }

    /* Apply defaults and clamp to valid range */
    if (BufferSizeBytes == 0) {
        BufferSizeBytes = MON_RINGBUF_DEFAULT_SIZE;
    }

    if (BufferSizeBytes < MON_RINGBUF_MIN_SIZE) {
        BufferSizeBytes = MON_RINGBUF_MIN_SIZE;
    }

    if (BufferSizeBytes > MON_RINGBUF_MAX_SIZE) {
        BufferSizeBytes = MON_RINGBUF_MAX_SIZE;
    }

    /* Align to page boundary for efficiency */
    BufferSizeBytes = (BufferSizeBytes + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    /* Allocate buffer from NonPaged pool */
    PUCHAR buffer = (PUCHAR)MonAllocatePoolNonPaged(BufferSizeBytes, MON_RINGBUF_TAG);
    if (buffer == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WIN11MON][RING] Failed to allocate %lu bytes\n", BufferSizeBytes);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Zero initialize buffer */
    RtlZeroMemory(buffer, BufferSizeBytes);

    /* Initialize state */
    RtlZeroMemory(&g_RingState, sizeof(g_RingState));
    g_RingState.Base = buffer;
    g_RingState.BufferSize = BufferSizeBytes;
    g_RingState.WriteOffset = 0;
    g_RingState.ReadOffset = 0;
    g_RingState.EventCount = 0;
    g_RingState.SequenceNumber = 0;
    g_RingState.WrapCount = 0;
    g_RingState.TotalEventsWritten = 0;
    g_RingState.EventsOverwritten = 0;
    g_RingState.EventsDropped = 0;
    g_RingState.OldestTimestamp = 0;
    g_RingState.NewestTimestamp = 0;

    /* Initialize spinlocks */
    KeInitializeSpinLock(&g_RingState.ReadLock);
    KeInitializeSpinLock(&g_RingState.WriteLock);

    /* Mark as initialized with release semantics */
    MonWriteBooleanRelease(&g_RingState.Initialized, TRUE);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][RING] Initialized with %lu bytes (%lu KB)\n",
        BufferSizeBytes, BufferSizeBytes / 1024);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID MonRingBufferShutdown(VOID)
{
    if (!g_RingState.Initialized) {
        return;
    }

    /* Mark as not initialized first */
    g_RingState.Initialized = FALSE;

    /* Free buffer */
    if (g_RingState.Base != NULL) {
        ExFreePoolWithTag(g_RingState.Base, MON_RINGBUF_TAG);
        g_RingState.Base = NULL;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][RING] Shutdown complete (wrote=%lu, overwritten=%lu, dropped=%lu)\n",
        g_RingState.TotalEventsWritten,
        g_RingState.EventsOverwritten,
        g_RingState.EventsDropped);
}

_Use_decl_annotations_
BOOLEAN MonRingBufferIsInitialized(VOID)
{
    return MonReadBooleanAcquire(&g_RingState.Initialized);
}

_Use_decl_annotations_
NTSTATUS MonRingBufferWrite(
    MONITOR_EVENT_TYPE EventType,
    const VOID* Payload,
    ULONG PayloadSize
)
{
    if (!MonReadBooleanAcquire(&g_RingState.Initialized)) {
        return STATUS_NOT_SUPPORTED;
    }

    /* Calculate total event size */
    ULONG eventSize = MonRingGetEventSize(PayloadSize);

    /* Reject events larger than maximum */
    if (eventSize > MON_RING_MAX_EVENT_SIZE) {
        InterlockedIncrement(&g_RingState.EventsDropped);
        return STATUS_BUFFER_OVERFLOW;
    }

    /* Reject events that would fill more than half the buffer */
    if (eventSize > g_RingState.BufferSize / 2) {
        InterlockedIncrement(&g_RingState.EventsDropped);
        return STATUS_BUFFER_OVERFLOW;
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_RingState.WriteLock, &oldIrql);

    /* Check if we need to make room */
    ULONG freeSpace = MonRingGetFreeSpace();
    if (freeSpace < eventSize) {
        /* Overwrite oldest events to make room */
        MonRingAdvanceReadOffset(eventSize - freeSpace + 1);
    }

    /* Get write position */
    LONG64 writeOffset = g_RingState.WriteOffset;
    ULONG bufferOffset = (ULONG)(writeOffset % g_RingState.BufferSize);

    /* Check for wrap-around within event (need contiguous write) */
    if (bufferOffset + eventSize > g_RingState.BufferSize) {
        /*
         * Event would span wrap boundary - advance to start of buffer.
         * Mark remaining space as padding (zero magic).
         */
        if (bufferOffset < g_RingState.BufferSize) {
            PMON_RING_EVENT_HEADER padding = (PMON_RING_EVENT_HEADER)
                (g_RingState.Base + bufferOffset);
            padding->Magic = 0;  /* Invalid magic marks padding */
            padding->TotalSize = g_RingState.BufferSize - bufferOffset;
        }

        writeOffset = MonRingWrapOffset(writeOffset + (g_RingState.BufferSize - bufferOffset),
                                         g_RingState.BufferSize);
        bufferOffset = 0;
        InterlockedIncrement(&g_RingState.WrapCount);
    }

    /* Write event header */
    PMON_RING_EVENT_HEADER header = (PMON_RING_EVENT_HEADER)
        (g_RingState.Base + bufferOffset);

    header->Magic = MON_RING_EVENT_MAGIC;
    header->TotalSize = eventSize;
    header->PayloadSize = PayloadSize;
    header->EventType = EventType;
    KeQuerySystemTime(&header->Timestamp);
    header->ProcessId = HandleToUlong(PsGetCurrentProcessId());
    header->ThreadId = HandleToUlong(PsGetCurrentThreadId());
    header->SequenceNumber = InterlockedIncrement(&g_RingState.SequenceNumber);
    header->Reserved = 0;

    /* Copy payload if present */
    if (PayloadSize > 0 && Payload != NULL) {
        RtlCopyMemory((PUCHAR)header + sizeof(MON_RING_EVENT_HEADER),
                      Payload, PayloadSize);
    }

    /* Update timestamps */
    InterlockedExchange64(&g_RingState.NewestTimestamp, header->Timestamp.QuadPart);
    if (g_RingState.EventCount == 0) {
        InterlockedExchange64(&g_RingState.OldestTimestamp, header->Timestamp.QuadPart);
    }

    /* Advance write offset */
    g_RingState.WriteOffset = MonRingWrapOffset(writeOffset + eventSize,
                                                  g_RingState.BufferSize);

    /* Update counters */
    InterlockedIncrement(&g_RingState.EventCount);
    InterlockedIncrement(&g_RingState.TotalEventsWritten);

    KeReleaseSpinLock(&g_RingState.WriteLock, oldIrql);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS MonRingBufferRead(
    PVOID OutputBuffer,
    ULONG BufferSize,
    PULONG BytesRead,
    PULONG EventCount
)
{
    *BytesRead = 0;
    *EventCount = 0;

    if (!MonReadBooleanAcquire(&g_RingState.Initialized)) {
        return STATUS_NOT_SUPPORTED;
    }

    if (OutputBuffer == NULL || BufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_RingState.ReadLock, &oldIrql);

    PUCHAR output = (PUCHAR)OutputBuffer;
    ULONG bytesWritten = 0;
    ULONG eventsRead = 0;
    LONG64 readOffset = g_RingState.ReadOffset;
    LONG64 writeOffset = g_RingState.WriteOffset;

    while (readOffset != writeOffset && bytesWritten < BufferSize) {
        ULONG bufferOffset = (ULONG)(readOffset % g_RingState.BufferSize);
        PMON_RING_EVENT_HEADER header = (PMON_RING_EVENT_HEADER)
            (g_RingState.Base + bufferOffset);

        /* Check for padding (invalid magic) */
        if (header->Magic != MON_RING_EVENT_MAGIC) {
            /* Skip padding and wrap to start */
            readOffset = 0;
            continue;
        }

        /* Check if event fits in remaining output buffer */
        if (bytesWritten + header->TotalSize > BufferSize) {
            break;
        }

        /* Copy event to output */
        RtlCopyMemory(output + bytesWritten, header, header->TotalSize);

        bytesWritten += header->TotalSize;
        eventsRead++;
        readOffset = MonRingWrapOffset(readOffset + header->TotalSize,
                                        g_RingState.BufferSize);
        InterlockedDecrement(&g_RingState.EventCount);
    }

    /* Update read offset */
    g_RingState.ReadOffset = readOffset;

    /* Update oldest timestamp if we have remaining events */
    if (g_RingState.EventCount > 0) {
        ULONG bufferOffset = (ULONG)(readOffset % g_RingState.BufferSize);
        PMON_RING_EVENT_HEADER header = (PMON_RING_EVENT_HEADER)
            (g_RingState.Base + bufferOffset);
        if (header->Magic == MON_RING_EVENT_MAGIC) {
            InterlockedExchange64(&g_RingState.OldestTimestamp,
                                  header->Timestamp.QuadPart);
        }
    }

    KeReleaseSpinLock(&g_RingState.ReadLock, oldIrql);

    *BytesRead = bytesWritten;
    *EventCount = eventsRead;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS MonRingBufferSnapshot(
    PVOID OutputBuffer,
    ULONG BufferSize,
    PULONG BytesWritten
)
{
    *BytesWritten = 0;

    if (!MonReadBooleanAcquire(&g_RingState.Initialized)) {
        return STATUS_NOT_SUPPORTED;
    }

    if (OutputBuffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Need at least header size */
    if (BufferSize < sizeof(MON_RING_SNAPSHOT_HEADER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_RingState.ReadLock, &oldIrql);

    /* Prepare snapshot header */
    PMON_RING_SNAPSHOT_HEADER snapshotHeader = (PMON_RING_SNAPSHOT_HEADER)OutputBuffer;
    RtlZeroMemory(snapshotHeader, sizeof(MON_RING_SNAPSHOT_HEADER));
    snapshotHeader->Size = sizeof(MON_RING_SNAPSHOT_HEADER);
    KeQuerySystemTime(&snapshotHeader->SnapshotTime);

    PUCHAR output = (PUCHAR)OutputBuffer + sizeof(MON_RING_SNAPSHOT_HEADER);
    ULONG outputRemaining = BufferSize - sizeof(MON_RING_SNAPSHOT_HEADER);
    ULONG bytesWritten = sizeof(MON_RING_SNAPSHOT_HEADER);
    ULONG eventsWritten = 0;
    LONG64 readOffset = g_RingState.ReadOffset;
    LONG64 writeOffset = g_RingState.WriteOffset;
    BOOLEAN firstEvent = TRUE;

    while (readOffset != writeOffset && outputRemaining > 0) {
        ULONG bufferOffset = (ULONG)(readOffset % g_RingState.BufferSize);
        PMON_RING_EVENT_HEADER header = (PMON_RING_EVENT_HEADER)
            (g_RingState.Base + bufferOffset);

        /* Check for padding */
        if (header->Magic != MON_RING_EVENT_MAGIC) {
            readOffset = 0;
            continue;
        }

        /* Check if event fits */
        if (header->TotalSize > outputRemaining) {
            break;
        }

        /* Copy event (non-destructive) */
        RtlCopyMemory(output, header, header->TotalSize);

        /* Track timestamps and sequence */
        if (firstEvent) {
            snapshotHeader->OldestEventTime = header->Timestamp;
            snapshotHeader->FirstSequence = header->SequenceNumber;
            firstEvent = FALSE;
        }
        snapshotHeader->NewestEventTime = header->Timestamp;
        snapshotHeader->LastSequence = header->SequenceNumber;

        output += header->TotalSize;
        outputRemaining -= header->TotalSize;
        bytesWritten += header->TotalSize;
        eventsWritten++;
        readOffset = MonRingWrapOffset(readOffset + header->TotalSize,
                                        g_RingState.BufferSize);
    }

    snapshotHeader->EventCount = eventsWritten;
    snapshotHeader->TotalBytes = bytesWritten;

    KeReleaseSpinLock(&g_RingState.ReadLock, oldIrql);

    *BytesWritten = bytesWritten;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID MonRingBufferGetStats(PMON_RING_BUFFER_STATS Stats)
{
    RtlZeroMemory(Stats, sizeof(MON_RING_BUFFER_STATS));
    Stats->Size = sizeof(MON_RING_BUFFER_STATS);

    if (!MonReadBooleanAcquire(&g_RingState.Initialized)) {
        return;
    }

    Stats->BufferSizeBytes = g_RingState.BufferSize;
    Stats->UsedBytes = MonRingGetUsedSpace();
    Stats->FreeBytes = MonRingGetFreeSpace();
    Stats->EventCount = InterlockedCompareExchange(&g_RingState.EventCount, 0, 0);
    Stats->TotalEventsWritten = InterlockedCompareExchange(&g_RingState.TotalEventsWritten, 0, 0);
    Stats->EventsOverwritten = InterlockedCompareExchange(&g_RingState.EventsOverwritten, 0, 0);
    Stats->EventsDropped = InterlockedCompareExchange(&g_RingState.EventsDropped, 0, 0);
    Stats->WrapCount = InterlockedCompareExchange(&g_RingState.WrapCount, 0, 0);
    Stats->OldestTimestamp.QuadPart = InterlockedCompareExchange64(
        &g_RingState.OldestTimestamp, 0, 0);
    Stats->NewestTimestamp.QuadPart = InterlockedCompareExchange64(
        &g_RingState.NewestTimestamp, 0, 0);
}

_Use_decl_annotations_
VOID MonRingBufferClear(VOID)
{
    if (!MonReadBooleanAcquire(&g_RingState.Initialized)) {
        return;
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_RingState.WriteLock, &oldIrql);
    KeAcquireSpinLockAtDpcLevel(&g_RingState.ReadLock);

    /* Reset pointers */
    g_RingState.WriteOffset = 0;
    g_RingState.ReadOffset = 0;
    g_RingState.EventCount = 0;
    g_RingState.OldestTimestamp = 0;
    g_RingState.NewestTimestamp = 0;

    /* Zero buffer for clean state */
    RtlZeroMemory(g_RingState.Base, g_RingState.BufferSize);

    KeReleaseSpinLockFromDpcLevel(&g_RingState.ReadLock);
    KeReleaseSpinLock(&g_RingState.WriteLock, oldIrql);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][RING] Buffer cleared\n");
}

#pragma warning(pop)
