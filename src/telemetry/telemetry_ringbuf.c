/*
 * Telemetry Ring Buffer – Implementation
 *
 * Author: Colin MacRitchie
 * Organization: ziX Performance Labs
 * File: telemetry_ringbuf.c
 * Version: 2.0
 * Date: 2025-12-01
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and
 * confidential. Redistribution or disclosure without prior written consent is
 * prohibited.
 *
 * Summary
 * -------
 * Implements a fixed-size circular buffer for telemetry event storage using
 * a true lock-free write path based on the DPDK rte_ring algorithm.
 *
 * Architecture (MPSC - Multi-Producer Single-Consumer):
 * - Single contiguous NonPaged allocation for cache efficiency
 * - Lock-free multi-producer write path via CAS (InterlockedCompareExchange64)
 * - WriteHead/WriteTail separation: head reserves space, tail commits data
 * - Spinlock-protected read path for multi-reader safety
 * - Automatic overwrite of oldest events when full
 * - Cache-line aligned hot variables to prevent false sharing
 *
 * Lock-Free Write Algorithm:
 * 1. CAS WriteHead to atomically reserve space
 * 2. Copy event data to reserved region
 * 3. Wait for previous writers to commit (WriteTail == our offset)
 * 4. CAS WriteTail to commit our write
 *
 * Memory Layout:
 * +--------------------------------------------------+
 * |  Event 1  |  Event 2  |  ... Free ...  | Event N |
 * +--------------------------------------------------+
 *         ^ReadOffset      ^WriteTail     ^WriteHead
 *         (consumer)       (committed)    (reserved)
 *
 * Uses 64-bit non-wrapping offsets to avoid ABA problem:
 * - At 1M events/sec with 100B avg: ~10^15 years until wrap
 * - Actual buffer position = offset % BufferSize
 */

#include "telemetry_ringbuf.h"

#include <ntifs.h>

#include "monitor_internal.h"

#pragma warning(push)
#pragma warning(disable : 4201 4214)

/*--------------------------------------------------------------------------
 * Internal Ring Buffer State
 *
 * Lock-Free Architecture (MPSC - Multi-Producer Single-Consumer):
 * - WriteHead: Atomically incremented via CAS to reserve space
 * - WriteTail: Updated after data copy to signal completion
 * - ReadOffset: Protected by ReadLock for consumer
 *
 * Write Flow:
 * 1. CAS WriteHead to reserve space
 * 2. Copy data to reserved region
 * 3. Spin until WriteTail == our slot (ordering)
 * 4. Advance WriteTail
 *-------------------------------------------------------------------------*/

typedef struct _MON_RING_BUFFER_STATE {
  /* Buffer memory */
  PUCHAR Base;      /* Buffer start */
  ULONG BufferSize; /* Total allocation size */

  /* Producer state (lock-free via CAS) - separate cache line */
  DECLSPEC_ALIGN(64) volatile LONG64 WriteHead; /* Space reservation point */
  volatile LONG64 WriteTail;                    /* Committed data point */

  /* Consumer state (spinlock protected) - separate cache line */
  DECLSPEC_ALIGN(64) volatile LONG64 ReadOffset; /* Consumer read position */
  KSPIN_LOCK ReadLock;                           /* Multi-reader serialization */

  /* Statistics (atomic updates) - separate cache line */
  DECLSPEC_ALIGN(64) volatile LONG EventCount; /* Events in buffer */
  volatile LONG SequenceNumber;                /* Next sequence number */
  volatile LONG WrapCount;                     /* Buffer wrap count */
  volatile LONG TotalEventsWritten;            /* Lifetime event count */
  volatile LONG EventsOverwritten;             /* Events overwritten */
  volatile LONG EventsDropped;                 /* Events dropped */
  volatile LONG CasRetryCount;                 /* CAS retry count */

  /* Timestamps (updated on write) */
  volatile LONG64 OldestTimestamp; /* Oldest event time */
  volatile LONG64 NewestTimestamp; /* Newest event time */

  /* Initialization flag */
  volatile BOOLEAN Initialized;

} MON_RING_BUFFER_STATE, *PMON_RING_BUFFER_STATE;

static MON_RING_BUFFER_STATE g_RingState = {0};

/* Pool tag for ring buffer allocation */
#define MON_RINGBUF_TAG 'fBRM' /* 'MRBf' - Monitor Ring Buffer */

/*--------------------------------------------------------------------------
 * Internal Helper Functions
 *-------------------------------------------------------------------------*/

/**
 * @function   MonRingAlignUp
 * @purpose    Align a size up to MON_RINGBUF_ALIGNMENT boundary
 */
static FORCEINLINE ULONG MonRingAlignUp(_In_ ULONG Size) {
  return (Size + MON_RINGBUF_ALIGNMENT - 1) & ~(MON_RINGBUF_ALIGNMENT - 1);
}

/**
 * @function   MonRingWrapOffset
 * @purpose    Wrap offset around buffer boundary
 */
static FORCEINLINE LONG64 MonRingWrapOffset(_In_ LONG64 Offset, _In_ ULONG BufferSize) {
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
static FORCEINLINE ULONG MonRingGetEventSize(_In_ ULONG PayloadSize) {
  return MonRingAlignUp(sizeof(MON_RING_EVENT_HEADER) + PayloadSize);
}

/**
 * @function   MonRingGetFreeSpaceLockFree
 * @purpose    Calculate available space using lock-free reads
 * @note       Uses WriteTail (committed) not WriteHead (reserved)
 */
static ULONG MonRingGetFreeSpaceLockFree(VOID) {
  LONG64 writeTail = InterlockedCompareExchange64(&g_RingState.WriteTail, 0, 0);
  LONG64 readOffset = InterlockedCompareExchange64(&g_RingState.ReadOffset, 0, 0);

  /* Use modulo buffer size for both to handle wrap */
  ULONG writePos = (ULONG)(writeTail % g_RingState.BufferSize);
  ULONG readPos = (ULONG)(readOffset % g_RingState.BufferSize);

  if (writeTail >= readOffset) {
    /* Normal case: write ahead of read */
    return g_RingState.BufferSize - (ULONG)(writeTail - readOffset);
  } else {
    /* Should not happen with 64-bit counters, but handle gracefully */
    return g_RingState.BufferSize - (ULONG)(readOffset - writeTail);
  }
}

/**
 * @function   MonRingGetUsedSpaceLockFree
 * @purpose    Calculate used space using lock-free reads
 */
static ULONG MonRingGetUsedSpaceLockFree(VOID) {
  LONG64 writeTail = InterlockedCompareExchange64(&g_RingState.WriteTail, 0, 0);
  LONG64 readOffset = InterlockedCompareExchange64(&g_RingState.ReadOffset, 0, 0);
  return (ULONG)(writeTail - readOffset);
}

/**
 * @function   MonRingAdvanceReadOffset
 * @purpose    Skip oldest events to make room for new event
 * @precondition Called under ReadLock when overwrite needed
 * @note       Uses WriteTail for committed boundary check
 */
static VOID MonRingAdvanceReadOffset(_In_ ULONG BytesNeeded) {
  LONG64 readOffset = g_RingState.ReadOffset;
  LONG64 writeTail = InterlockedCompareExchange64(&g_RingState.WriteTail, 0, 0);
  ULONG bytesFreed = 0;

  while (bytesFreed < BytesNeeded && readOffset < writeTail) {
    ULONG bufferPos = (ULONG)(readOffset % g_RingState.BufferSize);
    PMON_RING_EVENT_HEADER header = (PMON_RING_EVENT_HEADER)(g_RingState.Base + bufferPos);

    /* Check for padding (zero magic means skip to buffer start) */
    if (header->Magic == 0) {
      /* This is padding - skip to buffer start */
      readOffset = ((readOffset / g_RingState.BufferSize) + 1) * g_RingState.BufferSize;
      continue;
    }

    /* Validate magic */
    if (header->Magic != MON_RING_EVENT_MAGIC) {
      /* Corruption detected - reset to WriteTail */
      DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                 "[WIN11MON][RING] Corruption at offset %lld, resetting\n", readOffset);
      InterlockedExchange64(&g_RingState.ReadOffset, writeTail);
      InterlockedExchange(&g_RingState.EventCount, 0);
      return;
    }

    /* Advance past this event */
    readOffset += header->TotalSize;
    bytesFreed += header->TotalSize;

    InterlockedDecrement(&g_RingState.EventCount);
    InterlockedIncrement(&g_RingState.EventsOverwritten);
  }

  /* Update read offset atomically */
  InterlockedExchange64(&g_RingState.ReadOffset, readOffset);
}

/*--------------------------------------------------------------------------
 * Lock-Free CAS Functions
 *-------------------------------------------------------------------------*/

/* Maximum CAS retries before giving up */
#define MON_RING_MAX_CAS_RETRIES 1000

/* Yield threshold for tail wait spin */
#define MON_RING_TAIL_SPIN_YIELD 10000

/**
 * @function   MonRingReserveSpace
 * @purpose    Atomically reserve space in ring buffer via CAS
 * @precondition IRQL <= DISPATCH_LEVEL
 * @postcondition Space reserved, ready for data copy
 * @returns    Offset to write at, or -1 if cannot reserve
 */
static LONG64 MonRingReserveSpace(_In_ ULONG EventSize, _Out_ PULONG ActualSize,
                                  _Out_ PBOOLEAN NeedsPadding, _Out_ PULONG PaddingSize) {
  LONG64 localHead;
  LONG64 newHead;
  ULONG bufferOffset;
  ULONG retryCount = 0;

  *NeedsPadding = FALSE;
  *PaddingSize = 0;
  *ActualSize = EventSize;

  do {
    if (retryCount++ > MON_RING_MAX_CAS_RETRIES) {
      /* Too much contention - drop event */
      InterlockedIncrement(&g_RingState.EventsDropped);
      return -1;
    }

    /* Read current head */
    localHead = InterlockedCompareExchange64(&g_RingState.WriteHead, 0, 0);
    bufferOffset = (ULONG)(localHead % g_RingState.BufferSize);

    /* Check for wrap-around: event must fit contiguously */
    if (bufferOffset + EventSize > g_RingState.BufferSize) {
      /* Need padding to end of buffer, then event at start */
      *PaddingSize = g_RingState.BufferSize - bufferOffset;
      *ActualSize = *PaddingSize + EventSize;
      *NeedsPadding = TRUE;
      newHead = localHead + *ActualSize;
    } else {
      newHead = localHead + EventSize;
    }

    /* CAS to reserve space */
  } while (InterlockedCompareExchange64(&g_RingState.WriteHead, newHead, localHead) != localHead);

  /* Track CAS retries for performance monitoring */
  if (retryCount > 1) {
    InterlockedAdd(&g_RingState.CasRetryCount, (LONG)(retryCount - 1));
  }

  return localHead;
}

/**
 * @function   MonRingCommitWrite
 * @purpose    Commit write by advancing WriteTail (maintains ordering)
 * @precondition Data has been copied to reserved space
 * @postcondition WriteTail advanced, event visible to consumers
 */
static VOID MonRingCommitWrite(_In_ LONG64 MyOffset, _In_ ULONG TotalSize) {
  ULONG spinCount = 0;

  /*
   * Wait for our turn to update tail (preserves event ordering)
   * Previous writers must complete before we can advance tail
   */
  while (InterlockedCompareExchange64(&g_RingState.WriteTail, MyOffset + TotalSize, MyOffset) !=
         MyOffset) {
    /* Previous writer hasn't finished yet */
    if (++spinCount > MON_RING_TAIL_SPIN_YIELD) {
      /* Yield to prevent CPU starvation */
      KeYieldProcessor();
      spinCount = 0;
    }
  }
}

/**
 * @function   MonRingWritePadding
 * @purpose    Write padding marker at wrap boundary
 */
static VOID MonRingWritePadding(_In_ ULONG BufferOffset, _In_ ULONG PaddingSize) {
  if (PaddingSize >= sizeof(MON_RING_EVENT_HEADER)) {
    PMON_RING_EVENT_HEADER padding = (PMON_RING_EVENT_HEADER)(g_RingState.Base + BufferOffset);
    padding->Magic = 0; /* Zero magic indicates padding */
    padding->TotalSize = PaddingSize;
  }
  /* Small padding at end of buffer - just leave as-is */
}

/*--------------------------------------------------------------------------
 * Public API Implementation
 *-------------------------------------------------------------------------*/

_Use_decl_annotations_ NTSTATUS MonRingBufferInitialize(ULONG BufferSizeBytes) {
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
  g_RingState.WriteHead = 0;
  g_RingState.WriteTail = 0;
  g_RingState.ReadOffset = 0;
  g_RingState.EventCount = 0;
  g_RingState.SequenceNumber = 0;
  g_RingState.WrapCount = 0;
  g_RingState.TotalEventsWritten = 0;
  g_RingState.EventsOverwritten = 0;
  g_RingState.EventsDropped = 0;
  g_RingState.CasRetryCount = 0;
  g_RingState.OldestTimestamp = 0;
  g_RingState.NewestTimestamp = 0;

  /* Initialize spinlock for reader */
  KeInitializeSpinLock(&g_RingState.ReadLock);

  /* Mark as initialized with release semantics */
  MonWriteBooleanRelease(&g_RingState.Initialized, TRUE);

  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
             "[WIN11MON][RING] Initialized with %lu bytes (%lu KB)\n", BufferSizeBytes,
             BufferSizeBytes / 1024);

  return STATUS_SUCCESS;
}

_Use_decl_annotations_ VOID MonRingBufferShutdown(VOID) {
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
             "[WIN11MON][RING] Shutdown complete (wrote=%lu, overwritten=%lu, "
             "dropped=%lu)\n",
             g_RingState.TotalEventsWritten, g_RingState.EventsOverwritten,
             g_RingState.EventsDropped);
}

_Use_decl_annotations_ BOOLEAN MonRingBufferIsInitialized(VOID) {
  return MonReadBooleanAcquire(&g_RingState.Initialized);
}

/**
 * @function   MonRingBufferWrite
 * @purpose    Write event to ring buffer using lock-free CAS algorithm
 * @precondition IRQL <= DISPATCH_LEVEL; buffer initialized
 * @postcondition Event stored; oldest events overwritten if buffer full
 *
 * Lock-Free Algorithm (DPDK rte_ring pattern):
 * 1. CAS WriteHead to reserve space
 * 2. Copy data to reserved region
 * 3. Wait for turn to update WriteTail (ordering)
 * 4. CAS WriteTail to commit write
 */
_Use_decl_annotations_ NTSTATUS MonRingBufferWrite(MONITOR_EVENT_TYPE EventType,
                                                   const VOID *Payload, ULONG PayloadSize) {
  LONG64 reservedOffset;
  ULONG eventSize;
  ULONG actualSize;
  ULONG paddingSize;
  ULONG bufferOffset;
  BOOLEAN needsPadding;
  PMON_RING_EVENT_HEADER header;
  LARGE_INTEGER timestamp;

  if (!MonReadBooleanAcquire(&g_RingState.Initialized)) {
    return STATUS_NOT_SUPPORTED;
  }

  /* Calculate total event size (header + payload, aligned) */
  eventSize = MonRingGetEventSize(PayloadSize);

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

  /* Check if we need to make room (overwrite oldest events) */
  if (MonRingGetUsedSpaceLockFree() + eventSize > g_RingState.BufferSize) {
    /* Need to advance read offset - requires ReadLock */
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_RingState.ReadLock, &oldIrql);
    MonRingAdvanceReadOffset(eventSize);
    KeReleaseSpinLock(&g_RingState.ReadLock, oldIrql);
  }

  /* Reserve space via CAS (lock-free) */
  reservedOffset = MonRingReserveSpace(eventSize, &actualSize, &needsPadding, &paddingSize);
  if (reservedOffset < 0) {
    /* CAS failed too many times - event dropped (counter already incremented) */
    return STATUS_DEVICE_BUSY;
  }

  /* Calculate buffer position for this write */
  bufferOffset = (ULONG)(reservedOffset % g_RingState.BufferSize);

  /* Handle wrap-around: write padding marker if needed */
  if (needsPadding) {
    MonRingWritePadding(bufferOffset, paddingSize);
    bufferOffset = 0; /* Event goes at start of buffer */
    InterlockedIncrement(&g_RingState.WrapCount);
  }

  /* Write event header */
  header = (PMON_RING_EVENT_HEADER)(g_RingState.Base + bufferOffset);

  header->Magic = MON_RING_EVENT_MAGIC;
  header->TotalSize = eventSize;
  header->PayloadSize = PayloadSize;
  header->EventType = EventType;
  KeQuerySystemTime(&timestamp);
  header->Timestamp = timestamp;
  header->ProcessId = HandleToUlong(PsGetCurrentProcessId());
  header->ThreadId = HandleToUlong(PsGetCurrentThreadId());
  header->SequenceNumber = InterlockedIncrement(&g_RingState.SequenceNumber);
  header->Reserved = 0;

  /* Copy payload if present */
  if (PayloadSize > 0 && Payload != NULL) {
    RtlCopyMemory((PUCHAR)header + sizeof(MON_RING_EVENT_HEADER), Payload, PayloadSize);
  }

  /* Commit write by advancing WriteTail (preserves ordering) */
  MonRingCommitWrite(reservedOffset, actualSize);

  /* Update timestamps atomically */
  InterlockedExchange64(&g_RingState.NewestTimestamp, timestamp.QuadPart);
  if (InterlockedCompareExchange(&g_RingState.EventCount, 0, 0) == 0) {
    InterlockedExchange64(&g_RingState.OldestTimestamp, timestamp.QuadPart);
  }

  /* Update counters */
  InterlockedIncrement(&g_RingState.EventCount);
  InterlockedIncrement(&g_RingState.TotalEventsWritten);

  return STATUS_SUCCESS;
}

_Use_decl_annotations_ NTSTATUS MonRingBufferRead(PVOID OutputBuffer, ULONG BufferSize,
                                                  PULONG BytesRead, PULONG EventCount) {
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
  LONG64 writeTail = InterlockedCompareExchange64(&g_RingState.WriteTail, 0, 0);

  while (readOffset < writeTail && bytesWritten < BufferSize) {
    ULONG bufferOffset = (ULONG)(readOffset % g_RingState.BufferSize);
    PMON_RING_EVENT_HEADER header = (PMON_RING_EVENT_HEADER)(g_RingState.Base + bufferOffset);

    /* Check for padding (zero magic indicates wrap padding) */
    if (header->Magic == 0) {
      /* Skip padding - advance to next buffer boundary */
      readOffset = ((readOffset / g_RingState.BufferSize) + 1) * g_RingState.BufferSize;
      continue;
    }

    /* Validate magic */
    if (header->Magic != MON_RING_EVENT_MAGIC) {
      /* Corruption - stop reading */
      break;
    }

    /* Check if event fits in remaining output buffer */
    if (bytesWritten + header->TotalSize > BufferSize) {
      break;
    }

    /* Copy event to output */
    RtlCopyMemory(output + bytesWritten, header, header->TotalSize);

    bytesWritten += header->TotalSize;
    eventsRead++;
    readOffset += header->TotalSize;
    InterlockedDecrement(&g_RingState.EventCount);
  }

  /* Update read offset atomically */
  InterlockedExchange64(&g_RingState.ReadOffset, readOffset);

  /* Update oldest timestamp if we have remaining events */
  if (g_RingState.EventCount > 0) {
    ULONG bufferOffset = (ULONG)(readOffset % g_RingState.BufferSize);
    PMON_RING_EVENT_HEADER header = (PMON_RING_EVENT_HEADER)(g_RingState.Base + bufferOffset);
    if (header->Magic == MON_RING_EVENT_MAGIC) {
      InterlockedExchange64(&g_RingState.OldestTimestamp, header->Timestamp.QuadPart);
    }
  }

  KeReleaseSpinLock(&g_RingState.ReadLock, oldIrql);

  *BytesRead = bytesWritten;
  *EventCount = eventsRead;

  return STATUS_SUCCESS;
}

_Use_decl_annotations_ NTSTATUS MonRingBufferSnapshot(PVOID OutputBuffer, ULONG BufferSize,
                                                      PULONG BytesWritten) {
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
  LONG64 writeTail = InterlockedCompareExchange64(&g_RingState.WriteTail, 0, 0);
  BOOLEAN firstEvent = TRUE;

  while (readOffset < writeTail && outputRemaining > 0) {
    ULONG bufferOffset = (ULONG)(readOffset % g_RingState.BufferSize);
    PMON_RING_EVENT_HEADER header = (PMON_RING_EVENT_HEADER)(g_RingState.Base + bufferOffset);

    /* Check for padding (zero magic indicates wrap padding) */
    if (header->Magic == 0) {
      /* Skip padding - advance to next buffer boundary */
      readOffset = ((readOffset / g_RingState.BufferSize) + 1) * g_RingState.BufferSize;
      continue;
    }

    /* Validate magic */
    if (header->Magic != MON_RING_EVENT_MAGIC) {
      /* Corruption - stop reading */
      break;
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
    readOffset += header->TotalSize;
  }

  snapshotHeader->EventCount = eventsWritten;
  snapshotHeader->TotalBytes = bytesWritten;

  KeReleaseSpinLock(&g_RingState.ReadLock, oldIrql);

  *BytesWritten = bytesWritten;

  return STATUS_SUCCESS;
}

_Use_decl_annotations_ VOID MonRingBufferGetStats(PMON_RING_BUFFER_STATS Stats) {
  RtlZeroMemory(Stats, sizeof(MON_RING_BUFFER_STATS));
  Stats->Size = sizeof(MON_RING_BUFFER_STATS);

  if (!MonReadBooleanAcquire(&g_RingState.Initialized)) {
    return;
  }

  Stats->BufferSizeBytes = g_RingState.BufferSize;
  Stats->UsedBytes = MonRingGetUsedSpaceLockFree();
  Stats->FreeBytes = MonRingGetFreeSpaceLockFree();
  Stats->EventCount = InterlockedCompareExchange(&g_RingState.EventCount, 0, 0);
  Stats->TotalEventsWritten = InterlockedCompareExchange(&g_RingState.TotalEventsWritten, 0, 0);
  Stats->EventsOverwritten = InterlockedCompareExchange(&g_RingState.EventsOverwritten, 0, 0);
  Stats->EventsDropped = InterlockedCompareExchange(&g_RingState.EventsDropped, 0, 0);
  Stats->WrapCount = InterlockedCompareExchange(&g_RingState.WrapCount, 0, 0);
  Stats->CasRetryCount = InterlockedCompareExchange(&g_RingState.CasRetryCount, 0, 0);
  Stats->OldestTimestamp.QuadPart =
      InterlockedCompareExchange64(&g_RingState.OldestTimestamp, 0, 0);
  Stats->NewestTimestamp.QuadPart =
      InterlockedCompareExchange64(&g_RingState.NewestTimestamp, 0, 0);
}

_Use_decl_annotations_ VOID MonRingBufferClear(VOID) {
  if (!MonReadBooleanAcquire(&g_RingState.Initialized)) {
    return;
  }

  /*
   * Clear requires coordination with both writers and readers.
   * We use ReadLock and atomic resets for writer state.
   */
  KIRQL oldIrql;
  KeAcquireSpinLock(&g_RingState.ReadLock, &oldIrql);

  /* Reset write pointers atomically */
  InterlockedExchange64(&g_RingState.WriteHead, 0);
  InterlockedExchange64(&g_RingState.WriteTail, 0);
  InterlockedExchange64(&g_RingState.ReadOffset, 0);

  /* Reset counters */
  InterlockedExchange(&g_RingState.EventCount, 0);
  InterlockedExchange64(&g_RingState.OldestTimestamp, 0);
  InterlockedExchange64(&g_RingState.NewestTimestamp, 0);

  /* Zero buffer for clean state */
  RtlZeroMemory(g_RingState.Base, g_RingState.BufferSize);

  KeReleaseSpinLock(&g_RingState.ReadLock, oldIrql);

  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[WIN11MON][RING] Buffer cleared\n");
}

#pragma warning(pop)
