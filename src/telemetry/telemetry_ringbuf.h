/*
 * Telemetry Ring Buffer – Public Header
 *
 * Author: Colin MacRitchie
 * Organization: ziX Performance Labs
 * File: telemetry_ringbuf.h
 * Version: 1.1
 * Date: 2025-12-01
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and
 * confidential. Redistribution or disclosure without prior written consent is
 * prohibited.
 *
 * Summary
 * -------
 * Implements a fixed-size circular buffer for telemetry event storage.
 * Provides bounded memory usage with automatic overwrite of oldest events.
 *
 * Design Principles:
 * - Lock-free single-writer producer (MonRingBufferWrite)
 * - Multi-reader consumer with spinlock serialization
 * - Automatic overwrite of oldest events when full
 * - Snapshot capability for non-destructive diagnostics
 * - IRQL-safe up to DISPATCH_LEVEL for writes
 *
 * References:
 * - Microsoft VirtualSerial2 ringbuffer.h sample
 * - Win-Kernel-Logger lock-free design:
 * https://github.com/stuxnet147/Win-Kernel-Logger
 * - ETW circular buffer:
 * https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
 */

#ifndef _ZIX_LABS_TELEMETRY_RINGBUF_H_
#define _ZIX_LABS_TELEMETRY_RINGBUF_H_

#ifndef _KERNEL_MODE
#error "This header is for kernel-mode only."
#endif

#include <ntddk.h>

#include "win11_monitor_mgr.h"

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------
 * Configuration Constants
 *-------------------------------------------------------------------------*/

/* Default buffer size: 1MB provides ~60 seconds at 1000 events/sec */
#define MON_RINGBUF_DEFAULT_SIZE (1024 * 1024)

/* Minimum buffer size: 64KB allows ~100 events minimum */
#define MON_RINGBUF_MIN_SIZE (64 * 1024)

/* Maximum buffer size: 16MB to prevent excessive NonPaged consumption */
#define MON_RINGBUF_MAX_SIZE (16 * 1024 * 1024)

/* Event alignment: 8-byte for atomic operations */
#define MON_RINGBUF_ALIGNMENT 8

/* Magic value for event validation */
#define MON_RING_EVENT_MAGIC 0x54564552 /* 'REVT' */

/* Maximum single event size: 4KB reasonable for most payloads */
#define MON_RING_MAX_EVENT_SIZE (4 * 1024)

/*--------------------------------------------------------------------------
 * Ring Buffer Event Header
 *
 * Stored at the start of each event in the ring buffer.
 * Total event size = sizeof(MON_RING_EVENT_HEADER) + PayloadSize + padding
 *-------------------------------------------------------------------------*/
typedef struct _MON_RING_EVENT_HEADER {
  ULONG Magic;                  /* MON_RING_EVENT_MAGIC for validation */
  ULONG TotalSize;              /* Total bytes including header and padding */
  ULONG PayloadSize;            /* Actual payload bytes */
  MONITOR_EVENT_TYPE EventType; /* Event type enum */
  LARGE_INTEGER Timestamp;      /* KeQuerySystemTime timestamp */
  ULONG ProcessId;              /* Source process ID */
  ULONG ThreadId;               /* Source thread ID */
  ULONG SequenceNumber;         /* Monotonic sequence for ordering */
  ULONG Reserved;               /* Alignment padding */
                                /* Payload follows immediately */
} MON_RING_EVENT_HEADER, *PMON_RING_EVENT_HEADER;

C_ASSERT(sizeof(MON_RING_EVENT_HEADER) == 40);
C_ASSERT((sizeof(MON_RING_EVENT_HEADER) % MON_RINGBUF_ALIGNMENT) == 0);

/*--------------------------------------------------------------------------
 * Ring Buffer Statistics
 *-------------------------------------------------------------------------*/
typedef struct _MON_RING_BUFFER_STATS {
  ULONG Size;                    /* sizeof(MON_RING_BUFFER_STATS) */
  ULONG BufferSizeBytes;         /* Total buffer allocation */
  ULONG UsedBytes;               /* Bytes currently used */
  ULONG FreeBytes;               /* Bytes available */
  ULONG EventCount;              /* Events in buffer */
  ULONG TotalEventsWritten;      /* Lifetime event count */
  ULONG EventsOverwritten;       /* Events lost to overwrite */
  ULONG EventsDropped;           /* Events dropped (too large, etc) */
  ULONG WrapCount;               /* Buffer wrap-around count */
  LARGE_INTEGER OldestTimestamp; /* Oldest event timestamp */
  LARGE_INTEGER NewestTimestamp; /* Newest event timestamp */
} MON_RING_BUFFER_STATS, *PMON_RING_BUFFER_STATS;

/*--------------------------------------------------------------------------
 * Ring Buffer Snapshot Header
 *
 * Returned at start of snapshot buffer to describe contents.
 *-------------------------------------------------------------------------*/
typedef struct _MON_RING_SNAPSHOT_HEADER {
  ULONG Size;                    /* sizeof(MON_RING_SNAPSHOT_HEADER) */
  ULONG EventCount;              /* Events in snapshot */
  ULONG TotalBytes;              /* Total bytes including header */
  ULONG Flags;                   /* Reserved flags */
  LARGE_INTEGER SnapshotTime;    /* When snapshot was taken */
  LARGE_INTEGER OldestEventTime; /* Oldest event timestamp */
  LARGE_INTEGER NewestEventTime; /* Newest event timestamp */
  ULONG FirstSequence;           /* First event sequence number */
  ULONG LastSequence;            /* Last event sequence number */
                                 /* Events follow immediately */
} MON_RING_SNAPSHOT_HEADER, *PMON_RING_SNAPSHOT_HEADER;

/*--------------------------------------------------------------------------
 * Ring Buffer Configuration (for IOCTL_MONITOR_RINGBUF_CONFIGURE)
 *-------------------------------------------------------------------------*/
typedef struct _MON_RINGBUF_CONFIG_INPUT {
  ULONG Size;            /* Must be sizeof(MON_RINGBUF_CONFIG_INPUT) */
  ULONG BufferSizeBytes; /* 0 = use default */
  ULONG Flags;           /* Reserved, must be 0 */
} MON_RINGBUF_CONFIG_INPUT, *PMON_RINGBUF_CONFIG_INPUT;

/*--------------------------------------------------------------------------
 * Public Function Prototypes
 *-------------------------------------------------------------------------*/

/**
 * @function   MonRingBufferInitialize
 * @purpose    Initialize the telemetry ring buffer with specified size
 * @precondition IRQL == PASSIVE_LEVEL; Called from DriverEntry
 * @postcondition Ring buffer allocated and ready for event storage
 * @thread-safety Single-threaded initialization
 * @side-effects Allocates NonPaged pool memory
 *
 * @param[in] BufferSizeBytes - Size in bytes, or 0 for default (1MB)
 *                              Clamped to [MON_RINGBUF_MIN_SIZE,
 * MON_RINGBUF_MAX_SIZE]
 * @returns   STATUS_SUCCESS on success
 *            STATUS_INSUFFICIENT_RESOURCES if allocation fails
 *            STATUS_INVALID_PARAMETER if size out of range
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS MonRingBufferInitialize(_In_ ULONG BufferSizeBytes);

/**
 * @function   MonRingBufferShutdown
 * @purpose    Shut down ring buffer and free memory
 * @precondition IRQL == PASSIVE_LEVEL; Called from DriverUnload
 * @postcondition All memory freed, buffer unavailable
 * @thread-safety Single-threaded shutdown
 * @side-effects Frees NonPaged pool memory
 */
_IRQL_requires_(PASSIVE_LEVEL) VOID MonRingBufferShutdown(VOID);

/**
 * @function   MonRingBufferIsInitialized
 * @purpose    Check if ring buffer is initialized and available
 * @precondition IRQL <= DISPATCH_LEVEL
 * @postcondition Returns TRUE if ring buffer is operational
 * @thread-safety Thread-safe read-only
 * @side-effects None
 */
_IRQL_requires_max_(DISPATCH_LEVEL) BOOLEAN MonRingBufferIsInitialized(VOID);

/**
 * @function   MonRingBufferWrite
 * @purpose    Write an event to the ring buffer (lock-free for single writer)
 * @precondition IRQL <= DISPATCH_LEVEL; Ring buffer initialized
 * @postcondition Event stored in ring buffer, oldest overwritten if full
 * @thread-safety Lock-free single-writer; concurrent writes require external
 * sync
 * @side-effects May overwrite oldest events; updates statistics
 *
 * @param[in] EventType - Event type classification
 * @param[in] Payload - Optional payload data
 * @param[in] PayloadSize - Payload size in bytes (0 if no payload)
 * @returns   STATUS_SUCCESS on success
 *            STATUS_NOT_SUPPORTED if ring buffer not initialized
 *            STATUS_BUFFER_OVERFLOW if event too large for buffer
 */
_IRQL_requires_max_(DISPATCH_LEVEL) NTSTATUS
    MonRingBufferWrite(_In_ MONITOR_EVENT_TYPE EventType,
                       _In_reads_bytes_opt_(PayloadSize) const VOID *Payload,
                       _In_ ULONG PayloadSize);

/**
 * @function   MonRingBufferRead
 * @purpose    Read and consume events from the ring buffer
 * @precondition IRQL == PASSIVE_LEVEL; Ring buffer initialized
 * @postcondition Read events removed from buffer
 * @thread-safety Multi-reader safe via internal spinlock
 * @side-effects Advances read pointer; updates statistics
 *
 * @param[out] OutputBuffer - Buffer to receive events
 * @param[in] BufferSize - Size of output buffer in bytes
 * @param[out] BytesRead - Actual bytes written to buffer
 * @param[out] EventCount - Number of events written
 * @returns   STATUS_SUCCESS on success (may return 0 events if buffer empty)
 *            STATUS_NOT_SUPPORTED if ring buffer not initialized
 *            STATUS_BUFFER_TOO_SMALL if no events fit in buffer
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS
    MonRingBufferRead(_Out_writes_bytes_to_(BufferSize, *BytesRead) PVOID OutputBuffer,
                      _In_ ULONG BufferSize, _Out_ PULONG BytesRead, _Out_ PULONG EventCount);

/**
 * @function   MonRingBufferSnapshot
 * @purpose    Non-destructive copy of ring buffer contents
 * @precondition IRQL == PASSIVE_LEVEL; Ring buffer initialized
 * @postcondition Events copied to output; ring buffer unchanged
 * @thread-safety Multi-reader safe via internal spinlock
 * @side-effects None (read-only operation)
 *
 * @param[out] OutputBuffer - Buffer to receive snapshot (starts with
 * MON_RING_SNAPSHOT_HEADER)
 * @param[in] BufferSize - Size of output buffer in bytes
 * @param[out] BytesWritten - Actual bytes written including header
 * @returns   STATUS_SUCCESS on success
 *            STATUS_NOT_SUPPORTED if ring buffer not initialized
 *            STATUS_BUFFER_TOO_SMALL if header doesn't fit
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS
    MonRingBufferSnapshot(_Out_writes_bytes_to_(BufferSize, *BytesWritten) PVOID OutputBuffer,
                          _In_ ULONG BufferSize, _Out_ PULONG BytesWritten);

/**
 * @function   MonRingBufferGetStats
 * @purpose    Retrieve ring buffer statistics
 * @precondition IRQL <= DISPATCH_LEVEL
 * @postcondition Stats structure populated
 * @thread-safety Thread-safe snapshot of volatile counters
 * @side-effects None
 *
 * @param[out] Stats - Statistics structure to populate
 */
_IRQL_requires_max_(DISPATCH_LEVEL) VOID MonRingBufferGetStats(_Out_ PMON_RING_BUFFER_STATS Stats);

/**
 * @function   MonRingBufferClear
 * @purpose    Clear all events from the ring buffer
 * @precondition IRQL == PASSIVE_LEVEL; Ring buffer initialized
 * @postcondition Ring buffer empty; statistics preserved
 * @thread-safety Acquires internal lock
 * @side-effects Resets read/write pointers
 */
_IRQL_requires_(PASSIVE_LEVEL) VOID MonRingBufferClear(VOID);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _ZIX_LABS_TELEMETRY_RINGBUF_H_ */
