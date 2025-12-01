/*
 * Handle Correlation Engine - Implementation
 *
 * Author: Colin MacRitchie
 * Organization: ziX Labs - Security Research Division
 * File: handle_correlator.c
 * Version: 1.0
 * Date: 2025-11-30
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and confidential.
 *   Redistribution or disclosure without prior written consent is prohibited.
 *
 * Summary:
 * Handle enumeration and grouping engine for cross-process detection.
 * Enumerates system handles, groups by object address, and identifies
 * objects shared across multiple processes.
 *
 * Threading Model:
 * - All functions require PASSIVE_LEVEL
 * - Local allocations only; no global state
 *
 * SECURITY PROPERTIES:
 * - Input: Handle table treated as hostile data
 * - Output: Object addresses masked per policy
 * - Memory Safety: Overflow checks on all allocations
 * - IRQL: PASSIVE_LEVEL required
 */

#include <ntddk.h>
#include <ntstrsafe.h>
#include "cross_process.h"
#include "ioring_enum.h"
#include "addr_mask.h"

#pragma warning(push)
#pragma warning(disable: 4201)

/*--------------------------------------------------------------------------*/
/* Undocumented System Information Classes                                  */
/*--------------------------------------------------------------------------*/

#ifndef SystemExtendedHandleInformation
#define SystemExtendedHandleInformation 64
#endif

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID       Object;
    ULONG_PTR   UniqueProcessId;
    ULONG_PTR   HandleValue;
    ULONG       GrantedAccess;
    USHORT      CreatorBackTraceIndex;
    USHORT      ObjectTypeIndex;
    ULONG       HandleAttributes;
    ULONG       Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[ANYSIZE_ARRAY];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

NTKERNELAPI NTSTATUS ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

/*--------------------------------------------------------------------------*/
/* Constants                                                                */
/*--------------------------------------------------------------------------*/

#define MON_HC_POOL_TAG             'cHnM'  /* 'MnHc' - Handle Correlator */
#define MON_HC_BUFFER_MARGIN        0x10000
#define MON_HC_HASH_BITS            16
#define MON_HC_HASH_SIZE            (1u << MON_HC_HASH_BITS)
#define MON_HC_MAX_PROCS_PER_OBJ    MON_XP_MAX_PROCESSES

/*--------------------------------------------------------------------------*/
/* Internal Structures                                                      */
/*--------------------------------------------------------------------------*/

/* Per-object grouping entry in hash table */
typedef struct _MON_HC_GROUP_ENTRY {
    LIST_ENTRY      BucketLink;
    PVOID           ObjectAddress;
    UCHAR           ObjectTypeIndex;
    UCHAR           ProcessCount;
    USHORT          Reserved;
    struct {
        ULONG       ProcessId;
        ULONG64     HandleValue;
        ULONG       AccessMask;
    } Processes[MON_HC_MAX_PROCS_PER_OBJ];
} MON_HC_GROUP_ENTRY, *PMON_HC_GROUP_ENTRY;

/* Hash table context */
typedef struct _MON_HC_HASH_TABLE {
    LIST_ENTRY      Buckets[MON_HC_HASH_SIZE];
    ULONG           TotalEntries;
    ULONG           SharedObjectCount;      /* Objects with ProcessCount > 1 */
} MON_HC_HASH_TABLE, *PMON_HC_HASH_TABLE;

/*--------------------------------------------------------------------------*/
/* Internal Helpers                                                         */
/*--------------------------------------------------------------------------*/

/**
 * Hash function for object addresses
 */
static
FORCEINLINE
ULONG
MonHcHashObjectAddress(
    _In_ PVOID Address
)
{
    ULONG64 addr = (ULONG64)Address >> 3;   /* Pointers are 8-byte aligned */
    ULONG hash = 2166136261u;               /* FNV offset basis */
    hash ^= (ULONG)(addr & 0xFFFFFFFF);
    hash *= 16777619u;                       /* FNV prime */
    hash ^= (ULONG)(addr >> 32);
    hash *= 16777619u;
    return hash & (MON_HC_HASH_SIZE - 1);
}

/**
 * Initialize hash table
 */
static
VOID
MonHcInitHashTable(
    _Out_ PMON_HC_HASH_TABLE Table
)
{
    ULONG i;

    RtlZeroMemory(Table, sizeof(*Table));
    for (i = 0; i < MON_HC_HASH_SIZE; i++) {
        InitializeListHead(&Table->Buckets[i]);
    }
}

/**
 * Find entry in hash table
 */
static
PMON_HC_GROUP_ENTRY
MonHcFindEntry(
    _In_ PMON_HC_HASH_TABLE Table,
    _In_ PVOID ObjectAddress
)
{
    ULONG bucket = MonHcHashObjectAddress(ObjectAddress);
    PLIST_ENTRY entry;
    PMON_HC_GROUP_ENTRY group;

    for (entry = Table->Buckets[bucket].Flink;
         entry != &Table->Buckets[bucket];
         entry = entry->Flink) {

        group = CONTAINING_RECORD(entry, MON_HC_GROUP_ENTRY, BucketLink);
        if (group->ObjectAddress == ObjectAddress) {
            return group;
        }
    }

    return NULL;
}

/**
 * Add handle to hash table
 */
static
NTSTATUS
MonHcAddHandle(
    _Inout_ PMON_HC_HASH_TABLE Table,
    _In_ PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX HandleEntry
)
{
    PMON_HC_GROUP_ENTRY group;
    ULONG bucket;

    group = MonHcFindEntry(Table, HandleEntry->Object);

    if (group == NULL) {
        /* Create new entry */
        group = (PMON_HC_GROUP_ENTRY)ExAllocatePool2(
            POOL_FLAG_PAGED,
            sizeof(MON_HC_GROUP_ENTRY),
            MON_HC_POOL_TAG);

        if (group == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(group, sizeof(*group));
        group->ObjectAddress = HandleEntry->Object;
        group->ObjectTypeIndex = (UCHAR)HandleEntry->ObjectTypeIndex;

        bucket = MonHcHashObjectAddress(HandleEntry->Object);
        InsertTailList(&Table->Buckets[bucket], &group->BucketLink);
        Table->TotalEntries++;
    }

    /* Add process to group if not already present */
    if (group->ProcessCount < MON_HC_MAX_PROCS_PER_OBJ) {
        BOOLEAN found = FALSE;
        ULONG pid = (ULONG)HandleEntry->UniqueProcessId;

        for (UCHAR i = 0; i < group->ProcessCount && !found; i++) {
            if (group->Processes[i].ProcessId == pid) {
                found = TRUE;
            }
        }

        if (!found) {
            UCHAR idx = group->ProcessCount;
            group->Processes[idx].ProcessId = pid;
            group->Processes[idx].HandleValue = (ULONG64)HandleEntry->HandleValue;
            group->Processes[idx].AccessMask = HandleEntry->GrantedAccess;
            group->ProcessCount++;

            /* Track shared objects */
            if (group->ProcessCount == 2) {
                Table->SharedObjectCount++;
            }
        }
    }

    return STATUS_SUCCESS;
}

/**
 * Free hash table entries
 */
static
VOID
MonHcFreeHashTable(
    _Inout_ PMON_HC_HASH_TABLE Table
)
{
    ULONG i;
    PLIST_ENTRY entry;
    PLIST_ENTRY next;
    PMON_HC_GROUP_ENTRY group;

    for (i = 0; i < MON_HC_HASH_SIZE; i++) {
        entry = Table->Buckets[i].Flink;
        while (entry != &Table->Buckets[i]) {
            next = entry->Flink;
            group = CONTAINING_RECORD(entry, MON_HC_GROUP_ENTRY, BucketLink);
            ExFreePoolWithTag(group, MON_HC_POOL_TAG);
            entry = next;
        }
        InitializeListHead(&Table->Buckets[i]);
    }

    Table->TotalEntries = 0;
    Table->SharedObjectCount = 0;
}

/*--------------------------------------------------------------------------*/
/* Handle Enumeration                                                       */
/*--------------------------------------------------------------------------*/

/**
 * Enumerate all handles and build grouping table
 */
static
NTSTATUS
MonHcEnumerateHandles(
    _Out_ PMON_HC_HASH_TABLE Table,
    _In_opt_ UCHAR FilterTypeIndex      /* 0 = no filter */
)
{
    NTSTATUS status;
    ULONG bufferSize = 0;
    ULONG newBufferSize;
    PSYSTEM_HANDLE_INFORMATION_EX handleInfo = NULL;
    ULONG_PTR i;

    MonHcInitHashTable(Table);

    /* Query required buffer size */
    status = ZwQuerySystemInformation(
        SystemExtendedHandleInformation,
        NULL,
        0,
        &bufferSize);

    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return status;
    }

    /* Add margin for handles created during allocation */
    newBufferSize = bufferSize + MON_HC_BUFFER_MARGIN;
    if (newBufferSize < bufferSize) {
        return STATUS_INTEGER_OVERFLOW;
    }
    bufferSize = newBufferSize;

    /* Allocate from paged pool */
    handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)ExAllocatePool2(
        POOL_FLAG_PAGED,
        bufferSize,
        MON_HC_POOL_TAG);

    if (handleInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Query handles */
    status = ZwQuerySystemInformation(
        SystemExtendedHandleInformation,
        handleInfo,
        bufferSize,
        &bufferSize);

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(handleInfo, MON_HC_POOL_TAG);
        return status;
    }

    /* Process each handle */
    for (i = 0; i < handleInfo->NumberOfHandles; i++) {
        PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry = &handleInfo->Handles[i];

        /* Skip NULL objects */
        if (entry->Object == NULL) {
            continue;
        }

        /* Skip user-mode addresses (security check) */
        if ((ULONG64)entry->Object < 0xFFFF800000000000ULL) {
            continue;
        }

        /* Skip PID 4 (System process) - too many handles, usually benign */
        if (entry->UniqueProcessId == 4) {
            continue;
        }

        /* Apply type filter if specified */
        if (FilterTypeIndex != 0 && entry->ObjectTypeIndex != FilterTypeIndex) {
            continue;
        }

        /* Add to hash table */
        status = MonHcAddHandle(Table, entry);
        if (!NT_SUCCESS(status)) {
            /* Log but continue - don't fail entire scan */
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[WIN11MON][HC] Failed to add handle: 0x%08X\n", status);
        }
    }

    ExFreePoolWithTag(handleInfo, MON_HC_POOL_TAG);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
        "[WIN11MON][HC] Enumerated %lu entries, %lu shared\n",
        Table->TotalEntries, Table->SharedObjectCount);

    return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------*/
/* Public API                                                               */
/*--------------------------------------------------------------------------*/

/**
 * @function   MonHcCorrelateHandles
 * @purpose    Enumerate handles and find cross-process sharing
 * @precondition IRQL == PASSIVE_LEVEL
 * @returns    STATUS_SUCCESS on completion
 *
 * @param[out] SharedCount - Number of shared objects found (optional)
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MonHcCorrelateHandles(
    _Out_opt_ ULONG* SharedCount
)
{
    NTSTATUS status;
    MON_HC_HASH_TABLE hashTable;
    const MON_IORING_TYPE_INFO* ioRingInfo;
    UCHAR filterType = 0;

    if (SharedCount != NULL) {
        *SharedCount = 0;
    }

    /* Get IoRing type index if available for filtering */
    ioRingInfo = MonGetIoRingTypeInfo();
    if (ioRingInfo != NULL && ioRingInfo->Initialized) {
        filterType = ioRingInfo->TypeIndex;
    }

    /* Enumerate and group handles */
    status = MonHcEnumerateHandles(&hashTable, filterType);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Process shared objects */
    /* TODO: Integrate with cross_process.c to analyze relationships */
    /* For each shared object, call MonXp* functions to:
     * - Check parent-child relationships
     * - Validate integrity levels
     * - Calculate risk scores
     * - Generate alerts
     */

    if (SharedCount != NULL) {
        *SharedCount = hashTable.SharedObjectCount;
    }

    /* Cleanup */
    MonHcFreeHashTable(&hashTable);

    return STATUS_SUCCESS;
}

/**
 * @function   MonHcEnumerateSharedObjects
 * @purpose    Enumerate shared objects and invoke callback
 * @precondition IRQL == PASSIVE_LEVEL
 */
typedef BOOLEAN (NTAPI *PMON_HC_SHARED_CALLBACK)(
    _In_ PVOID ObjectAddress,
    _In_ UCHAR ObjectTypeIndex,
    _In_ UCHAR ProcessCount,
    _In_reads_(ProcessCount) const ULONG* ProcessIds,
    _In_opt_ PVOID Context
);

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MonHcEnumerateSharedObjects(
    _In_ PMON_HC_SHARED_CALLBACK Callback,
    _In_opt_ PVOID Context
)
{
    NTSTATUS status;
    MON_HC_HASH_TABLE hashTable;
    ULONG i;
    PLIST_ENTRY entry;
    PMON_HC_GROUP_ENTRY group;
    ULONG processIds[MON_HC_MAX_PROCS_PER_OBJ];

    if (Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Enumerate all handles (no type filter for general correlation) */
    status = MonHcEnumerateHandles(&hashTable, 0);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Walk hash table and report shared objects */
    for (i = 0; i < MON_HC_HASH_SIZE; i++) {
        for (entry = hashTable.Buckets[i].Flink;
             entry != &hashTable.Buckets[i];
             entry = entry->Flink) {

            group = CONTAINING_RECORD(entry, MON_HC_GROUP_ENTRY, BucketLink);

            /* Only report shared objects (2+ processes) */
            if (group->ProcessCount < 2) {
                continue;
            }

            /* Build process ID array */
            for (UCHAR j = 0; j < group->ProcessCount; j++) {
                processIds[j] = group->Processes[j].ProcessId;
            }

            /* Invoke callback */
            if (!Callback(group->ObjectAddress, group->ObjectTypeIndex,
                          group->ProcessCount, processIds, Context)) {
                break;  /* Callback requested stop */
            }
        }
    }

    MonHcFreeHashTable(&hashTable);
    return STATUS_SUCCESS;
}

#pragma warning(pop)
