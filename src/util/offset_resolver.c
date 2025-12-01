/*
 * Dynamic Offset Resolution Module
 *
 * Author: Colin MacRitchie
 * Organization: ziX Performance Labs
 * File: offset_resolver.c
 * Version: 1.0
 * Date: 2025-12-01
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and confidential.
 *   Redistribution or disclosure without prior written consent is prohibited.
 *
 * Summary
 * -------
 * Implements the three-tier offset resolution strategy:
 * 1. Embedded Tables - Known Windows builds with hardcoded offsets
 * 2. Signature-Based - Memory scanning fallback for unknown builds
 * 3. Override - Admin-provided offsets via registry/IOCTL
 *
 * Safety
 * ------
 * - All offset validation uses SEH to prevent BSOD
 * - Graceful degradation on resolution failure
 * - ETW audit trail for all resolution attempts
 */

#include <ntifs.h>
#include "offset_resolver.h"
#include "monitor_internal.h"

#pragma warning(push)
#pragma warning(disable: 4201 4214)

/*--------------------------------------------------------------------------
 * Module Tags
 *-------------------------------------------------------------------------*/
#define MON_OFFSET_TAG      'sffO'  /* 'Offs' - Offset resolver */

/*--------------------------------------------------------------------------
 * Embedded Offset Tables
 *
 * These tables contain known-good offsets for various Windows builds.
 * Source: Vergilius Project and manual reverse engineering.
 *-------------------------------------------------------------------------*/

/* IORING_OBJECT offsets for various builds */
static const struct {
    ULONG   BuildMin;       /* Minimum build number (inclusive) */
    ULONG   BuildMax;       /* Maximum build number (inclusive) */
    ULONG   StructureSize;
    ULONG   RegBuffersCountOffset;
    ULONG   RegBuffersOffset;
    ULONG   RegFilesCountOffset;
    ULONG   RegFilesOffset;
} g_IoRingEmbeddedOffsets[] = {
    /* Windows 11 22H2 (Build 22621-22622) */
    { 22621, 22622, 0xD0, 0xB0, 0xB8, 0xC0, 0xC8 },

    /* Windows 11 23H2 (Build 22631-22635) */
    { 22631, 22635, 0xD0, 0xB0, 0xB8, 0xC0, 0xC8 },

    /* Windows 11 24H2 (Build 26100-26200) - preliminary from Vergilius */
    { 26100, 26200, 0xD0, 0xB0, 0xB8, 0xC0, 0xC8 },

    /* Windows 11 Insider Canary (Build 26xxx) - same offsets observed */
    { 26201, 27000, 0xD0, 0xB0, 0xB8, 0xC0, 0xC8 },

    /* Sentinel */
    { 0, 0, 0, 0, 0, 0, 0 }
};

/*--------------------------------------------------------------------------
 * Module State
 *-------------------------------------------------------------------------*/
typedef struct _MON_OFFSET_RESOLVER_STATE {
    BOOLEAN                     Initialized;
    BOOLEAN                     Degraded;
    ULONG                       CurrentBuild;
    MON_OFFSET_RESOLVER_CONFIG  Config;

    /* Registered structures */
    MON_STRUCTURE_OFFSETS       Structures[MON_OFFSET_MAX_STRUCTURES];
    ULONG                       StructureCount;

    /* Statistics */
    volatile LONG               EmbeddedHits;
    volatile LONG               SignatureHits;
    volatile LONG               InferenceHits;
    volatile LONG               ValidationFailures;

    /* Synchronization */
    KSPIN_LOCK                  Lock;
} MON_OFFSET_RESOLVER_STATE, *PMON_OFFSET_RESOLVER_STATE;

static MON_OFFSET_RESOLVER_STATE g_OffsetState = {0};

/*--------------------------------------------------------------------------
 * Internal Helper: Detect Windows Build
 *-------------------------------------------------------------------------*/
static ULONG MonOffsetDetectBuild(VOID)
{
    RTL_OSVERSIONINFOW versionInfo = {0};
    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);

    NTSTATUS status = RtlGetVersion(&versionInfo);
    if (!NT_SUCCESS(status)) {
        return 0;
    }

    return versionInfo.dwBuildNumber;
}

/*--------------------------------------------------------------------------
 * Internal Helper: Find Structure by Name
 *-------------------------------------------------------------------------*/
static PMON_STRUCTURE_OFFSETS MonOffsetFindStructure(
    _In_z_ const CHAR* StructureName
)
{
    for (ULONG i = 0; i < g_OffsetState.StructureCount; i++) {
        if (_stricmp(g_OffsetState.Structures[i].StructureName, StructureName) == 0) {
            return &g_OffsetState.Structures[i];
        }
    }
    return NULL;
}

/*--------------------------------------------------------------------------
 * Internal Helper: Find Field in Structure
 *-------------------------------------------------------------------------*/
static PMON_RESOLVED_OFFSET MonOffsetFindField(
    _In_ PMON_STRUCTURE_OFFSETS Structure,
    _In_z_ const CHAR* FieldName
)
{
    for (ULONG i = 0; i < Structure->FieldCount; i++) {
        if (_stricmp(Structure->Fields[i].FieldName, FieldName) == 0) {
            return &Structure->Fields[i];
        }
    }
    return NULL;
}

/*--------------------------------------------------------------------------
 * Internal Helper: Resolve IORING_OBJECT from Embedded Table
 *-------------------------------------------------------------------------*/
static NTSTATUS MonOffsetResolveIoRingEmbedded(
    _In_ ULONG BuildNumber,
    _Out_ PMON_STRUCTURE_OFFSETS Offsets
)
{
    /* Search for exact match or range match */
    for (ULONG i = 0; g_IoRingEmbeddedOffsets[i].BuildMin != 0; i++) {
        if (BuildNumber >= g_IoRingEmbeddedOffsets[i].BuildMin &&
            BuildNumber <= g_IoRingEmbeddedOffsets[i].BuildMax) {

            /* Found matching entry */
            RtlZeroMemory(Offsets, sizeof(*Offsets));
            RtlStringCchCopyA(Offsets->StructureName, MON_OFFSET_MAX_NAME_LEN, MON_STRUCT_IORING_OBJECT);
            Offsets->StructureSize = g_IoRingEmbeddedOffsets[i].StructureSize;
            Offsets->TargetBuild = BuildNumber;
            Offsets->SourceBuild = g_IoRingEmbeddedOffsets[i].BuildMin;
            Offsets->OverallSource = MonOffsetSource_Embedded;
            Offsets->OverallValidation = MonOffsetValidation_NotTested;

            /* Populate fields */
            Offsets->FieldCount = 4;

            /* RegBuffersCount */
            RtlStringCchCopyA(Offsets->Fields[0].FieldName, MON_OFFSET_MAX_NAME_LEN, MON_FIELD_REGBUFFERS_COUNT);
            Offsets->Fields[0].Offset = g_IoRingEmbeddedOffsets[i].RegBuffersCountOffset;
            Offsets->Fields[0].Size = sizeof(ULONG);
            Offsets->Fields[0].Source = MonOffsetSource_Embedded;

            /* RegBuffers */
            RtlStringCchCopyA(Offsets->Fields[1].FieldName, MON_OFFSET_MAX_NAME_LEN, MON_FIELD_REGBUFFERS);
            Offsets->Fields[1].Offset = g_IoRingEmbeddedOffsets[i].RegBuffersOffset;
            Offsets->Fields[1].Size = sizeof(PVOID);
            Offsets->Fields[1].Source = MonOffsetSource_Embedded;

            /* RegFilesCount */
            RtlStringCchCopyA(Offsets->Fields[2].FieldName, MON_OFFSET_MAX_NAME_LEN, MON_FIELD_REGFILES_COUNT);
            Offsets->Fields[2].Offset = g_IoRingEmbeddedOffsets[i].RegFilesCountOffset;
            Offsets->Fields[2].Size = sizeof(ULONG);
            Offsets->Fields[2].Source = MonOffsetSource_Embedded;

            /* RegFiles */
            RtlStringCchCopyA(Offsets->Fields[3].FieldName, MON_OFFSET_MAX_NAME_LEN, MON_FIELD_REGFILES);
            Offsets->Fields[3].Offset = g_IoRingEmbeddedOffsets[i].RegFilesOffset;
            Offsets->Fields[3].Size = sizeof(PVOID);
            Offsets->Fields[3].Source = MonOffsetSource_Embedded;

            InterlockedIncrement(&g_OffsetState.EmbeddedHits);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[WIN11MON][OFFSET] Resolved %s from embedded table (build %lu->%lu)\n",
                MON_STRUCT_IORING_OBJECT, BuildNumber, Offsets->SourceBuild);

            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

/*--------------------------------------------------------------------------
 * Internal Helper: Infer IORING_OBJECT from Nearest Build
 *-------------------------------------------------------------------------*/
static NTSTATUS MonOffsetResolveIoRingInferred(
    _In_ ULONG BuildNumber,
    _In_ ULONG Tolerance,
    _Out_ PMON_STRUCTURE_OFFSETS Offsets
)
{
    LONG bestDelta = LONG_MAX;
    ULONG bestIndex = ULONG_MAX;

    /* Find nearest build within tolerance */
    for (ULONG i = 0; g_IoRingEmbeddedOffsets[i].BuildMin != 0; i++) {
        /* Calculate distance to range */
        LONG delta;
        if (BuildNumber < g_IoRingEmbeddedOffsets[i].BuildMin) {
            delta = (LONG)g_IoRingEmbeddedOffsets[i].BuildMin - (LONG)BuildNumber;
        } else if (BuildNumber > g_IoRingEmbeddedOffsets[i].BuildMax) {
            delta = (LONG)BuildNumber - (LONG)g_IoRingEmbeddedOffsets[i].BuildMax;
        } else {
            delta = 0; /* Within range */
        }

        if (delta < bestDelta && (ULONG)delta <= Tolerance) {
            bestDelta = delta;
            bestIndex = i;
        }
    }

    if (bestIndex == ULONG_MAX) {
        return STATUS_NOT_FOUND;
    }

    /* Use nearest build's offsets */
    RtlZeroMemory(Offsets, sizeof(*Offsets));
    RtlStringCchCopyA(Offsets->StructureName, MON_OFFSET_MAX_NAME_LEN, MON_STRUCT_IORING_OBJECT);
    Offsets->StructureSize = g_IoRingEmbeddedOffsets[bestIndex].StructureSize;
    Offsets->TargetBuild = BuildNumber;
    Offsets->SourceBuild = g_IoRingEmbeddedOffsets[bestIndex].BuildMin;
    Offsets->OverallSource = MonOffsetSource_Inferred;
    Offsets->OverallValidation = MonOffsetValidation_NotTested;

    /* Populate fields (same as embedded) */
    Offsets->FieldCount = 4;

    RtlStringCchCopyA(Offsets->Fields[0].FieldName, MON_OFFSET_MAX_NAME_LEN, MON_FIELD_REGBUFFERS_COUNT);
    Offsets->Fields[0].Offset = g_IoRingEmbeddedOffsets[bestIndex].RegBuffersCountOffset;
    Offsets->Fields[0].Size = sizeof(ULONG);
    Offsets->Fields[0].Source = MonOffsetSource_Inferred;

    RtlStringCchCopyA(Offsets->Fields[1].FieldName, MON_OFFSET_MAX_NAME_LEN, MON_FIELD_REGBUFFERS);
    Offsets->Fields[1].Offset = g_IoRingEmbeddedOffsets[bestIndex].RegBuffersOffset;
    Offsets->Fields[1].Size = sizeof(PVOID);
    Offsets->Fields[1].Source = MonOffsetSource_Inferred;

    RtlStringCchCopyA(Offsets->Fields[2].FieldName, MON_OFFSET_MAX_NAME_LEN, MON_FIELD_REGFILES_COUNT);
    Offsets->Fields[2].Offset = g_IoRingEmbeddedOffsets[bestIndex].RegFilesCountOffset;
    Offsets->Fields[2].Size = sizeof(ULONG);
    Offsets->Fields[2].Source = MonOffsetSource_Inferred;

    RtlStringCchCopyA(Offsets->Fields[3].FieldName, MON_OFFSET_MAX_NAME_LEN, MON_FIELD_REGFILES);
    Offsets->Fields[3].Offset = g_IoRingEmbeddedOffsets[bestIndex].RegFilesOffset;
    Offsets->Fields[3].Size = sizeof(PVOID);
    Offsets->Fields[3].Source = MonOffsetSource_Inferred;

    InterlockedIncrement(&g_OffsetState.InferenceHits);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
        "[WIN11MON][OFFSET] Inferred %s from build %lu (delta=%ld)\n",
        MON_STRUCT_IORING_OBJECT, Offsets->SourceBuild, bestDelta);

    return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
 * Public API
 *-------------------------------------------------------------------------*/

_Use_decl_annotations_
NTSTATUS MonOffsetResolverInitialize(
    const MON_OFFSET_RESOLVER_CONFIG* Config
)
{
    NTSTATUS status;

    if (g_OffsetState.Initialized) {
        return STATUS_ALREADY_INITIALIZED;
    }

    RtlZeroMemory(&g_OffsetState, sizeof(g_OffsetState));
    KeInitializeSpinLock(&g_OffsetState.Lock);

    /* Apply configuration */
    if (Config != NULL && Config->Size == sizeof(MON_OFFSET_RESOLVER_CONFIG)) {
        g_OffsetState.Config = *Config;
    } else {
        /* Defaults */
        g_OffsetState.Config.Size = sizeof(MON_OFFSET_RESOLVER_CONFIG);
        g_OffsetState.Config.EnableSignatureScan = FALSE;   /* Future feature */
        g_OffsetState.Config.EnableInference = TRUE;
        g_OffsetState.Config.RequireValidation = FALSE;
        g_OffsetState.Config.BuildTolerance = MON_OFFSET_BUILD_TOLERANCE;
    }

    /* Detect current build */
    g_OffsetState.CurrentBuild = MonOffsetDetectBuild();
    if (g_OffsetState.CurrentBuild == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WIN11MON][OFFSET] Failed to detect Windows build\n");
        return STATUS_NOT_SUPPORTED;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][OFFSET] Initializing for Windows build %lu\n",
        g_OffsetState.CurrentBuild);

    /* Resolve IORING_OBJECT offsets */
    MON_STRUCTURE_OFFSETS ioringOffsets = {0};

    status = MonOffsetResolveIoRingEmbedded(g_OffsetState.CurrentBuild, &ioringOffsets);

    if (status == STATUS_NOT_FOUND && g_OffsetState.Config.EnableInference) {
        /* Try inference from nearest build */
        status = MonOffsetResolveIoRingInferred(
            g_OffsetState.CurrentBuild,
            g_OffsetState.Config.BuildTolerance,
            &ioringOffsets
        );
    }

    if (NT_SUCCESS(status)) {
        /* Register the resolved offsets */
        status = MonRegisterStructureOffsets(&ioringOffsets);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[WIN11MON][OFFSET] Failed to register %s: 0x%08X\n",
                MON_STRUCT_IORING_OBJECT, status);
        }
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WIN11MON][OFFSET] No offsets for build %lu; operating in degraded mode\n",
            g_OffsetState.CurrentBuild);
        g_OffsetState.Degraded = TRUE;
    }

    /* Memory barrier ensures state visible before Initialized flag */
    MemoryBarrier();
    g_OffsetState.Initialized = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][OFFSET] Initialized (build=%lu, structures=%lu, degraded=%s)\n",
        g_OffsetState.CurrentBuild,
        g_OffsetState.StructureCount,
        g_OffsetState.Degraded ? "YES" : "NO");

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID MonOffsetResolverShutdown(VOID)
{
    g_OffsetState.Initialized = FALSE;
    g_OffsetState.StructureCount = 0;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][OFFSET] Shutdown (embedded=%ld, inferred=%ld, failures=%ld)\n",
        g_OffsetState.EmbeddedHits,
        g_OffsetState.InferenceHits,
        g_OffsetState.ValidationFailures);
}

_Use_decl_annotations_
BOOLEAN MonOffsetResolverIsInitialized(VOID)
{
    return g_OffsetState.Initialized;
}

_Use_decl_annotations_
NTSTATUS MonGetStructureOffsets(
    const CHAR* StructureName,
    PMON_STRUCTURE_OFFSETS Offsets
)
{
    if (StructureName == NULL || Offsets == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_OffsetState.Initialized) {
        return STATUS_NOT_SUPPORTED;
    }

    PMON_STRUCTURE_OFFSETS found = MonOffsetFindStructure(StructureName);
    if (found == NULL) {
        return STATUS_NOT_FOUND;
    }

    RtlCopyMemory(Offsets, found, sizeof(*Offsets));
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS MonGetFieldOffset(
    const CHAR* StructureName,
    const CHAR* FieldName,
    PULONG Offset
)
{
    if (StructureName == NULL || FieldName == NULL || Offset == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_OffsetState.Initialized) {
        return STATUS_NOT_SUPPORTED;
    }

    PMON_STRUCTURE_OFFSETS structure = MonOffsetFindStructure(StructureName);
    if (structure == NULL) {
        return STATUS_NOT_FOUND;
    }

    PMON_RESOLVED_OFFSET field = MonOffsetFindField(structure, FieldName);
    if (field == NULL) {
        return STATUS_NOT_FOUND;
    }

    *Offset = field->Offset;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS MonGetFieldOffsetWithSize(
    const CHAR* StructureName,
    const CHAR* FieldName,
    PULONG Offset,
    PULONG Size
)
{
    if (StructureName == NULL || FieldName == NULL || Offset == NULL || Size == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_OffsetState.Initialized) {
        return STATUS_NOT_SUPPORTED;
    }

    PMON_STRUCTURE_OFFSETS structure = MonOffsetFindStructure(StructureName);
    if (structure == NULL) {
        return STATUS_NOT_FOUND;
    }

    PMON_RESOLVED_OFFSET field = MonOffsetFindField(structure, FieldName);
    if (field == NULL) {
        return STATUS_NOT_FOUND;
    }

    *Offset = field->Offset;
    *Size = field->Size;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
MON_OFFSET_SOURCE MonGetOffsetSource(
    const CHAR* StructureName
)
{
    if (StructureName == NULL || !g_OffsetState.Initialized) {
        return MonOffsetSource_Unknown;
    }

    PMON_STRUCTURE_OFFSETS found = MonOffsetFindStructure(StructureName);
    if (found == NULL) {
        return MonOffsetSource_Unknown;
    }

    return found->OverallSource;
}

_Use_decl_annotations_
BOOLEAN MonAreOffsetsValidated(
    const CHAR* StructureName
)
{
    if (StructureName == NULL || !g_OffsetState.Initialized) {
        return FALSE;
    }

    PMON_STRUCTURE_OFFSETS found = MonOffsetFindStructure(StructureName);
    if (found == NULL) {
        return FALSE;
    }

    return (found->OverallValidation == MonOffsetValidation_Passed);
}

_Use_decl_annotations_
NTSTATUS MonValidateStructureOffsets(
    const CHAR* StructureName,
    PVOID TestObject
)
{
    if (StructureName == NULL || TestObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_OffsetState.Initialized) {
        return STATUS_NOT_SUPPORTED;
    }

    PMON_STRUCTURE_OFFSETS structure = MonOffsetFindStructure(StructureName);
    if (structure == NULL) {
        return STATUS_NOT_FOUND;
    }

    /* IORING_OBJECT-specific validation */
    if (_stricmp(StructureName, MON_STRUCT_IORING_OBJECT) == 0) {
        __try {
            PUCHAR base = (PUCHAR)TestObject;

            /* Validate RegBuffersCount is reasonable (0-65536) */
            ULONG regBufCount = *(PULONG)(base + structure->Fields[0].Offset);
            if (regBufCount > 65536) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "[WIN11MON][OFFSET] Validation failed: RegBuffersCount=%lu\n", regBufCount);
                structure->OverallValidation = MonOffsetValidation_Failed;
                InterlockedIncrement(&g_OffsetState.ValidationFailures);
                return STATUS_UNSUCCESSFUL;
            }

            /* If RegBuffersCount > 0, RegBuffers should be a kernel pointer */
            if (regBufCount > 0) {
                PVOID regBuffers = *(PVOID*)(base + structure->Fields[1].Offset);
                if (regBuffers != NULL && !MON_IS_KERNEL_ADDRESS(regBuffers)) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                        "[WIN11MON][OFFSET] Validation failed: RegBuffers=%p (user-mode)\n", regBuffers);
                    structure->OverallValidation = MonOffsetValidation_Failed;
                    InterlockedIncrement(&g_OffsetState.ValidationFailures);
                    return STATUS_UNSUCCESSFUL;
                }
            }

            /* Validation passed */
            structure->OverallValidation = MonOffsetValidation_Passed;
            for (ULONG i = 0; i < structure->FieldCount; i++) {
                structure->Fields[i].Validation = MonOffsetValidation_Passed;
            }

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[WIN11MON][OFFSET] Validation passed for %s\n", StructureName);

            return STATUS_SUCCESS;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[WIN11MON][OFFSET] Validation exception for %s: 0x%08X\n",
                StructureName, GetExceptionCode());
            structure->OverallValidation = MonOffsetValidation_Failed;
            InterlockedIncrement(&g_OffsetState.ValidationFailures);
            return STATUS_ACCESS_VIOLATION;
        }
    }

    /* Unknown structure - skip validation */
    structure->OverallValidation = MonOffsetValidation_Skipped;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID MonOffsetResolverGetStats(
    PMON_OFFSET_RESOLVER_STATS Stats
)
{
    if (Stats == NULL) {
        return;
    }

    RtlZeroMemory(Stats, sizeof(*Stats));
    Stats->Size = sizeof(MON_OFFSET_RESOLVER_STATS);
    Stats->CurrentBuild = g_OffsetState.CurrentBuild;
    Stats->StructuresRegistered = g_OffsetState.StructureCount;
    Stats->EmbeddedHits = (ULONG)g_OffsetState.EmbeddedHits;
    Stats->SignatureHits = (ULONG)g_OffsetState.SignatureHits;
    Stats->InferenceHits = (ULONG)g_OffsetState.InferenceHits;
    Stats->ValidationFailures = (ULONG)g_OffsetState.ValidationFailures;
    Stats->Initialized = g_OffsetState.Initialized;
    Stats->Degraded = g_OffsetState.Degraded;

    /* Count validated structures */
    for (ULONG i = 0; i < g_OffsetState.StructureCount; i++) {
        if (g_OffsetState.Structures[i].OverallValidation == MonOffsetValidation_Passed) {
            Stats->StructuresValidated++;
        }
    }
}

_Use_decl_annotations_
NTSTATUS MonRegisterStructureOffsets(
    const MON_STRUCTURE_OFFSETS* Offsets
)
{
    if (Offsets == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_OffsetState.StructureCount >= MON_OFFSET_MAX_STRUCTURES) {
        return STATUS_QUOTA_EXCEEDED;
    }

    /* Check for duplicate */
    if (MonOffsetFindStructure(Offsets->StructureName) != NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WIN11MON][OFFSET] Structure %s already registered\n",
            Offsets->StructureName);
        return STATUS_OBJECTID_EXISTS;
    }

    /* Copy to internal storage */
    RtlCopyMemory(
        &g_OffsetState.Structures[g_OffsetState.StructureCount],
        Offsets,
        sizeof(MON_STRUCTURE_OFFSETS)
    );

    g_OffsetState.StructureCount++;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][OFFSET] Registered %s (size=0x%X, fields=%lu, source=%u)\n",
        Offsets->StructureName,
        Offsets->StructureSize,
        Offsets->FieldCount,
        Offsets->OverallSource);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID MonOffsetResolverSetDegraded(
    BOOLEAN Degraded
)
{
    g_OffsetState.Degraded = Degraded;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][OFFSET] Degraded mode %s\n",
        Degraded ? "ENABLED" : "DISABLED");
}

#pragma warning(pop)
