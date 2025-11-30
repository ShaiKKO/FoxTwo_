/*
 * IoRing Handle Enumeration Module – Implementation
 *
 * Author: Colin MacRitchie | ziX Labs
 * Organization: ziX Labs — Security Research Division
 * File: ioring_enum.c
 * Version: 1.0
 * Date: 2025-11-30
 *
 * Summary
 * -------
 * Implements IoRing handle enumeration using SystemHandleInformation.
 * ObRegisterCallbacks cannot be used for IoRing (only Process, Thread,
 * Desktop are supported per Microsoft documentation).
 *
 * Security
 * --------
 * - All object addresses validated before dereference
 * - SEH guards all untrusted memory access
 * - Addresses masked before external exposure
 */

#include <ntifs.h>
#include "ioring_enum.h"
#include "monitor_internal.h"
#include "offset_resolver.h"  /* E2: Dynamic offset resolution */

#pragma warning(push)
#pragma warning(disable: 4201 4214)

/*--------------------------------------------------------------------------
 * Undocumented System Information Classes
 *-------------------------------------------------------------------------*/
#ifndef SystemHandleInformation
#define SystemHandleInformation 16
#endif

#ifndef SystemExtendedHandleInformation
#define SystemExtendedHandleInformation 64
#endif

/*--------------------------------------------------------------------------
 * Handle Information Structures
 *-------------------------------------------------------------------------*/
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

#pragma warning(pop)

/*--------------------------------------------------------------------------
 * External Declarations
 *-------------------------------------------------------------------------*/
NTKERNELAPI NTSTATUS ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

/*--------------------------------------------------------------------------
 * Module Constants
 *-------------------------------------------------------------------------*/
#define MON_IORING_BUILD_TOLERANCE      100
#define MON_HANDLE_BUFFER_MARGIN        0x10000

/*
 * Windows 11 24H2 Build Number Threshold
 *
 * Starting with Windows 11 24H2 (Build 26100+), Microsoft added restrictions
 * to NtQuerySystemInformation that may affect SystemHandleInformation access.
 * The driver continues to work but may have reduced capabilities.
 *
 * Reference: https://hackyboiz.github.io/2025/04/13/l0ch/bypassing-kernel-mitigation-part0/en/
 */
#define MON_WIN11_24H2_BUILD            26100

/*--------------------------------------------------------------------------
 * Module State
 *-------------------------------------------------------------------------*/
static MON_IORING_TYPE_INFO g_IoRingTypeInfo = {0};

/* Embedded offset table for known builds */
static const IORING_OFFSET_TABLE g_IoRingOffsets[] = {
    /* Win11 22H2 (Build 22621) */
    { 22621, 0xD0, 0xB0, 0xB8, 0xC0, 0xC8 },
    /* Win11 23H2 (Build 22631) */
    { 22631, 0xD0, 0xB0, 0xB8, 0xC0, 0xC8 },
    /* Win11 24H2 (Build 26100) - preliminary */
    { 26100, 0xD0, 0xB0, 0xB8, 0xC0, 0xC8 },
    /* Sentinel */
    { 0, 0, 0, 0, 0, 0 }
};

/* Cached offset table pointer for current build */
static const IORING_OFFSET_TABLE* g_CurrentOffsets = NULL;

/*--------------------------------------------------------------------------
 * Internal Helpers
 *-------------------------------------------------------------------------*/

/**
 * @function   MonFindOffsetsForBuild
 * @purpose    Locate offset table entry for a specific build number
 *
 * Note: This function first checks if the offset_resolver (E2) has offsets
 * available, and if so, synthesizes an IORING_OFFSET_TABLE from them.
 * This allows ioring_enum.c to benefit from the expanded offset tables
 * and inference capabilities of the offset resolver while maintaining
 * backward compatibility with the existing API.
 */
static const IORING_OFFSET_TABLE*
MonFindOffsetsForBuild(_In_ ULONG BuildNumber)
{
    /* Static table to return from resolver-based lookup */
    static IORING_OFFSET_TABLE s_ResolverOffsets = {0};

    /* First, try the offset resolver (E2) if available */
    if (MonOffsetResolverIsInitialized()) {
        MON_STRUCTURE_OFFSETS ioringOffsets = {0};
        NTSTATUS status = MonGetStructureOffsets(MON_STRUCT_IORING_OBJECT, &ioringOffsets);

        if (NT_SUCCESS(status) && ioringOffsets.FieldCount >= 4) {
            /* Synthesize IORING_OFFSET_TABLE from resolver data */
            s_ResolverOffsets.BuildNumber = ioringOffsets.TargetBuild;
            s_ResolverOffsets.StructureSize = ioringOffsets.StructureSize;

            /* Find each field by name */
            for (ULONG i = 0; i < ioringOffsets.FieldCount; i++) {
                if (_stricmp(ioringOffsets.Fields[i].FieldName, MON_FIELD_REGBUFFERS_COUNT) == 0) {
                    s_ResolverOffsets.RegBuffersCountOffset = ioringOffsets.Fields[i].Offset;
                } else if (_stricmp(ioringOffsets.Fields[i].FieldName, MON_FIELD_REGBUFFERS) == 0) {
                    s_ResolverOffsets.RegBuffersOffset = ioringOffsets.Fields[i].Offset;
                } else if (_stricmp(ioringOffsets.Fields[i].FieldName, MON_FIELD_REGFILES_COUNT) == 0) {
                    s_ResolverOffsets.RegFilesCountOffset = ioringOffsets.Fields[i].Offset;
                } else if (_stricmp(ioringOffsets.Fields[i].FieldName, MON_FIELD_REGFILES) == 0) {
                    s_ResolverOffsets.RegFilesOffset = ioringOffsets.Fields[i].Offset;
                }
            }

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[WIN11MON][IORING] Using offsets from resolver (build %lu, source=%u)\n",
                ioringOffsets.TargetBuild, ioringOffsets.OverallSource);

            return &s_ResolverOffsets;
        }
    }

    /* Fallback to embedded table lookup */
    for (ULONG i = 0; g_IoRingOffsets[i].BuildNumber != 0; i++) {
        if (g_IoRingOffsets[i].BuildNumber == BuildNumber) {
            return &g_IoRingOffsets[i];
        }
    }

    /* Fallback: find nearest known build within tolerance */
    for (ULONG i = 0; g_IoRingOffsets[i].BuildNumber != 0; i++) {
        LONG delta = (LONG)BuildNumber - (LONG)g_IoRingOffsets[i].BuildNumber;
        if (delta >= -MON_IORING_BUILD_TOLERANCE &&
            delta <= MON_IORING_BUILD_TOLERANCE) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[WIN11MON][IORING] Using offsets from build %lu for build %lu\n",
                g_IoRingOffsets[i].BuildNumber, BuildNumber);
            return &g_IoRingOffsets[i];
        }
    }

    return NULL;
}

/*--------------------------------------------------------------------------
 * Public API Implementation
 *-------------------------------------------------------------------------*/

_Use_decl_annotations_
ULONG MonDetectWindowsBuild(VOID)
{
    RTL_OSVERSIONINFOW versionInfo = {0};
    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);

    NTSTATUS status = RtlGetVersion(&versionInfo);
    if (!NT_SUCCESS(status)) {
        return 0;
    }

    return versionInfo.dwBuildNumber;
}

_Use_decl_annotations_
NTSTATUS MonIoRingEnumInitialize(VOID)
{
    RtlZeroMemory(&g_IoRingTypeInfo, sizeof(g_IoRingTypeInfo));

    /* Detect Windows build */
    ULONG buildNumber = MonDetectWindowsBuild();
    if (buildNumber == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WIN11MON][IORING] Failed to detect Windows build\n");
        return STATUS_NOT_SUPPORTED;
    }

    g_IoRingTypeInfo.WindowsBuild = buildNumber;

    /*
     * Windows 11 24H2 Compatibility Warning
     *
     * Microsoft added restrictions to NtQuerySystemInformation in 24H2 that
     * suppress kernel base addresses unless the caller has SeDebugPrivilege.
     * This affects SystemModuleInformation and may impact handle enumeration.
     *
     * The driver continues to function but capabilities may be reduced:
     * - Handle enumeration may fail or return incomplete results
     * - Object addresses may be zeroed or restricted
     *
     * Reference: https://hackyboiz.github.io/2025/04/13/l0ch/bypassing-kernel-mitigation-part0/en/
     */
    if (buildNumber >= MON_WIN11_24H2_BUILD) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WIN11MON][IORING] Windows 11 24H2+ (build %lu) detected - "
            "NtQuerySystemInformation restrictions may apply. "
            "Handle enumeration capabilities may be reduced.\n",
            buildNumber);
    }

    /* Locate offset table for this build */
    g_CurrentOffsets = MonFindOffsetsForBuild(buildNumber);
    if (g_CurrentOffsets == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WIN11MON][IORING] No offset table for build %lu; degraded mode\n",
            buildNumber);
        /* Continue in degraded mode - A2 will be disabled */
    } else {
        g_IoRingTypeInfo.ObjectBodySize = (USHORT)g_CurrentOffsets->StructureSize;
    }

    /*
     * IoRing type index discovery:
     * The type index is XOR'd with a per-boot cookie in Win10+.
     * We discover it opportunistically during first enumeration by
     * probing candidate objects with our RegBuffers validation.
     *
     * TypeIndex remains 0 until first successful discovery.
     */

    /* Memory barrier ensures all fields are visible before Initialized flag */
    MonWriteBooleanRelease(&g_IoRingTypeInfo.Initialized, TRUE);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][IORING] Initialized for build %lu (offsets=%s, 24H2+=%s)\n",
        buildNumber,
        g_CurrentOffsets ? "embedded" : "unavailable",
        buildNumber >= MON_WIN11_24H2_BUILD ? "YES" : "NO");

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID MonIoRingEnumShutdown(VOID)
{
    g_IoRingTypeInfo.Initialized = FALSE;
    g_CurrentOffsets = NULL;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][IORING] Shutdown complete\n");
}

_Use_decl_annotations_
const IORING_OFFSET_TABLE* MonGetIoRingOffsets(VOID)
{
    return g_CurrentOffsets;
}

_Use_decl_annotations_
const MON_IORING_TYPE_INFO* MonGetIoRingTypeInfo(VOID)
{
    return &g_IoRingTypeInfo;
}

_Use_decl_annotations_
NTSTATUS
MonEnumerateIoRingObjects(
    PMON_IORING_CALLBACK Callback,
    PVOID Context
)
{
    if (Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!MonReadBooleanAcquire(&g_IoRingTypeInfo.Initialized)) {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG bufferSize = 0;
    ULONG newBufferSize = 0;
    PSYSTEM_HANDLE_INFORMATION_EX handleInfo = NULL;

    /* Query required buffer size */
    status = ZwQuerySystemInformation(
        SystemExtendedHandleInformation,
        NULL,
        0,
        &bufferSize
    );

    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return status;
    }

    /* Add margin for handles created during allocation (with overflow check) */
    if (!MON_SAFE_ADD_ULONG(bufferSize, MON_HANDLE_BUFFER_MARGIN, &newBufferSize)) {
        return STATUS_INTEGER_OVERFLOW;
    }
    bufferSize = newBufferSize;

    /* Allocate from paged pool (PASSIVE_LEVEL only) */
    handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)MonAllocatePoolPaged(
        bufferSize,
        MON_POOL_TAG
    );

    if (handleInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQuerySystemInformation(
        SystemExtendedHandleInformation,
        handleInfo,
        bufferSize,
        &bufferSize
    );

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(handleInfo, MON_POOL_TAG);
        return status;
    }

    /*
     * Enumerate handles looking for IoRing objects.
     *
     * Since we cannot reliably discover IoRing type index without existing
     * handles (the type index is XOR'd with a per-boot cookie), we use a
     * heuristic approach: validate each candidate using RegBuffers validation.
     *
     * If offsets are available and validation succeeds without exception,
     * we consider it a potential IoRing object.
     */
    for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; i++) {
        PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry = &handleInfo->Handles[i];

        /* Skip NULL objects */
        if (entry->Object == NULL) {
            continue;
        }

        /* SECURITY: Reject user-mode addresses */
        if (!MON_IS_KERNEL_ADDRESS(entry->Object)) {
            continue;
        }

        /*
         * If we have a known type index, use it for fast filtering.
         * Otherwise, use heuristic validation via RegBuffers check.
         */
        BOOLEAN isIoRingCandidate = FALSE;

        if (g_IoRingTypeInfo.TypeIndex != 0) {
            /* Fast path: type index known */
            isIoRingCandidate = (entry->ObjectTypeIndex == g_IoRingTypeInfo.TypeIndex);
        } else if (g_CurrentOffsets != NULL) {
            /*
             * Slow path: validate via structure probe.
             * This is safe because MonValidateIoRingRegBuffers uses SEH.
             * If validation succeeds (no exception, returns 0 or specific flags),
             * this is likely an IoRing object.
             */
            ULONG violations = MonValidateIoRingRegBuffers(entry->Object, NULL);

            /*
             * Consider it an IoRing candidate if:
             * - No access violation (object is readable)
             * - Not flagged as offsets unavailable (would indicate wrong object)
             * Only proceed if we got a clean read or a legitimate violation.
             */
            if (!(violations & (MON_REGBUF_VF_ACCESS_VIOLATION |
                                MON_REGBUF_VF_OFFSETS_UNAVAIL))) {
                isIoRingCandidate = TRUE;

                /* Opportunistically record type index for future fast-path */
                if (g_IoRingTypeInfo.TypeIndex == 0) {
                    g_IoRingTypeInfo.TypeIndex = (UCHAR)entry->ObjectTypeIndex;
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                        "[WIN11MON][IORING] Discovered type index: %u\n",
                        g_IoRingTypeInfo.TypeIndex);
                }
            }
        }

        if (isIoRingCandidate) {
            BOOLEAN continueEnum = Callback(
                (ULONG)entry->UniqueProcessId,
                (HANDLE)entry->HandleValue,
                entry->Object,
                entry->GrantedAccess,
                Context
            );

            if (!continueEnum) {
                break;
            }
        }
    }

    ExFreePoolWithTag(handleInfo, MON_POOL_TAG);
    return STATUS_SUCCESS;
}
