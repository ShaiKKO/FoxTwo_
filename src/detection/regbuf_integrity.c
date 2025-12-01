/*
 * RegBuffers Pointer Integrity Validation Module – Implementation
 *
 * Author: Colin MacRitchie | ziX Labs
 * Organization: ziX Labs — Security Research Division
 * File: regbuf_integrity.c
 * Version: 1.0
 * Date: 2025-11-30
 *
 * Summary
 * -------
 * Implements RegBuffers pointer integrity validation for IORING_OBJECT.
 * Detects cross-VM attacks where RegBuffers or its entries point to
 * user-mode virtual addresses.
 *
 * Security
 * --------
 * - All IORING_OBJECT access is SEH-guarded
 * - User-mode pointers detected before any dereference
 * - Values captured locally to prevent TOCTOU races
 */

#include <ntifs.h>
#include "regbuf_integrity.h"
#include "ioring_enum.h"
#include "monitor_internal.h"

#pragma warning(push)
#pragma warning(disable: 4201 4214)

/*--------------------------------------------------------------------------
 * Configuration
 *-------------------------------------------------------------------------*/
#define MON_REGBUF_DEFAULT_MAX_ENTRIES      64
#define MON_REGBUF_ABSOLUTE_MAX_COUNT       0x10000

/*--------------------------------------------------------------------------
 * Internal Helpers
 *-------------------------------------------------------------------------*/

/**
 * @function   MonRegBufInitViolationInfo
 * @purpose    Initialize violation info structure with defaults
 */
static VOID
MonRegBufInitViolationInfo(
    _Out_ PMON_REGBUF_VIOLATION_INFO Info,
    _In_ PVOID IoRingObject
)
{
    RtlZeroMemory(Info, sizeof(*Info));
    Info->Size = sizeof(MON_REGBUF_VIOLATION_INFO);
    Info->ProcessId = HandleToUlong(PsGetCurrentProcessId());
    Info->ThreadId = HandleToUlong(PsGetCurrentThreadId());
    Info->IoRingObjectAddress = (ULONG_PTR)IoRingObject;
    Info->FirstViolatingIndex = (ULONG)-1;
}

/*--------------------------------------------------------------------------
 * Public API Implementation
 *-------------------------------------------------------------------------*/

_Use_decl_annotations_
BOOLEAN MonIsRegBuffersValidationAvailable(VOID)
{
    return MonGetIoRingOffsets() != NULL;
}

_Use_decl_annotations_
ULONG
MonValidateIoRingRegBuffers(
    PVOID IoRingObject,
    PMON_REGBUF_VIOLATION_INFO ViolationInfo
)
{
    return MonValidateIoRingRegBuffersEx(
        IoRingObject,
        MON_REGBUF_DEFAULT_MAX_ENTRIES,
        ViolationInfo
    );
}

_Use_decl_annotations_
ULONG
MonValidateIoRingRegBuffersEx(
    PVOID IoRingObject,
    ULONG MaxEntriesToInspect,
    PMON_REGBUF_VIOLATION_INFO ViolationInfo
)
{
    ULONG violations = MON_REGBUF_VF_NONE;
    MON_REGBUF_VIOLATION_INFO localInfo = {0};

    /* Initialize output if provided */
    if (ViolationInfo != NULL) {
        MonRegBufInitViolationInfo(ViolationInfo, IoRingObject);
    }
    MonRegBufInitViolationInfo(&localInfo, IoRingObject);

    /* SECURITY CHECK 1: Reject NULL pointer */
    if (IoRingObject == NULL) {
        violations = MON_REGBUF_VF_NULL_OBJECT;
        localInfo.ViolationType = violations;
        goto Exit;
    }

    /* SECURITY CHECK 2: Reject user-mode addresses */
    if (!MON_IS_KERNEL_ADDRESS(IoRingObject)) {
        violations = MON_REGBUF_VF_USERMODE_PTR;
        localInfo.ViolationType = violations;
        goto Exit;
    }

    /* SECURITY CHECK 3: Verify offset table available */
    const IORING_OFFSET_TABLE* offsets = MonGetIoRingOffsets();
    if (offsets == NULL) {
        violations = MON_REGBUF_VF_OFFSETS_UNAVAIL;
        localInfo.ViolationType = violations;
        goto Exit;
    }

    /* Apply default max entries if zero */
    if (MaxEntriesToInspect == 0) {
        MaxEntriesToInspect = MON_REGBUF_DEFAULT_MAX_ENTRIES;
    }

    __try {
        /*
         * SECURITY: Capture values locally (TOCTOU protection)
         * An attacker could modify the object between our reads.
         * By capturing to local variables, we ensure consistent validation.
         */
        ULONG regBuffersCount;
        PVOID regBuffers;

        /* Read RegBuffersCount at offset 0xB0 */
        regBuffersCount = *(PULONG)((PUCHAR)IoRingObject +
                                    offsets->RegBuffersCountOffset);

        /* Read RegBuffers pointer at offset 0xB8 */
        regBuffers = *(PVOID*)((PUCHAR)IoRingObject +
                               offsets->RegBuffersOffset);

        /* Store captured values */
        localInfo.RegBuffersCount = regBuffersCount;
        localInfo.RegBuffersAddress = (ULONG_PTR)regBuffers;

        /* SECURITY CHECK 4: Validate RegBuffers pointer itself */
        if (regBuffers != NULL) {
            if (!MON_IS_KERNEL_ADDRESS(regBuffers)) {
                /*
                 * CRITICAL: RegBuffers points to user-mode memory.
                 * This is a strong indicator of exploitation attempt.
                 * The attacker has corrupted the IORING_OBJECT to point
                 * to attacker-controlled user-mode memory.
                 */
                violations |= MON_REGBUF_VF_USERMODE_PTR;
                localInfo.ViolationType = violations;

                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[WIN11MON][REGBUF] CRITICAL: RegBuffers=0x%p in user-mode! "
                    "IoRing=0x%p PID=%lu\n",
                    regBuffers, IoRingObject, localInfo.ProcessId);

                /* Don't dereference user-mode pointer - exit immediately */
                goto Exit;
            }

            /* SECURITY CHECK 5: Validate count is sane */
            if (regBuffersCount > MON_REGBUF_ABSOLUTE_MAX_COUNT) {
                violations |= MON_REGBUF_VF_COUNT_MISMATCH;
                localInfo.ViolationType |= MON_REGBUF_VF_COUNT_MISMATCH;

                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "[WIN11MON][REGBUF] Suspicious count: %lu (max=%lu)\n",
                    regBuffersCount, MON_REGBUF_ABSOLUTE_MAX_COUNT);
            }

            /* SECURITY CHECK 6: Walk array entries (bounded) */
            if (regBuffersCount > 0 && regBuffersCount <= MON_REGBUF_ABSOLUTE_MAX_COUNT) {
                ULONG entriesToCheck = min(regBuffersCount, MaxEntriesToInspect);

                for (ULONG i = 0; i < entriesToCheck; i++) {
                    /* Read entry pointer from array */
                    PVOID entry = ((PVOID*)regBuffers)[i];

                    if (entry != NULL && !MON_IS_KERNEL_ADDRESS(entry)) {
                        /*
                         * Entry in RegBuffers array points to user-mode.
                         * This indicates array content corruption.
                         */
                        violations |= MON_REGBUF_VF_ENTRY_USERMODE;
                        localInfo.ViolationType |= MON_REGBUF_VF_ENTRY_USERMODE;
                        localInfo.FirstViolatingIndex = i;
                        localInfo.ViolatingEntryAddr = (ULONG_PTR)entry;

                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                            "[WIN11MON][REGBUF] Entry[%lu]=0x%p in user-mode! "
                            "IoRing=0x%p\n",
                            i, entry, IoRingObject);

                        /* Found violation - can stop early */
                        break;
                    }
                }
            }
        }
        /* NULL RegBuffers is valid - means no buffers registered */

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* IMPORTANT: Preserve any previously detected violations */
        violations |= MON_REGBUF_VF_ACCESS_VIOLATION;
        localInfo.ViolationType |= MON_REGBUF_VF_ACCESS_VIOLATION;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WIN11MON][REGBUF] SEH in validation: 0x%08X IoRing=0x%p\n",
            GetExceptionCode(), IoRingObject);
    }

Exit:
    /* Copy local info to output if provided */
    if (ViolationInfo != NULL) {
        *ViolationInfo = localInfo;
    }

    return violations;
}

#pragma warning(pop)
