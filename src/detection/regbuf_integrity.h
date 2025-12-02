/*
 * RegBuffers Pointer Integrity Validation Module
 *
 * Author: Colin MacRitchie | ziX Labs
 * Organization: ziX Labs — Security Research Division
 * File: regbuf_integrity.h
 * Version: 1.0
 * Date: 2025-11-30
 *
 * Summary
 * -------
 * Validates IORING_OBJECT RegBuffers pointer integrity to detect
 * exploitation attempts where attackers corrupt RegBuffers to point
 * to user-mode addresses (cross-VM attack pattern).
 *
 * SECURITY PROPERTIES:
 * - Input: All IORING_OBJECT pointers treated as hostile
 * - Output: Violation flags indicate corruption type
 * - Memory Safety: SEH guards all dereferences
 * - IRQL: Most functions work at DISPATCH_LEVEL
 *
 * References:
 * - "One I/O Ring to Rule Them All" - Yarden Shafir
 * - Vergilius Project: _IORING_OBJECT structure
 */

#ifndef _ZIX_LABS_REGBUF_INTEGRITY_H_
#define _ZIX_LABS_REGBUF_INTEGRITY_H_

#ifndef _KERNEL_MODE
#error "This header is for kernel-mode only."
#endif

#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------
 * Violation Flags
 *
 * Returned by MonValidateIoRingRegBuffers to indicate corruption type.
 *-------------------------------------------------------------------------*/
#define MON_REGBUF_VF_NONE 0x00000000
#define MON_REGBUF_VF_USERMODE_PTR                                                \
  0x00000001                                      /* RegBuffers points to user VA \
                                                   */
#define MON_REGBUF_VF_COUNT_MISMATCH   0x00000002 /* Count inconsistent */
#define MON_REGBUF_VF_ENTRY_USERMODE   0x00000004 /* Entry in array points to user VA */
#define MON_REGBUF_VF_ACCESS_VIOLATION 0x00000008 /* SEH caught exception */
#define MON_REGBUF_VF_INVALID_STRUCTURE                                     \
  0x00000010                                     /* Structure size mismatch \
                                                  */
#define MON_REGBUF_VF_NULL_OBJECT     0x00000020 /* NULL object pointer */
#define MON_REGBUF_VF_OFFSETS_UNAVAIL 0x00000040 /* Offset table not available */

/*--------------------------------------------------------------------------
 * Violation Info Structure
 *-------------------------------------------------------------------------*/
typedef struct _MON_REGBUF_VIOLATION_INFO {
  ULONG Size;          /* sizeof(MON_REGBUF_VIOLATION_INFO) */
  ULONG ViolationType; /* MON_REGBUF_VF_* flags */
  ULONG ProcessId;
  ULONG ThreadId;
  ULONG_PTR IoRingObjectAddress;
  ULONG_PTR RegBuffersAddress;  /* Captured RegBuffers pointer */
  ULONG RegBuffersCount;        /* Captured count */
  ULONG FirstViolatingIndex;    /* Index of first bad entry (-1 if N/A) */
  ULONG_PTR ViolatingEntryAddr; /* Address of violating entry */
} MON_REGBUF_VIOLATION_INFO, *PMON_REGBUF_VIOLATION_INFO;

/*--------------------------------------------------------------------------
 * Public Function Prototypes
 *-------------------------------------------------------------------------*/

/**
 * @function   MonValidateIoRingRegBuffers
 * @purpose    Validate RegBuffers pointer integrity for a single IORING_OBJECT
 * @precondition IRQL <= DISPATCH_LEVEL; IoRingObject is kernel address
 * (untrusted)
 * @postcondition Returns violation code; does not modify object
 *
 * SECURITY REQUIREMENTS:
 * 1. Validate IoRingObject is in kernel address space BEFORE any access
 * 2. Wrap ALL dereferences in __try/__except
 * 3. Capture values locally - never trust re-reads (TOCTOU protection)
 * 4. Mask addresses before returning to caller
 *
 * @param[in]  IoRingObject - Kernel address of IORING_OBJECT (untrusted)
 * @param[out] ViolationInfo - Output violation details (optional)
 * @returns    0 if valid, MON_REGBUF_VF_* flags if violations detected
 *
 * @thread-safety Re-entrant; SEH-guarded; no global state modified
 * @side-effects None (read-only validation)
 */
_IRQL_requires_max_(DISPATCH_LEVEL) ULONG
    MonValidateIoRingRegBuffers(_In_ PVOID IoRingObject,
                                _Out_opt_ PMON_REGBUF_VIOLATION_INFO ViolationInfo);

/**
 * @function   MonValidateIoRingRegBuffersEx
 * @purpose    Extended validation with configurable inspection depth
 * @precondition IRQL <= DISPATCH_LEVEL
 * @postcondition Returns violation code
 *
 * @param[in]  IoRingObject - Kernel address of IORING_OBJECT
 * @param[in]  MaxEntriesToInspect - Maximum array entries to check (0 = default
 * 64)
 * @param[out] ViolationInfo - Output violation details (optional)
 * @returns    0 if valid, MON_REGBUF_VF_* flags if violations detected
 */
_IRQL_requires_max_(DISPATCH_LEVEL) ULONG
    MonValidateIoRingRegBuffersEx(_In_ PVOID IoRingObject, _In_ ULONG MaxEntriesToInspect,
                                  _Out_opt_ PMON_REGBUF_VIOLATION_INFO ViolationInfo);

/**
 * @function   MonIsRegBuffersValidationAvailable
 * @purpose    Check if RegBuffers validation is available for current build
 * @precondition IRQL <= DISPATCH_LEVEL
 * @postcondition Returns TRUE if offset table is available
 * @returns    TRUE if validation can be performed, FALSE if degraded mode
 */
_IRQL_requires_max_(DISPATCH_LEVEL) BOOLEAN MonIsRegBuffersValidationAvailable(VOID);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _ZIX_LABS_REGBUF_INTEGRITY_H_ */
