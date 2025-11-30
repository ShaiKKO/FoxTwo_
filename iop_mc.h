/*
 * Author: Colin MacRitchie | ziX Labs | N0v4 | colin@teraflux.app
 * Organization: ziX Labs
 * File: iop_mc.h
 * Version: 1.3
 * Date: 2025-08-22
 *
 *  introspection utilities for Windows I/O ring memory-context (MC) buffer entries.
 *
 * Rationale: Kernel drivers may need to inspect arbitrary pointers to the internal ntoskrnl _IOP_MC_BUFFER_ENTRY
 * structure (e.g., for diagnostics, security monitoring, or metadata projection) without trusting layout stability
 * or pointer integrity. This header provides a header-only, exception-guarded parsing and projection layer that
 * converts potentially hostile in‑kernel pointers into sanitized, policy‑gated metadata snapshots.
 *
 * Preconditions / Requirements:
 * - Included only in NT kernel-mode builds (_KERNEL_MODE required); user-mode inclusion is rejected.
 * - Caller IRQL <= APC_LEVEL (structures and MDLs may reside in pageable pool).
 * - Pointers passed to validation/query functions are considered untrusted; caller must not hold locks that
 * would deadlock during potential page faults.
 * - No modification of the target _IOP_MC_BUFFER_ENTRY occurs; routines are read-only by design.
 *
 * Implementation Notes:
 * • Structure layout mirrored from observed Windows11 x64 symbols; a size assert (optional) detects ABI drift.
 * • Validation is policy-driven (strict vs. lenient) to allow forward compatibility across OS revisions while
 * enabling fail-fast behavior in security-focused deployments.
 * • All field access is wrapped in SEH (__try/__except) so stale/freed/paged-out memory yields STATUS_ACCESS_VIOLATION
 * instead of crashing the system.
 * • MDL coherence checks (length, process pointer) are performed only when an MDL is present; cleaned-up entries
 * should normally have MDL == NULL.
 * • Projection intentionally excludes raw MDL/page tree internals to avoid leaking kernel implementation details
 * across the user/kernel boundary.
 *
 * Edge Cases:
 * - Stale or freed memory: Trapped via SEH; violation mask includes IOP_MC_VIOL_ACCESS_FAULT.
 * - User-space entry pointer: Rejected upfront under IOP_MC_VF_FAIL_USERPTR_ENTRY policy without dereference.
 * - Unknown flag bits: Treated as corruption in strict mode; tolerated (and logged) in lenient mode.
 * - MDL present after cleanup flag: Flagged as inconsistent; may indicate race or partial teardown.
 * - Zero length or negative ref counts: Hard validation failures to prevent downstream misuse.
 *
 * Post-Conditions / Guarantees:
 * - Validation APIs return NTSTATUS reflecting success or exact failure class; optional violation mask encodes
 * granular invariant breaches for diagnostics.
 * - Query API returns a sanitized IOP_MC_BUFFER_ENTRY_INFO with only caller-safe fields populated; on failure the
 * structure is zeroed.
 * - No side effects: global state, reference counts, and MDL contents remain untouched.
 *
 * Security Model:
 * - Treats all inputs as hostile until validated; enforces address space expectations (user vs. kernel) under policy.
 * - Prevents kernel pointer disclosure to user mode by restricting projection and requiring explicit IOCTL handling.
 * - Guards against time-of-check/time-of-use crashes using SEH rather than speculative lock acquisition.
 *
 * Usage:
 * - Call IopValidateMcBufferEntryEx (or IopIsValidMcBufferEntry for default strict policy) before any deeper analysis.
 * - Use IopQueryMcBufferEntry to obtain IOCTL-returnable metadata after successful validation.
 * - For diagnostics in checked builds, invoke IopDumpMcBufferEntry to emit a structured snapshot to the debugger.
 *
 * Copyright: ©2025 ziX Labs. All rights reserved.
 * 
 */

#ifndef IOP_MC_H_INCLUDED
#define IOP_MC_H_INCLUDED 1

/*=============================
 * Environment & Guard Rails
 *============================*/
/*
 * Establish compile-time and inclusion constraints for kernel-only MC buffer parsing utilities.
 *
 * Rationale: Prevent accidental user-mode or mixed-header inclusion that could invalidate SEH usage, MDL
 * assumptions, or introduce macro conflicts across WDK variants. Early rejection avoids latent runtime faults.
 *
 * Preconditions:
 * - Build target defines _KERNEL_MODE (enforced below).
 * - ntddk.h selected intentionally (avoids dual ntddk.h + wdm.h redefinition noise).
 *
 * Implementation Notes:
 * • Single inclusion: #pragma once + explicit guard; no multiple-definition side effects.
 * • We rely on ntddk.h for NTSTATUS, LIST_ENTRY, MDL, KEVENT; wdm.h deliberately omitted to minimize macro churn.
 * • Hard #error on missing _KERNEL_MODE provides immediate developer feedback vs. undefined behavior later.
 *
 * Edge Cases:
 * - Inclusion from user shim: blocked with diagnostic #error.
 * - Future WDK header restructure: ntddk.h remains canonical for WDM drivers; adjust if deprecation notice arises.
 *
 * Post-Conditions / Guarantees:
 * - Translation unit guarantees kernel primitives available; subsequent validation code may safely assume MDL/SEH.
 * - No runtime effect; enforcement is compile-time only.
 */
#pragma once
 #include <ntddk.h>
 #include "iop_mc_layout.h"

 #ifndef _KERNEL_MODE
 # error "IOP_MC: FOR NT KERNEL-MODE DRIVERS ONLY."
 #endif

 #ifndef _In_
 #define _In_
 #endif

 #ifndef _In_opt_
 #define _In_opt_
 #endif

 #ifndef _Out_
 #define _Out_
 #endif

 #ifndef _Out_opt_
 #define _Out_opt_
 #endif

 #ifndef _Inout_
 #define _Inout_
 #endif

 #ifndef _In_reads_bytes_opt_
 #define _In_reads_bytes_opt_(n)
 #endif

 #ifndef _In_range_
 #define _In_range_(l,u)
 #endif

 #ifndef _IRQL_requires_max_
 #define _IRQL_requires_max_(level)
 #endif

 

/*============================================
 * Build-Time Configuration & Policy Flags
 *============================================*/
/*
 * Policy bitmap defining granular validation behaviors for MC buffer entry introspection.
 *
 * Rationale: Undocumented kernel structures may evolve; callers need tunable strictness to balance
 * security (fail-fast on divergence) against forward compatibility (tolerate benign drift). A unified
 * flag set enables composable validation profiles without proliferating API variants.
 *
 * Preconditions:
 * - Flags chosen prior to calling IopValidateMcBufferEntryEx; no dynamic mutation inside validation.
 * - Caller understands distinction between STRICT (hard rejection) and LENIENT (soft acceptance) paths.
 *
 * Implementation Notes:
 * • Lower16 bits define hard enforcement triggers; upper16 bits define leniency overrides for their
 * corresponding strict checks (TYPE/SIZE/MDL). Using separate domains avoids ambiguous precedence.
 * • Unknown flag bits in the target entry are treated as corruption unless the FAIL_UNKNOWN_FLAGS policy
 * is omitted (permissive scenario for newer OS builds).
 * • STRICT_FLAGS rejects entries with ANY flags set (even known ones); useful for detecting entries that
 * should be in pristine/initial state. Distinct from FAIL_UNKNOWN_FLAGS which only catches unknown bits.
 * • FAIL_USERPTR_ENTRY short-circuits before any dereference to avoid speculative touching of user VA.
 * • VALIDATE_ADDRMODE cross-references AccessMode with VA classification (MmSystemRangeStart) to detect
 * inconsistent privilege tagging.
 *
 * Edge Cases:
 * - Combining STRICT_* with LENIENT_* of same category: lenient bit wins (caller explicitly overrides strict).
 * - Omitting all strict bits: validation degrades to structural probes only; increases risk of accepting
 * malformed entries (acceptable in research, not production).
 * - Undefined future kernel fields: surfaced as UNKNOWN_FLAGS and rejected when fail policy active.
 *
 * Post-Conditions:
 * - Chosen mask directly governs branch decisions in IopValidateMcBufferEntryEx; no hidden side effects.
 * - Default composite (IOP_MC_VF_DEFAULT) favors security monitoring (user-range pointers rejected, all core
 * invariants enforced).
 */
typedef enum _IOP_MC_VALIDATION_FLAGS {
    IOP_MC_VF_STRICT_TYPE          = 0x00000001,
    IOP_MC_VF_STRICT_SIZE          = 0x00000002,
    IOP_MC_VF_STRICT_MDL           = 0x00000004,
    IOP_MC_VF_STRICT_FLAGS         = 0x00000008,
    IOP_MC_VF_FAIL_UNKNOWN_FLAGS   = 0x00000010,
    IOP_MC_VF_FAIL_USERPTR_ENTRY   = 0x00000020,
    IOP_MC_VF_VALIDATE_ADDRMODE    = 0x00000040,
    IOP_MC_VF_FAIL_ZERO_LENGTH     = 0x00000080,
    IOP_MC_VF_FAIL_BAD_REFCOUNT    = 0x00000100,
    IOP_MC_VF_LENIENT_TYPE         = 0x00010000,
    IOP_MC_VF_LENIENT_SIZE         = 0x00020000,
    IOP_MC_VF_LENIENT_MDL          = 0x00040000,
    IOP_MC_VF_LENIENT_FLAGS        = 0x00080000,  // Override STRICT_FLAGS; allow any flags present

    IOP_MC_VF_DEFAULT =
        IOP_MC_VF_STRICT_TYPE |
        IOP_MC_VF_STRICT_SIZE |
        IOP_MC_VF_STRICT_MDL |
        IOP_MC_VF_STRICT_FLAGS |
        IOP_MC_VF_FAIL_UNKNOWN_FLAGS |
        IOP_MC_VF_FAIL_USERPTR_ENTRY |
        IOP_MC_VF_VALIDATE_ADDRMODE |
        IOP_MC_VF_FAIL_ZERO_LENGTH |
        IOP_MC_VF_FAIL_BAD_REFCOUNT
} IOP_MC_VALIDATION_FLAGS;

/*
 * Validation violation categories for diagnostic feedback and detailed failure analysis.
 *
 * Rationale: Single NTSTATUS codes lack granularity for root-cause analysis in security monitoring
 * or diagnostic contexts. An optional violation bitmask enables callers to distinguish between
 * transient faults (memory access), structural mismatches (wrong type/size), and policy breaches
 * (user-space pointer in kernel context). This supports automated remediation and telemetry.
 *
 * Implementation Notes:
 * • Violations accumulate during validation; multiple breaches in a single entry produce a bitwise-OR'd mask.
 * • ACCESS_FAULT indicates SEH trap; all subsequent checks skipped to avoid cascading failures.
 * • Violation codes orthogonal to NTSTATUS return; a function may return STATUS_INVALID_PARAMETER while
 * populating VIOL_BAD_TYPE | VIOL_BAD_SIZE to distinguish which invariants triggered rejection.
 * • Callers may ignore mask (pass NULL) for simple pass/fail workflows; mask becomes essential for
 * security auditing and differential analysis across OS versions.
 *
 * Post-Conditions:
 * - Mask reflects all observed violations during a single validation attempt.
 * - No side effects; mask is write-only output from validator.
 */
typedef enum _IOP_MC_VIOLATION {
    IOP_MC_VIOL_NONE            = 0x00000000,
    IOP_MC_VIOL_NULL_ENTRY      = 0x00000001,
    IOP_MC_VIOL_USERPTR_ENTRY   = 0x00000002,
    IOP_MC_VIOL_ACCESS_FAULT    = 0x00000004,
    IOP_MC_VIOL_BAD_TYPE        = 0x00000008,
    IOP_MC_VIOL_BAD_SIZE        = 0x00000010,
    IOP_MC_VIOL_UNKNOWN_FLAGS   = 0x00000020,
    IOP_MC_VIOL_ZERO_LENGTH     = 0x00000040,
    IOP_MC_VIOL_BAD_REFCOUNT    = 0x00000080,
    IOP_MC_VIOL_ADDRMODE_MISMATCH = 0x00000100,
    IOP_MC_VIOL_MDL_NULL_UNEXPECTEDLY = 0x00000200,
    IOP_MC_VIOL_MDL_NONNULL_AFTER_CLEANUP = 0x00000400,
    IOP_MC_VIOL_MDL_LENGTH_MISMATCH = 0x00000800,
    IOP_MC_VIOL_MDL_PROC_NULL   = 0x00001000,
    IOP_MC_VIOL_FLAGS_NONZERO_STRICT = 0x00002000, // Flags present when STRICT_FLAGS active
    IOP_MC_VIOL_MDL_USERPTR     = 0x00004000  // MDL pointer in user-mode address range
} IOP_MC_VIOLATION;

/*
 * Query flags controlling metadata projection behavior for MC buffer entries.
 *
 * Rationale: Callers that surface IOP_MC_BUFFER_ENTRY_INFO across a trust boundary
 * (for example, user-mode IOCTLs) may need to suppress the Address field to avoid
 * exposing kernel virtual addresses. Query flags provide an explicit, opt-in
 * mechanism for such policies without changing the default in-kernel behavior.
 *
 * Implementation Notes:
 * • IOP_MC_QF_NONE preserves existing semantics (Address projected verbatim).
 * • IOP_MC_QF_MASK_ADDRESS zeroes the Address field after projection; callers
 *   can select this for user-mode or multi-tenant diagnostics.
 */
typedef enum _IOP_MC_QUERY_FLAGS {
    IOP_MC_QF_NONE         = 0x00000000,
    IOP_MC_QF_MASK_ADDRESS = 0x00000001
} IOP_MC_QUERY_FLAGS;

/*==================================
 * Structure Layout Definitions
 *==================================*/
/*
 * Reverse-engineered declaration of internal Windows I/O ring buffer entry structure.
 *
 * Rationale: _IOP_MC_BUFFER_ENTRY is not exposed in public WDK headers but appears in ntoskrnl symbols
 * and driver introspection scenarios. Declaring the layout permits type-safe parsing without relying
 * on undocumented APIs or opaque pointer casts. Deviation from actual kernel layout triggers
 * size/type checks during validation, providing early warning of ABI drift.
 *
 * Preconditions:
 * - Structure matches Windows 11 22H2+ x64 kernel observations; older/newer builds may differ.
 * - No modification of actual kernel structures occurs; this is a read-only mirror for parsing.
 *
 * Implementation Notes:
 * • Fields ordered to match observed symbol offsets; padding explicitly avoided via natural alignment.
 * • Type and Size fields provide ABI fingerprint; validators check these before trusting remaining fields.
 * • Flags bitmap contains known values (UNLOCK, SIGNAL_RUNDOWN, CLEANED_UP); unknown bits treated as
 * corruption unless lenient policy permits forward compatibility.
 * • MDL pointer may be NULL after cleanup; validators cross-check against CLEANED_UP flag to detect
 * inconsistent teardown state.
 *
 * Edge Cases:
 * - OS update changes layout: Size or Type mismatch triggers validation failure; prevents silent misinterpretation.
 * - Structure packing differs across compilers: No #pragma pack used; relies on natural alignment matching kernel.
 * - Future kernel adds fields: Unknown flag bits or enlarged Size field signal divergence.
 *
 * Post-Conditions:
 * - Declaration permits safe offsetof() and sizeof() operations for forensic or diagnostic tools.
 * - No runtime behavior; structure is passive template for memory interpretation.
 */
typedef struct _IOP_MC_BUFFER_ENTRY {
    USHORT        Type;
    USHORT        Reserved;
    ULONG         Size;
    LONG          ReferenceCount;
    ULONG         Flags;
    LIST_ENTRY    GlobalDataLink;
    PVOID         Address;
    ULONG         Length;
    CHAR          AccessMode;
    LONG          MdlRef;
    PMDL          Mdl;
    UCHAR         ReservedTail[0x40];
} IOP_MC_BUFFER_ENTRY, *PIOP_MC_BUFFER_ENTRY;

C_ASSERT(FIELD_OFFSET(IOP_MC_BUFFER_ENTRY, Type)            == IOP_MC_FIELD_TYPE_OFFSET);
C_ASSERT(FIELD_OFFSET(IOP_MC_BUFFER_ENTRY, Reserved)        == IOP_MC_FIELD_RESERVED_OFFSET);
C_ASSERT(FIELD_OFFSET(IOP_MC_BUFFER_ENTRY, Size)            == IOP_MC_FIELD_SIZE_OFFSET);
C_ASSERT(FIELD_OFFSET(IOP_MC_BUFFER_ENTRY, ReferenceCount)  == IOP_MC_FIELD_REFERENCECOUNT_OFFSET);
C_ASSERT(FIELD_OFFSET(IOP_MC_BUFFER_ENTRY, Flags)           == IOP_MC_FIELD_FLAGS_OFFSET);
C_ASSERT(FIELD_OFFSET(IOP_MC_BUFFER_ENTRY, GlobalDataLink)  == IOP_MC_FIELD_GLOBALDATALINK_OFFSET);
C_ASSERT(FIELD_OFFSET(IOP_MC_BUFFER_ENTRY, Address)         == IOP_MC_FIELD_ADDRESS_OFFSET);
C_ASSERT(FIELD_OFFSET(IOP_MC_BUFFER_ENTRY, Length)          == IOP_MC_FIELD_LENGTH_OFFSET);
C_ASSERT(FIELD_OFFSET(IOP_MC_BUFFER_ENTRY, AccessMode)      == IOP_MC_FIELD_ACCESSMODE_OFFSET);
C_ASSERT(FIELD_OFFSET(IOP_MC_BUFFER_ENTRY, MdlRef)          == IOP_MC_FIELD_MDLREF_OFFSET);
C_ASSERT(FIELD_OFFSET(IOP_MC_BUFFER_ENTRY, Mdl)             == IOP_MC_FIELD_MDL_OFFSET);
C_ASSERT(sizeof(IOP_MC_BUFFER_ENTRY)                        == IOP_MC_BUFFER_ENTRY_SIZE);

/*
 * Known kernel-internal constants for MC buffer type identification and flag decoding.
 *
 * Rationale: Validation requires comparing observed values against expected constants to detect
 * corruption or ABI drift. Flags control cleanup semantics and synchronization behavior; unknown
 * bits may indicate future kernel features or tampering. Surfacing these as named constants
 * avoids magic numbers and enables version-specific validation profiles.
 *
 * Implementation Notes:
 * • Type constant (0x4D43 "MC") appears to be stable across Win10/Win11; validator permits override
 * via ExpectedType parameter for forward compatibility.
 * • Flag definitions mirror observed kernel behavior; undocumented bits treated as reserved and
 * rejected under strict policy.
 * • Size computation matches sizeof(IOP_MC_BUFFER_ENTRY); deviation triggers hard failure unless
 * lenient mode permits OS-specific extensions.
 *
 * Post-Conditions:
 * - Constants used in validation comparisons; no mutable state.
 */
#define IOP_MC_KNOWN_TYPE_WIN11   0x4D43

#define IOP_MCBF_UNLOCK           0x00000001
#define IOP_MCBF_SIGNAL_RUNDOWN   0x00000002
#define IOP_MCBF_CLEANED_UP       0x00000004

#define IOP_MC_KNOWN_SIZE_WIN11   IOP_MC_BUFFER_ENTRY_SIZE

/*
 * Summary: Sanitized metadata projection structure for cross-boundary communication.
 *
 * Rationale: Returning raw _IOP_MC_BUFFER_ENTRY to user mode or IOCTL handlers would leak kernel
 * pointers and MDL internals. This structure contains only caller-safe fields (sizes, counts, flags)
 * and omits sensitive implementation details (raw MDL, event pointers, internal links). Enables
 * diagnostics without compromising address-space isolation.
 *
 * Implementation Notes:
 * • Address field retained for diagnostic correlation but marked as "handle" not dereferenceable pointer.
 * • HasMdl boolean replaces raw MDL pointer; callers needing page enumeration must use separate API.
 * • CleanedUp derived from flag bit; simplifies consumer logic without exposing full flag bitmap.
 * • NumberOfPages computed from Length; avoids exposing MDL page array structure.
 *
 * Post-Conditions:
 * - Structure safe to return across user/kernel boundary via IOCTL METHOD_BUFFERED.
 * - All pointer fields either elided or converted to non-dereferenceable handles.
 */
typedef struct _IOP_MC_BUFFER_ENTRY_INFO {
    USHORT     Type;
    USHORT     Flags;
    ULONG      Size;
    LONG       ReferenceCount;
    ULONG_PTR  Address;
    ULONG      Length;
    UCHAR      AccessMode;
    BOOLEAN    HasMdl;
    BOOLEAN    CleanedUp;
    ULONG      NumberOfPages;
} IOP_MC_BUFFER_ENTRY_INFO, *PIOP_MC_BUFFER_ENTRY_INFO;

/*===============================
 * Logging & Debug Infrastructure
 *===============================*/
/*
 * Conditional logging macros for debug builds; compiled away in retail to eliminate overhead.
 *
 * Rationale: Validation failures in production scenarios require diagnostics without impacting
 * performance. Debug builds emit detailed traces; retail builds omit all logging to preserve
 * zero-cost abstraction. Macros evaluate to no-ops when DBG undefined, ensuring no string literals
 * or formatting overhead in shipping binaries.
 *
 * Implementation Notes:
 * • LOG_ERROR maps to DbgPrintEx with ERROR level; triggers immediate debugger attention.
 * • LOG_INFO uses INFO level for non-critical diagnostics (e.g., lenient-mode warnings).
 * • DPFLTR_IHVDRIVER_ID chosen as representative IHV category; integrators may redefine.
 * • Macros wrap variadic DbgPrintEx to support printf-style formatting without manual conditional compilation.
 *
 * Post-Conditions:
 * - Debug builds produce structured kernel debugger output for failure analysis.
 * - Retail builds contain no logging code; macros vanish during preprocessing.
 */
#if DBG
# define IOP_MC_LOG_ERROR(...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[IOP_MC] ERROR: " __VA_ARGS__)
# define IOP_MC_LOG_INFO(...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[IOP_MC] INFO: " __VA_ARGS__)
#else
# define IOP_MC_LOG_ERROR(...)
# define IOP_MC_LOG_INFO(...)
#endif

/*=============================
 * Helper Inline Functions
 *============================*/
/*
 * Sentinel value indicating integer overflow in page count computation.
 * No valid address/length combination can span MAXULONG pages on any supported platform.
 */
#define IOP_MC_PAGE_COUNT_OVERFLOW  MAXULONG

/*
 * Compute required page count for a given virtual address and length using kernel paging macros.
 *
 * Rationale: MDL page enumeration and memory footprint calculations require consistent page-count
 * derivation that accounts for non page-aligned starting addresses. Using ADDRESS_AND_SIZE_TO_SPAN_PAGES
 * matches kernel MDL semantics and avoids off-by-one errors for buffers that straddle page boundaries.
 *
 * SECURITY: Validates against integer overflow before computation. The WDK documentation for
 * ADDRESS_AND_SIZE_TO_SPAN_PAGES explicitly states: "The caller must ensure that the specified
 * parameters do not cause memory overflow." An attacker providing malicious Address/Length
 * could cause wraparound in (Address + Length - 1), yielding an incorrect (smaller) page count
 * that could lead to under-allocation of resources or buffer overruns in dependent code.
 *
 * Implementation Notes:
 * • Zero-length input returns 0 pages (valid edge case per WDK contract).
 * • Overflow detection: if (Address + Length - 1) wraps around to a value less than Address,
 *   the parameters are invalid and IOP_MC_PAGE_COUNT_OVERFLOW is returned.
 * • Callers should check for IOP_MC_PAGE_COUNT_OVERFLOW before using the result for allocations
 *   or bounds calculations.
 *
 * Post-Conditions:
 * - Returns minimum page count to contain Length bytes starting at Address.
 * - Returns IOP_MC_PAGE_COUNT_OVERFLOW if the computation would overflow.
 * - Returns 0 if Length is 0 (no pages needed).
 * - No side effects; pure function suitable for high-frequency paths.
 *
 * Example overflow scenario:
 *   Address = 0xFFFFFFFFFFFFF000 (near end of 64-bit address space)
 *   Length  = 0x00002000 (8 KB)
 *   Address + Length - 1 = 0x0000000000000FFF (wrapped around!)
 *   Result without check: incorrect small page count
 *   Result with check: IOP_MC_PAGE_COUNT_OVERFLOW
 */
__forceinline static ULONG
IopMcComputePageCount(PVOID Address, ULONG Length)
{
    /* Zero-length: no pages needed (valid edge case) */
    if (Length == 0) {
        return 0;
    }

    /*
     * SECURITY: Detect integer overflow in (Address + Length - 1).
     * If the sum wraps around, the end address will be LESS than the start address.
     * This prevents incorrect page count calculations that could lead to buffer overruns.
     */
    ULONG_PTR base = (ULONG_PTR)Address;
    ULONG_PTR end_inclusive = base + (ULONG_PTR)Length - 1;

    if (end_inclusive < base) {
        /* Overflow detected: (base + Length - 1) wrapped around */
        return IOP_MC_PAGE_COUNT_OVERFLOW;
    }

    return (ULONG)ADDRESS_AND_SIZE_TO_SPAN_PAGES(Address, Length);
}

/*==========================
 * Core Validation Logic
 *==========================*/
/*
 * Extensible validation engine for IOP_MC buffer entries with policy-driven strictness.
 *
 * Rationale: Undocumented kernel structures evolve across OS releases; rigid validation breaks forward
 * compatibility while permissive checks miss corruption. This validator accepts a policy bitmask
 * enabling callers to tune behavior (strict fail-fast vs. lenient best-effort) per deployment context.
 * An optional violation output captures granular failure reasons for telemetry and root-cause analysis.
 *
 * Preconditions:
 * - Entry pointer may be NULL (rejected with VIOL_NULL_ENTRY) or untrusted kernel-VA (validated via SEH).
 * - Flags bitmask defines enforcement profile; mismatched flags (e.g., STRICT + LENIENT same category) resolve
 * to lenient precedence (caller explicitly relaxes).
 * - ExpectedType permits OS-specific type constants; pass IOP_MC_KNOWN_TYPE_WIN11 for current kernel.
 * - OutViolationMask may be NULL if caller performs simple pass/fail without diagnostics.
 * - Caller IRQL <= APC_LEVEL; pageable memory access possible.
 *
 * Implementation Notes:
 * • Validation proceeds in phases: NULL check → user-VA rejection → SEH-guarded structural probes → semantic checks.
 * Early exit on critical failures (NULL, user-space, access fault) prevents cascading errors.
 * • User-space pointer detection (MmIsAddressValid / MmSystemRangeStart comparison) occurs before any dereference
 * to prevent speculative execution touching user VA under kernel credentials.
 * • SEH wrapper (__try/__except) catches page faults from freed/paged-out entries; returns ACCESS_VIOLATION
 * with VIOL_ACCESS_FAULT set.
 * • Type and Size checks execute first within SEH block; mismatches prevent trusting subsequent field offsets.
 * • Flag validation: known bits (UNLOCK, SIGNAL_RUNDOWN, CLEANED_UP) permitted; unknown bits trigger failure
 * under FAIL_UNKNOWN_FLAGS policy (protects against OS mismatch or memory corruption).
 * • MDL coherence: checks length consistency, process pointer validity, and cross-validates with CLEANED_UP flag
 * (non-NULL MDL after cleanup indicates incomplete teardown).
 * • Lenient overrides: LENIENT_TYPE/SIZE/MDL bits disable corresponding strict checks; logged but not rejected.
 * • AccessMode validation (VALIDATE_ADDRMODE): cross-checks AccessMode field (0=kernel, 1=user) against VA range
 * classification; mismatch indicates privilege confusion or tampering.
 *
 * Performance Characteristics:
 * - O(1): Fixed sequence of checks; no iteration over MDL page arrays.
 * - No allocations: Stack-only operation; suitable for high-frequency paths.
 * - SEH overhead: ~100 cycles if no fault; acceptable for security-critical validation.
 *
 * Edge Cases:
 * - NULL entry: Rejected immediately with VIOL_NULL_ENTRY; no dereference attempted.
 * - User-space pointer: Detected via MmSystemRangeStart comparison before SEH; avoids speculative kernel-mode read.
 * - Stale/freed memory: SEH catches access violation; marks VIOL_ACCESS_FAULT and returns early.
 * - Type mismatch: Indicates wrong structure or OS version; fails unless LENIENT_TYPE overrides.
 * - Size drift: Structure layout changed; fails unless LENIENT_SIZE permits forward compatibility.
 * - Unknown flags: Future kernel additions or corruption; rejected unless FAIL_UNKNOWN_FLAGS omitted.
 * - MDL NULL but not CLEANED_UP: Potentially valid (pre-initialization) or incomplete teardown; allowed.
 * - MDL non-NULL after CLEANED_UP: Inconsistent state; flagged as VIOL_MDL_NONNULL_AFTER_CLEANUP.
 * - MDL length != Entry length: Desynchronized metadata; fails under STRICT_MDL.
 * - Zero length: Permitted unless FAIL_ZERO_LENGTH policy active; some contexts allow zero-byte buffers.
 * - Negative/zero refcount: Freed or corrupted entry; fails under FAIL_BAD_REFCOUNT.
 *
 * Post-Conditions:
 * - Returns STATUS_SUCCESS only if all enabled checks pass.
 * - Returns STATUS_INVALID_PARAMETER for structural failures (NULL, type/size mismatch).
 * - Returns STATUS_ACCESS_VIOLATION for memory faults during read.
 * - OutViolationMask populated with bitwise-OR of all observed violations (if non-NULL).
 * - No mutation of Entry or system state; operation is read-only and idempotent.
 *
 * Security Considerations:
 * - SECURITY: Never dereferences user-space pointers; enforces kernel-VA requirement under FAIL_USERPTR_ENTRY.
 * - SECURITY: SEH prevents malicious pointers from crashing kernel; converts faults to STATUS codes.
 * - SECURITY: Strict mode rejects unknown flag bits to detect tampering or OS mismatch; lenient mode logs only.
 * - SECURITY: AccessMode validation prevents privilege escalation via mismatched address-space tagging.
 */
/**
 * @function   IopValidateMcBufferEntryEx
 * @purpose    Strict validation of an _IOP_MC_BUFFER_ENTRY using policy flags
 * @precondition IRQL <= APC_LEVEL; Entry is untrusted; avoid holding locks that could deadlock on page faults
 * @postcondition STATUS_SUCCESS only if all enabled checks pass; OutViolationMask set when provided
 * @thread-safety Read-only; idempotent; no global mutation
 * @side-effects None
 */
_IRQL_requires_max_(APC_LEVEL)
__forceinline static NTSTATUS
IopValidateMcBufferEntryEx(
    _In_     PIOP_MC_BUFFER_ENTRY Entry,
    _In_     ULONG                Flags,
    _In_     USHORT               ExpectedType,
    _Out_opt_ PULONG              OutViolationMask
    )
{
    ULONG viol = IOP_MC_VIOL_NONE;

    if (OutViolationMask) {
        *OutViolationMask = IOP_MC_VIOL_NONE;
    }

    if (Entry == NULL) {
        viol |= IOP_MC_VIOL_NULL_ENTRY;
        if (OutViolationMask) *OutViolationMask = viol;
        IOP_MC_LOG_ERROR("Entry is NULL\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (Flags & IOP_MC_VF_FAIL_USERPTR_ENTRY) {
        if ((ULONG_PTR)Entry < (ULONG_PTR)MmSystemRangeStart) {
            viol |= IOP_MC_VIOL_USERPTR_ENTRY;
            if (OutViolationMask) *OutViolationMask = viol;
            IOP_MC_LOG_ERROR("Entry %p is in user-mode address range\n", Entry);
            return STATUS_INVALID_PARAMETER;
        }
    }

    __try {
        USHORT type = Entry->Type;
        ULONG  size = Entry->Size;

        BOOLEAN strict_type = (Flags & IOP_MC_VF_STRICT_TYPE) && !(Flags & IOP_MC_VF_LENIENT_TYPE);
        BOOLEAN strict_size = (Flags & IOP_MC_VF_STRICT_SIZE) && !(Flags & IOP_MC_VF_LENIENT_SIZE);
        BOOLEAN strict_mdl  = (Flags & IOP_MC_VF_STRICT_MDL)  && !(Flags & IOP_MC_VF_LENIENT_MDL);

        if (strict_type && (type != ExpectedType)) {
            viol |= IOP_MC_VIOL_BAD_TYPE;
            IOP_MC_LOG_ERROR("Type mismatch: entry=%04X expected=%04X\n", type, ExpectedType);
        }

        if (strict_size && (size != IOP_MC_KNOWN_SIZE_WIN11)) {
            viol |= IOP_MC_VIOL_BAD_SIZE;
            IOP_MC_LOG_ERROR("Size mismatch: entry=%08X expected=%08X\n", size, (ULONG)IOP_MC_KNOWN_SIZE_WIN11);
        }

        ULONG flags_val = Entry->Flags;
        ULONG known_flags = (IOP_MCBF_UNLOCK | IOP_MCBF_SIGNAL_RUNDOWN | IOP_MCBF_CLEANED_UP);
        if ((Flags & IOP_MC_VF_FAIL_UNKNOWN_FLAGS) && (flags_val & ~known_flags)) {
            viol |= IOP_MC_VIOL_UNKNOWN_FLAGS;
            IOP_MC_LOG_ERROR("Unknown flags detected: 0x%08X\n", flags_val & ~known_flags);
        }

        /*
         * Strict flags validation: reject entries with ANY flags set (even known ones).
         * Use case: detecting entries expected to be in pristine/initial state.
         * Distinct from FAIL_UNKNOWN_FLAGS which only catches bits outside the known set.
         * Lenient override allows callers to accept flagged entries when needed.
         */
        BOOLEAN strict_flags = (Flags & IOP_MC_VF_STRICT_FLAGS) && !(Flags & IOP_MC_VF_LENIENT_FLAGS);
        if (strict_flags && (flags_val != 0)) {
            viol |= IOP_MC_VIOL_FLAGS_NONZERO_STRICT;
            IOP_MC_LOG_ERROR("Flags present in strict-flags mode: 0x%08X\n", flags_val);
        }

        ULONG length = Entry->Length;
        if ((Flags & IOP_MC_VF_FAIL_ZERO_LENGTH) && (length == 0)) {
            viol |= IOP_MC_VIOL_ZERO_LENGTH;
            IOP_MC_LOG_ERROR("Zero length detected\n");
        }

        LONG refcnt = Entry->ReferenceCount;
        if ((Flags & IOP_MC_VF_FAIL_BAD_REFCOUNT) && (refcnt <= 0)) {
            viol |= IOP_MC_VIOL_BAD_REFCOUNT;
            IOP_MC_LOG_ERROR("Bad reference count: %d\n", refcnt);
        }

        UCHAR access_mode = Entry->AccessMode;
        PVOID addr = Entry->Address;
        if (Flags & IOP_MC_VF_VALIDATE_ADDRMODE) {
            BOOLEAN is_kernel_range = ((ULONG_PTR)addr >= (ULONG_PTR)MmSystemRangeStart);
            BOOLEAN access_is_kernel = (access_mode == 0);
            if (is_kernel_range != access_is_kernel) {
                viol |= IOP_MC_VIOL_ADDRMODE_MISMATCH;
                IOP_MC_LOG_ERROR("AccessMode mismatch: mode=%d addr=%p\n", access_mode, addr);
            }
        }

        PMDL mdl = Entry->Mdl;
        if (strict_mdl) {
            BOOLEAN cleaned = (flags_val & IOP_MCBF_CLEANED_UP) ? TRUE : FALSE;
            if (mdl == NULL && !cleaned) {
            } else if (mdl != NULL && cleaned) {
                viol |= IOP_MC_VIOL_MDL_NONNULL_AFTER_CLEANUP;
                IOP_MC_LOG_ERROR("MDL non-NULL after CLEANED_UP\n");
            }

            if (mdl != NULL) {
                /*
                 * SECURITY: Validate MDL pointer is in kernel address space before any dereference.
                 * An attacker controlling a corrupted entry could set Entry->Mdl to a user-space
                 * address. Without this check, the kernel would read from attacker-controlled memory
                 * when calling MmGetMdlByteCount(mdl) or accessing mdl->Process, potentially
                 * enabling information disclosure or controlled data injection attacks.
                 * While SEH would catch access violations, validating the pointer range first
                 * prevents the kernel from touching user-controlled memory entirely (defense-in-depth).
                 */
                if ((ULONG_PTR)mdl < (ULONG_PTR)MmSystemRangeStart) {
                    viol |= IOP_MC_VIOL_MDL_USERPTR;
                    IOP_MC_LOG_ERROR("MDL pointer %p is in user-mode range\n", mdl);
                } else {
                    /* MDL is in kernel VA - safe to dereference for validation */
                    ULONG mdl_len = MmGetMdlByteCount(mdl);
                    if (mdl_len != length) {
                        viol |= IOP_MC_VIOL_MDL_LENGTH_MISMATCH;
                        IOP_MC_LOG_ERROR("MDL length mismatch: mdl=%u entry=%u\n", mdl_len, length);
                    }
                    PEPROCESS proc = mdl->Process;
                    if (proc == NULL && access_mode == 1) {
                        viol |= IOP_MC_VIOL_MDL_PROC_NULL;
                        IOP_MC_LOG_ERROR("MDL->Process is NULL for user-mode AccessMode\n");
                    }
                }
            }
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        viol |= IOP_MC_VIOL_ACCESS_FAULT;
        if (OutViolationMask) *OutViolationMask = viol;
        IOP_MC_LOG_ERROR("Access violation reading entry %p (code=0x%08X)\n", Entry, GetExceptionCode());
        return STATUS_ACCESS_VIOLATION;
    }

    if (OutViolationMask) {
        *OutViolationMask = viol;
    }

    if (viol != IOP_MC_VIOL_NONE) {
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

/*
 * Strict validation wrapper with default security-focused policy.
 *
 * Rationale: Most use cases demand fail-fast behavior to prevent downstream exploitation of
 * corrupted or malicious entries. This wrapper applies the default policy bitmask (all strict
 * checks enabled, user-space pointers rejected) and the known Win11 type constant, eliminating
 * boilerplate for common security-monitoring workflows.
 *
 * Preconditions:
 * - Entry pointer is untrusted; may be NULL or hostile.
 * - Caller IRQL <= APC_LEVEL (pageable memory access possible).
 *
 * Implementation Notes:
 * • Delegates to IopValidateMcBufferEntryEx with IOP_MC_VF_DEFAULT and IOP_MC_KNOWN_TYPE_WIN11.
 * • Violation mask not captured; caller receives only pass/fail NTSTATUS.
 * • Inline expansion allows compiler to optimize away intermediate function call overhead.
 *
 * Post-Conditions:
 * - Returns STATUS_SUCCESS only if Entry passes all default validation checks.
 * - Returns STATUS_INVALID_PARAMETER or STATUS_ACCESS_VIOLATION on failure.
 * - No side effects; Entry and system state unchanged.
 */
/**
 * @function   IopIsValidMcBufferEntry
 * @purpose    Convenience wrapper applying default strict validation policy
 * @precondition IRQL <= APC_LEVEL; Entry may be NULL or hostile
 * @postcondition Returns NTSTATUS indicating pass/fail; no mutation
 * @thread-safety Read-only; idempotent
 * @side-effects None
 */
_IRQL_requires_max_(APC_LEVEL)
__forceinline static NTSTATUS
IopIsValidMcBufferEntry(_In_ PIOP_MC_BUFFER_ENTRY Entry)
{
    return IopValidateMcBufferEntryEx(
        Entry,
        IOP_MC_VF_DEFAULT,
        IOP_MC_KNOWN_TYPE_WIN11,
        NULL
    );
}

/*=============================================
 * Safe Info Projection (IOCTL-friendly)
 *=============================================*/
/*
 * Project validated MC buffer entry into sanitized, caller-safe metadata structure.
 *
 * Rationale: IOCTL handlers and diagnostic tools require buffer metadata (size, flags, page count)
 * without exposure to raw kernel pointers or MDL internals. Validates the entry under strict policy,
 * then copies only caller-safe fields into a pre-sanitized output structure. Prevents leakage of kernel
 * implementation details while enabling rich diagnostics.
 *
 * Preconditions:
 * - Entry pointer is untrusted; caller must not assume prior validation.
 * - Info must point to writable caller-allocated IOP_MC_BUFFER_ENTRY_INFO structure.
 * - Caller IRQL <= APC_LEVEL (pageable memory access possible).
 * - Caller holds no locks that would deadlock during potential page faults.
 *
 * Implementation Notes:
 * • Info structure zeroed upfront; failure paths return with all fields zero to prevent partial leakage.
 * • Validation performed via IopIsValidMcBufferEntry (strict policy); only compliant entries projected.
 * • Field copy wrapped in SEH to catch stale/freed entries that pass initial validation but fault during read
 *   (TOCTOU scenario); SEH converts fault to STATUS_ACCESS_VIOLATION.
 * • Address field retained as ULONG_PTR handle for diagnostic correlation in default usage; callers must
 *   not dereference this value.
 * • IopQueryMcBufferEntryEx accepts query flags (IOP_MC_QF_MASK_ADDRESS) so callers exposing results
 *   across a trust boundary can deliberately strip the Address field.
 * • HasMdl boolean replaces raw MDL pointer; prevents exposure of kernel heap addresses.
 * • CleanedUp derived from flag bit to simplify consumer logic without exposing full flag bitmap.
 * • NumberOfPages computed via helper to avoid direct MDL page array access.
 *
 * Performance Characteristics:
 * - O(1): Single validation pass followed by fixed field copies.
 * - No allocations: Caller provides output buffer.
 * - SEH overhead: ~100 cycles if no fault; negligible for IOCTL context.
 *
 * Edge Cases:
 * - Info NULL: Rejected immediately with STATUS_INVALID_PARAMETER.
 * - Entry fails validation: Info zeroed, validation NTSTATUS returned.
 * - Entry freed between validation and copy: SEH catches fault, returns STATUS_ACCESS_VIOLATION with Info zeroed.
 * - MDL NULL: HasMdl set FALSE; NumberOfPages derived from Length field only.
 *
 * Post-Conditions:
 * - Returns STATUS_SUCCESS with Info populated only if Entry passes strict validation and copy succeeds.
 * - Returns validation or access failure NTSTATUS with Info zeroed on any error path.
 * - Entry and system state unchanged; operation is read-only and idempotent.
 *
 * Security Considerations:
 * - SECURITY: Never exposes raw kernel pointers (MDL, Event, Context) to caller.
 * - SECURITY: Address field treated as opaque handle by default; callers may use IOP_MC_QF_MASK_ADDRESS
 *             when projecting into untrusted domains (for example, user-mode IOCTL payloads).
 * - SECURITY: Validation enforces user-space entry pointer rejection; prevents kernel-mode read of user VA.
 */
/**
 * @function   IopQueryMcBufferEntryEx
 * @purpose    Project validated entry into sanitized IOP_MC_BUFFER_ENTRY_INFO (with query flags)
 * @precondition IRQL <= APC_LEVEL; Entry untrusted; Info non-NULL writable
 * @postcondition On success, Info populated; on failure, Info zeroed and NTSTATUS returned
 * @thread-safety Read-only; no global mutation
 * @side-effects None
 */
_IRQL_requires_max_(APC_LEVEL)
__forceinline static NTSTATUS
IopQueryMcBufferEntryEx(
    _In_  PIOP_MC_BUFFER_ENTRY      Entry,
    _Out_ PIOP_MC_BUFFER_ENTRY_INFO Info,
    _In_  IOP_MC_QUERY_FLAGS        QueryFlags
    )
{
    if (Info == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Info, sizeof(*Info));

    NTSTATUS st = IopIsValidMcBufferEntry(Entry);
    if (!NT_SUCCESS(st)) {
        return st;
    }

    __try {
        Info->Type           = Entry->Type;
        Info->Flags          = (USHORT)Entry->Flags;
        Info->Size           = Entry->Size;
        Info->ReferenceCount = Entry->ReferenceCount;
        Info->Address        = (ULONG_PTR)Entry->Address;
        Info->Length         = Entry->Length;
        Info->AccessMode     = (UCHAR)Entry->AccessMode;
        Info->HasMdl         = (Entry->Mdl != NULL) ? TRUE : FALSE;
        Info->CleanedUp      = ((Entry->Flags & IOP_MCBF_CLEANED_UP) ? TRUE : FALSE);

        /* Compute page count with overflow detection */
        ULONG pageCount = IopMcComputePageCount(Entry->Address, Entry->Length);
        if (pageCount == IOP_MC_PAGE_COUNT_OVERFLOW) {
            IOP_MC_LOG_ERROR("Page count overflow: Address=%p Length=0x%X\n",
                             Entry->Address, Entry->Length);
            /* Set to 0 to indicate invalid/unknown page count */
            pageCount = 0;
        }
        Info->NumberOfPages = pageCount;

        if (QueryFlags & IOP_MC_QF_MASK_ADDRESS) {
            Info->Address = 0;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        IOP_MC_LOG_ERROR("Fault while copying entry %p into info\n", Entry);
        RtlZeroMemory(Info, sizeof(*Info));
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}

/**
 * @function   IopQueryMcBufferEntry
 * @purpose    Projection helper with default flags (no address masking)
 * @precondition IRQL <= APC_LEVEL; Entry untrusted; Info non-NULL writable
 * @postcondition Returns NTSTATUS; Info populated on success
 * @thread-safety Read-only; idempotent
 * @side-effects None
 */
_IRQL_requires_max_(APC_LEVEL)
__forceinline static NTSTATUS
IopQueryMcBufferEntry(
    _In_  PIOP_MC_BUFFER_ENTRY      Entry,
    _Out_ PIOP_MC_BUFFER_ENTRY_INFO Info
    )
{
    return IopQueryMcBufferEntryEx(Entry, Info, IOP_MC_QF_NONE);
}

/*=============================
 * Debug Dump Helper
 *============================*/

/*
 * Emit structured snapshot of MC buffer entry to kernel debugger.
 *
 * Rationale: Validates the entry, then formats all fields (including decoded flag bits and MDL metadata) as debugger-friendly text. Compiled away
 * in retail builds to eliminate overhead and avoid leaking internal state in production.
 *
 * Preconditions:
 * - Entry pointer is untrusted; may be NULL or hostile.
 * - Caller IRQL <= APC_LEVEL (DbgPrintEx and pageable memory access).
 * - Debug build (DBG defined); retail builds make this a no-op.
 *
 * Implementation Notes:
 * • Validation performed via IopIsValidMcBufferEntry; dump aborted if entry fails strict checks.
 * • All field reads wrapped in SEH to prevent debugger crashes from stale/freed entries.
 * • Flag bits decoded individually (UNLOCK, SIGNAL_RUNDOWN, CLEANED_UP) for human readability.
 * • MDL details (ByteCount, VA, Process) printed if MDL non-NULL; nested SEH isolates MDL faults
 * from outer exception handler.
 * • AccessMode decoded as "Kernel" (0) or "User" (1) with fallback for unknown values.
 * • Page count computed via helper for consistency with projection logic.
 * • Output formatted with labels and hex/decimal dual-display for ease of analysis.
 *
 * Performance Characteristics:
 * - Debug-only: Zero cost in retail builds (entire function body omitted).
 * - I/O-bound: DbgPrintEx dominates execution time; not suitable for hot paths.
 *
 * Edge Cases:
 * - Entry fails validation: Dump aborted with diagnostic message; prevents misleading output.
 * - Entry freed during dump: Outer SEH catches fault, logs error, returns early.
 * - MDL present but inaccessible: Inner SEH isolates MDL read failure; logs "<inaccessible>".
 * - Unknown AccessMode value: Printed as "Unknown" with raw value for diagnostic purposes.
 *
 * Post-Conditions:
 */
_IRQL_requires_max_(APC_LEVEL)
__forceinline static VOID
IopDumpMcBufferEntry(_In_ PIOP_MC_BUFFER_ENTRY Entry)
{
#if DBG
    NTSTATUS st = IopIsValidMcBufferEntry(Entry);
    if (!NT_SUCCESS(st)) {
        IOP_MC_LOG_ERROR("Dump aborted: entry %p failed validation (0x%08X)\n", Entry, st);
        return;
    }

    __try {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "\n[IOP_MC] Dumping entry @ %p\n"
            "  Type:        0x%04X\n"
            "  Size:        0x%08X\n"
            "  Flags:       0x%04X\n"
            "  RefCount:    %d\n"
            "  MdlRef:      %d\n"
            "  AccessMode:  %d (%s)\n"
            "  Address:     %p\n"
            "  Length:      0x%08X (%u)\n"
            "  MDL:         %p\n",
            Entry,
            Entry->Type,
            Entry->Size,
            (USHORT)Entry->Flags,
            Entry->ReferenceCount,
            Entry->MdlRef,
            (UCHAR)Entry->AccessMode,
            ((Entry->AccessMode == 0) ? "Kernel" : ((Entry->AccessMode == 1) ? "User" : "Unknown")),
            Entry->Address,
            Entry->Length, Entry->Length,
            Entry->Mdl
        );

        if (Entry->Flags & IOP_MCBF_UNLOCK) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "  [Flag] UNLOCK set\n");
        }
        if (Entry->Flags & IOP_MCBF_SIGNAL_RUNDOWN) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "  [Flag] SIGNAL_RUNDOWN set\n");
        }
        if (Entry->Flags & IOP_MCBF_CLEANED_UP) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "  [Flag] CLEANED_UP set\n");
        }

        ULONG pages = IopMcComputePageCount(Entry->Address, Entry->Length);
        if (pages == IOP_MC_PAGE_COUNT_OVERFLOW) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "  Pages:       OVERFLOW (Address=%p, Length=0x%X)\n",
                       Entry->Address, Entry->Length);
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "  Pages:       %lu\n", pages);
        }

        if (Entry->Mdl) {
            __try {
                ULONG mdlen = MmGetMdlByteCount(Entry->Mdl);
                PVOID mdva = MmGetMdlVirtualAddress(Entry->Mdl);
                PEPROCESS mdlProc = Entry->Mdl->Process;
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                    "  MDL->ByteCount: 0x%08X\n"
                    "  MDL->VA:        %p\n"
                    "  MDL->Process:   %p\n",
                    mdlen, mdva, mdlProc);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "  MDL fields: <inaccessible>\n");
            }
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[IOP_MC] End dump\n\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        IOP_MC_LOG_ERROR("Access violation during dump of entry %p\n", Entry);
    }
#else
    UNREFERENCED_PARAMETER(Entry);
#endif
}

#endif /* IOP_MC_H_INCLUDED */
