/*
 * Address Masking Module – Public Header
 *
 * Author: Colin MacRitchie
 * Organization: ziX Performance Labs
 * File: addr_mask.h
 * Version: 1.0
 * Date: 2025-12-01
 * Copyright:
 *   © 2025 ziX Performance Labs. All rights reserved. Proprietary and
 * confidential. Redistribution or disclosure without prior written consent is
 * prohibited.
 *
 * Summary
 * -------
 * Provides kernel address masking capabilities to prevent KASLR information
 * leakage through telemetry events. Implements multiple masking policies:
 *
 * - None: Full address (for debugging only)
 * - Truncate: Keep high bits, zero low bits (allows pool identification)
 * - Hash: SipHash-2-4 based transformation (allows correlation, no leakage)
 * - Zero: Complete address removal
 *
 * Security Properties
 * -------------------
 * - Default policy is Hash (safest for production)
 * - Per-boot random key prevents cross-session correlation attacks
 * - Truncation preserves pool region identification without exact address
 * - All policies are O(1) time complexity
 *
 * References:
 * - Linux kernel %p hashing: https://patchwork.kernel.org/patch/10031785/
 * - SipHash paper: https://131002.net/siphash/
 * - Windows KASLR hardening:
 * https://windows-internals.com/kaslr-leaks-restriction/
 */

#ifndef _ZIX_LABS_ADDR_MASK_H_
#define _ZIX_LABS_ADDR_MASK_H_

#ifndef _KERNEL_MODE
#error "This header is for kernel-mode only."
#endif

#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------
 * Address Masking Policy
 *
 * Controls how kernel addresses are transformed before external exposure.
 *-------------------------------------------------------------------------*/
typedef enum _MON_ADDRESS_MASK_POLICY {
  /*
   * MonMaskPolicy_None: No masking (DEBUG ONLY)
   *
   * Returns the full kernel address unchanged. This policy MUST NOT be
   * used in production as it leaks kernel ASLR information.
   *
   * Use case: Development debugging, controlled test environments
   */
  MonMaskPolicy_None = 0,

  /*
   * MonMaskPolicy_Truncate: Bit truncation
   *
   * Preserves high 16 bits (pool region identifier), zeros lower 48 bits.
   * Example: 0xFFFF8001'23456789 → 0xFFFF0000'00000000
   *
   * Properties:
   * - Identifies kernel vs user addresses
   * - Shows pool region (paged, nonpaged, session)
   * - No correlation capability between events
   *
   * Use case: Minimal info for pool region analysis
   */
  MonMaskPolicy_Truncate = 1,

  /*
   * MonMaskPolicy_Hash: SipHash-based transformation (DEFAULT)
   *
   * Uses SipHash-2-4 with a per-boot random 128-bit key to transform
   * the address into a 64-bit hash. Same address always produces same
   * hash within a boot session, allowing event correlation.
   *
   * Properties:
   * - Deterministic within boot session
   * - Different hash each boot (per-boot key)
   * - Cannot reverse to original address
   * - Allows correlation of events referencing same object
   *
   * Use case: Production telemetry (recommended default)
   */
  MonMaskPolicy_Hash = 2,

  /*
   * MonMaskPolicy_Zero: Complete removal
   *
   * Returns 0 for all addresses. Maximum privacy but no correlation.
   *
   * Use case: High-security environments where even hashed addresses
   *           are considered too risky
   */
  MonMaskPolicy_Zero = 3,

  MonMaskPolicy_Max
} MON_ADDRESS_MASK_POLICY;

/*--------------------------------------------------------------------------
 * Configuration Constants
 *-------------------------------------------------------------------------*/

/* Default policy for new driver instances */
#define MON_MASK_DEFAULT_POLICY MonMaskPolicy_Hash

/* Truncation preserves this many high bits */
#define MON_MASK_TRUNCATE_BITS 16

/*--------------------------------------------------------------------------
 * Public Function Prototypes
 *-------------------------------------------------------------------------*/

/**
 * @function   MonAddrMaskInitialize
 * @purpose    Initialize address masking subsystem with random key
 * @precondition IRQL == PASSIVE_LEVEL; Called from DriverEntry
 * @postcondition Per-boot SipHash key generated, ready for masking
 * @thread-safety Single-threaded init
 * @side-effects Generates cryptographic random key
 * @returns    STATUS_SUCCESS if initialization succeeded
 *             STATUS_UNSUCCESSFUL if RNG failed
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS MonAddrMaskInitialize(VOID);

/**
 * @function   MonAddrMaskShutdown
 * @purpose    Clean up address masking subsystem
 * @precondition IRQL == PASSIVE_LEVEL; Called from DriverUnload
 * @postcondition Key material securely zeroed
 * @thread-safety Single-threaded shutdown
 * @side-effects Zeros key material
 */
_IRQL_requires_(PASSIVE_LEVEL) VOID MonAddrMaskShutdown(VOID);

/**
 * @function   MonAddrMaskSetPolicy
 * @purpose    Set the current address masking policy
 * @precondition IRQL <= DISPATCH_LEVEL
 * @postcondition New policy takes effect for subsequent masking calls
 * @thread-safety Thread-safe (atomic write)
 * @side-effects Updates global policy
 *
 * @param[in] Policy - New masking policy to apply
 * @returns   STATUS_SUCCESS if policy set
 *            STATUS_INVALID_PARAMETER if policy out of range
 */
_IRQL_requires_max_(DISPATCH_LEVEL) NTSTATUS
    MonAddrMaskSetPolicy(_In_ MON_ADDRESS_MASK_POLICY Policy);

/**
 * @function   MonAddrMaskGetPolicy
 * @purpose    Get the current address masking policy
 * @precondition IRQL <= DISPATCH_LEVEL
 * @postcondition Returns current policy
 * @thread-safety Thread-safe (atomic read)
 * @side-effects None
 */
_IRQL_requires_max_(DISPATCH_LEVEL) MON_ADDRESS_MASK_POLICY MonAddrMaskGetPolicy(VOID);

/**
 * @function   MonMaskAddress
 * @purpose    Transform a kernel address according to current policy
 * @precondition IRQL <= DISPATCH_LEVEL; Subsystem initialized
 * @postcondition Returns masked address suitable for external exposure
 * @thread-safety Thread-safe, re-entrant
 * @side-effects None
 *
 * @param[in] Address - Raw kernel address to mask
 * @returns   Masked address according to current policy
 *
 * Security Notes:
 * - MonMaskPolicy_None returns address unchanged (debug only)
 * - MonMaskPolicy_Hash returns deterministic hash (same input → same output)
 * - NULL input always returns 0 regardless of policy
 */
_IRQL_requires_max_(DISPATCH_LEVEL) ULONG64 MonMaskAddress(_In_ ULONG64 Address);

/**
 * @function   MonMaskAddressWithPolicy
 * @purpose    Transform address using specified policy (override current)
 * @precondition IRQL <= DISPATCH_LEVEL; Subsystem initialized
 * @postcondition Returns masked address per specified policy
 * @thread-safety Thread-safe, re-entrant
 * @side-effects None
 *
 * @param[in] Address - Raw kernel address to mask
 * @param[in] Policy - Policy to use (overrides global setting)
 * @returns   Masked address according to specified policy
 */
_IRQL_requires_max_(DISPATCH_LEVEL) ULONG64
    MonMaskAddressWithPolicy(_In_ ULONG64 Address, _In_ MON_ADDRESS_MASK_POLICY Policy);

/**
 * @function   MonMaskPointer
 * @purpose    Convenience wrapper for pointer types
 * @precondition IRQL <= DISPATCH_LEVEL
 * @postcondition Returns masked pointer value as ULONG64
 * @thread-safety Thread-safe
 *
 * @param[in] Ptr - Pointer to mask
 * @returns   Masked pointer value
 */
_IRQL_requires_max_(DISPATCH_LEVEL) FORCEINLINE ULONG64 MonMaskPointer(_In_opt_ const VOID *Ptr) {
  return MonMaskAddress((ULONG64)(ULONG_PTR)Ptr);
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _ZIX_LABS_ADDR_MASK_H_ */
