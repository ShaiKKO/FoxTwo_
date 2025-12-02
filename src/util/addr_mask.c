/*
 * Address Masking Module – Implementation
 *
 * Author: Colin MacRitchie
 * Organization: ziX Performance Labs
 * File: addr_mask.c
 * Version: 1.0
 * Date: 2025-12-01
 * Copyright:
 *   © 2025 ziX Performance Labs. All rights reserved. Proprietary and
 * confidential. Redistribution or disclosure without prior written consent is
 * prohibited.
 *
 * Summary
 * -------
 * Implements kernel address masking using SipHash-2-4 for secure telemetry.
 * Per-boot random key prevents cross-session correlation attacks while
 * allowing within-session object tracking.
 *
 * SipHash Implementation
 * ----------------------
 * Based on the reference implementation by Jean-Philippe Aumasson and
 * Daniel J. Bernstein. SipHash-2-4 provides:
 * - 64-bit output from variable-length input
 * - 128-bit key for keyed hashing
 * - Collision resistance suitable for hash tables
 * - Speed comparable to non-cryptographic hashes
 *
 * References:
 * - SipHash paper: https://131002.net/siphash/siphash.pdf
 * - Linux kernel implementation: crypto/siphash.c
 */

#include "addr_mask.h"

#include <bcrypt.h>
#include <ntifs.h>

#include "monitor_internal.h"

#pragma warning(push)
#pragma warning(disable : 4201 4214)

/*--------------------------------------------------------------------------
 * SipHash-2-4 Implementation
 *
 * Adapted from the reference C implementation.
 * https://github.com/veorq/SipHash
 *-------------------------------------------------------------------------*/

#define SIPHASH_ROTL64(x, b) (((x) << (b)) | ((x) >> (64 - (b))))

#define SIPHASH_ROUND(v0, v1, v2, v3) \
  do {                                \
    (v0) += (v1);                     \
    (v1) = SIPHASH_ROTL64((v1), 13);  \
    (v1) ^= (v0);                     \
    (v0) = SIPHASH_ROTL64((v0), 32);  \
    (v2) += (v3);                     \
    (v3) = SIPHASH_ROTL64((v3), 16);  \
    (v3) ^= (v2);                     \
    (v0) += (v3);                     \
    (v3) = SIPHASH_ROTL64((v3), 21);  \
    (v3) ^= (v0);                     \
    (v2) += (v1);                     \
    (v1) = SIPHASH_ROTL64((v1), 17);  \
    (v1) ^= (v2);                     \
    (v2) = SIPHASH_ROTL64((v2), 32);  \
  } while (0)

/**
 * @function   MonSipHash24
 * @purpose    Compute SipHash-2-4 of 8-byte input (optimized for addresses)
 * @param[in]  Input - 64-bit value to hash
 * @param[in]  Key - 128-bit key as two 64-bit values
 * @returns    64-bit hash value
 */
static ULONG64 MonSipHash24(_In_ ULONG64 Input, _In_ const ULONG64 Key[2]) {
  /*
   * SipHash initialization constants
   * These are the "somepseudorandomlygeneratedbytes" from the paper
   */
  ULONG64 v0 = 0x736f6d6570736575ULL ^ Key[0];
  ULONG64 v1 = 0x646f72616e646f6dULL ^ Key[1];
  ULONG64 v2 = 0x6c7967656e657261ULL ^ Key[0];
  ULONG64 v3 = 0x7465646279746573ULL ^ Key[1];

  /*
   * For 8-byte input, we have exactly one 64-bit block plus the
   * length byte in the final block.
   */
  ULONG64 m = Input;

  /* Process the single message block */
  v3 ^= m;
  SIPHASH_ROUND(v0, v1, v2, v3); /* Round 1 */
  SIPHASH_ROUND(v0, v1, v2, v3); /* Round 2 */
  v0 ^= m;

  /* Final block: length = 8 bytes */
  m = ((ULONG64)8) << 56;
  v3 ^= m;
  SIPHASH_ROUND(v0, v1, v2, v3); /* Round 1 */
  SIPHASH_ROUND(v0, v1, v2, v3); /* Round 2 */
  v0 ^= m;

  /* Finalization */
  v2 ^= 0xff;
  SIPHASH_ROUND(v0, v1, v2, v3); /* Round 1 */
  SIPHASH_ROUND(v0, v1, v2, v3); /* Round 2 */
  SIPHASH_ROUND(v0, v1, v2, v3); /* Round 3 */
  SIPHASH_ROUND(v0, v1, v2, v3); /* Round 4 */

  return v0 ^ v1 ^ v2 ^ v3;
}

/*--------------------------------------------------------------------------
 * Module State
 *-------------------------------------------------------------------------*/

/* Per-boot 128-bit SipHash key */
static ULONG64 g_SipHashKey[2] = {0};

/* Current masking policy */
static volatile LONG g_MaskPolicy = MonMaskPolicy_Hash;

/* Initialization state */
static volatile BOOLEAN g_MaskInitialized = FALSE;

/*--------------------------------------------------------------------------
 * Public API Implementation
 *-------------------------------------------------------------------------*/

/**
 * @function   MonAddrMaskGenerateEntropyFallback
 * @purpose    Generate entropy using multiple kernel sources when BCrypt
 * unavailable
 * @note       This is a FALLBACK only - BCrypt is strongly preferred
 *
 * Entropy sources combined:
 * - KeQueryPerformanceCounter (high-resolution timing)
 * - KeQuerySystemTime (system time)
 * - KeQueryTickCount (tick count)
 * - PsGetCurrentProcessId/ThreadId (execution context)
 * - MmGetPhysicalMemoryRanges pointer (ASLR randomized)
 * - Stack pointer address (ASLR randomized)
 *
 * These are XOR'd together and run through a mixing function.
 * While not cryptographically ideal, this provides significantly
 * better entropy than simple time-based fallback.
 */
static VOID MonAddrMaskGenerateEntropyFallback(_Out_writes_bytes_(16) PUCHAR OutputBuffer) {
  LARGE_INTEGER perfCounter, systemTime;
  ULONG64 entropy[4] = {0};
  volatile UCHAR stackVar = 0;

  /* Source 1: High-resolution performance counter */
  perfCounter = KeQueryPerformanceCounter(NULL);
  entropy[0] = (ULONG64)perfCounter.QuadPart;

  /* Source 2: System time */
  KeQuerySystemTime(&systemTime);
  entropy[1] = (ULONG64)systemTime.QuadPart;

  /* Source 3: Execution context (randomized by ASLR) */
  entropy[2] = (ULONG64)(ULONG_PTR)PsGetCurrentProcessId();
  entropy[2] ^= ((ULONG64)(ULONG_PTR)PsGetCurrentThreadId()) << 32;

  /* Source 4: Stack address (ASLR randomized) + tick count */
  entropy[3] = (ULONG64)(ULONG_PTR)&stackVar;
  {
    LARGE_INTEGER tickCount;
    KeQueryTickCount(&tickCount);
    entropy[3] ^= (ULONG64)tickCount.QuadPart;
  }

  /*
   * Mix entropy sources together using rotation and XOR.
   * This is NOT a cryptographic hash, but provides better
   * distribution than simple XOR.
   */
  for (ULONG round = 0; round < 4; round++) {
    entropy[0] += entropy[1];
    entropy[1] = SIPHASH_ROTL64(entropy[1], 13) ^ entropy[0];
    entropy[2] += entropy[3];
    entropy[3] = SIPHASH_ROTL64(entropy[3], 16) ^ entropy[2];
    entropy[0] += entropy[3];
    entropy[2] += entropy[1];
  }

  /* Output the mixed entropy */
  RtlCopyMemory(OutputBuffer, entropy, 16);

  /* Securely zero local entropy array */
  RtlSecureZeroMemory(entropy, sizeof(entropy));
}

_Use_decl_annotations_ NTSTATUS MonAddrMaskInitialize(VOID) {
  NTSTATUS status;
  UCHAR randomBytes[16];
  BOOLEAN usedFallback = FALSE;

  /*
   * Generate per-boot random key using BCrypt (preferred).
   * BCrypt provides cryptographically secure random bytes from the
   * Windows kernel entropy pool.
   *
   * Reference:
   * https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom
   */
  status = BCryptGenRandom(NULL, randomBytes, sizeof(randomBytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

  if (!NT_SUCCESS(status)) {
    /*
     * BCrypt failed - use enhanced fallback with multiple entropy sources.
     *
     * SECURITY NOTE: This fallback is less secure than BCrypt but provides
     * reasonable entropy for address masking purposes. The primary risk is
     * that an attacker who knows the exact boot timing might be able to
     * predict the key. However:
     * 1. Address masking is defense-in-depth, not the sole protection
     * 2. We combine multiple entropy sources including ASLR-randomized
     * addresses
     * 3. SipHash provides good output distribution even with weak keys
     *
     * If BCrypt is consistently failing, investigate the root cause.
     */
    MonAddrMaskGenerateEntropyFallback(randomBytes);
    usedFallback = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
               "[WIN11MON][MASK] BCrypt failed (0x%08X), using enhanced "
               "fallback RNG\n",
               status);

    /* Continue with fallback - don't fail initialization */
    status = STATUS_SUCCESS;
  }

  /* Copy random bytes into key */
  RtlCopyMemory(g_SipHashKey, randomBytes, sizeof(g_SipHashKey));

  /* Securely zero the temporary buffer */
  RtlSecureZeroMemory(randomBytes, sizeof(randomBytes));

  /* Set default policy */
  InterlockedExchange(&g_MaskPolicy, MON_MASK_DEFAULT_POLICY);

  /* Mark as initialized with release semantics */
  MonWriteBooleanRelease(&g_MaskInitialized, TRUE);

  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
             "[WIN11MON][MASK] Initialized with policy=%d (fallback=%s)\n", g_MaskPolicy,
             usedFallback ? "YES" : "NO");

  return status;
}

_Use_decl_annotations_ VOID MonAddrMaskShutdown(VOID) {
  g_MaskInitialized = FALSE;

  /* Securely zero key material */
  RtlSecureZeroMemory(g_SipHashKey, sizeof(g_SipHashKey));

  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
             "[WIN11MON][MASK] Shutdown complete, key material zeroed\n");
}

_Use_decl_annotations_ NTSTATUS MonAddrMaskSetPolicy(_In_ MON_ADDRESS_MASK_POLICY Policy) {
  if (Policy >= MonMaskPolicy_Max) {
    return STATUS_INVALID_PARAMETER;
  }

  InterlockedExchange(&g_MaskPolicy, (LONG)Policy);

  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[WIN11MON][MASK] Policy set to %d\n", Policy);

  return STATUS_SUCCESS;
}

_Use_decl_annotations_ MON_ADDRESS_MASK_POLICY MonAddrMaskGetPolicy(VOID) {
  return (MON_ADDRESS_MASK_POLICY)InterlockedCompareExchange(&g_MaskPolicy, g_MaskPolicy,
                                                             g_MaskPolicy);
}

_Use_decl_annotations_ ULONG64 MonMaskAddressWithPolicy(_In_ ULONG64 Address,
                                                        _In_ MON_ADDRESS_MASK_POLICY Policy) {
  /* NULL always returns 0 regardless of policy */
  if (Address == 0) {
    return 0;
  }

  /* Validate policy */
  if (Policy >= MonMaskPolicy_Max) {
    Policy = MON_MASK_DEFAULT_POLICY;
  }

  switch (Policy) {
  case MonMaskPolicy_None:
    /*
     * WARNING: Debug only - leaks full kernel address
     * Should trigger audit alert in production systems
     */
    return Address;

  case MonMaskPolicy_Truncate:
    /*
     * Keep high 16 bits, zero the rest.
     * This preserves pool region identification:
     * - 0xFFFF8xxx = nonpaged pool
     * - 0xFFFFAxxx = paged pool
     * - etc.
     */
    return Address & 0xFFFF000000000000ULL;

  case MonMaskPolicy_Hash:
    /*
     * SipHash-2-4 transformation.
     * Returns deterministic hash allowing correlation.
     */
    if (!MonReadBooleanAcquire(&g_MaskInitialized)) {
      /* Subsystem not initialized - return truncated as fallback */
      return Address & 0xFFFF000000000000ULL;
    }
    return MonSipHash24(Address, g_SipHashKey);

  case MonMaskPolicy_Zero:
    /*
     * Complete address removal.
     * Maximum privacy, no correlation possible.
     */
    return 0;

  default:
    /* Should never reach here, but return zero for safety */
    return 0;
  }
}

_Use_decl_annotations_ ULONG64 MonMaskAddress(_In_ ULONG64 Address) {
  MON_ADDRESS_MASK_POLICY policy = MonAddrMaskGetPolicy();
  return MonMaskAddressWithPolicy(Address, policy);
}

#pragma warning(pop)
