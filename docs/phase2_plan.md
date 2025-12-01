# Windows 11 Monitor Manager – Phase 2 Implementation Plan

**Version**: 1.0
**Date**: 2025-11-30
**Status**: Planning
**Author**: Colin MacRitchie | ziX Labs

---

## Executive Summary

Phase 1 delivered the core detection infrastructure (A1, A2, B1). Phase 2 focuses on:
- **Telemetry hardening** (B2, B3) - Address masking and per-process rate limiting
- **Extended detection** (A3) - Additional pool tag monitoring for WNF/Pipe spray
- **Robustness** (C1 partial) - Already embedded in Phase 1, needs validation
- **Deferred** (A4) - Named pipe minifilter remains out of scope

---

## Phase 1 Completion Status

| Item | Status | Notes |
|------|--------|-------|
| A1: IoRing Handle Enumeration | ✅ Complete | `ioring_enum.c/h` |
| A2: RegBuffers Integrity | ✅ Complete | `regbuf_integrity.c/h` |
| B1: ETW TraceLogging | ✅ Complete | `telemetry_etw.c/h` |
| C1: Offset Resolution (partial) | ✅ Complete | Embedded tables in A1 |
| D1: MITRE ATT&CK Tagging | ✅ Complete | Embedded in B1 events |

---

## Phase 2 Scope

### Tier 1 (High Priority)

#### B2: Address Masking Enhancement
**Rationale**: Prevent kernel address leakage in telemetry events.

**Implementation**:
1. Add `MON_ADDRESS_MASK_POLICY` enum to `win11_monitor_public.h`
2. Create `addr_mask.c/h` module with:
   - `MonMaskAddress()` - Policy-based address transformation
   - `MonHashAddress()` - Truncated SHA256 for correlation
3. Update `MONITOR_SETTINGS` to v2 with `AddressMaskPolicy` field
4. Apply masking in all ETW event emission paths
5. Add IOCTL for runtime policy configuration

**Files**:
- New: `addr_mask.c`, `addr_mask.h`
- Modified: `win11_monitor_public.h`, `telemetry_etw.c`, `win11_monitor_mgr.c`

**Risk**: Low - isolated module, no kernel structure dependencies

---

#### B3: Per-Process Rate Limiting
**Rationale**: Prevent telemetry flooding from single malicious process.

**Implementation**:
1. Create `rate_limit.c/h` module with:
   - `MON_RATE_LIMIT_CONTEXT` state structure
   - `MonRateLimitInitialize()` / `MonRateLimitShutdown()`
   - `MonCheckProcessRateLimit()` - Returns TRUE if event allowed
   - `MonRateLimitCleanup()` - Periodic stale entry removal
2. Hash table or sorted list for O(1) PID lookup
3. Integrate into `MonTelemetryLogBlob()` path
4. Add cleanup timer (60s interval)

**Files**:
- New: `rate_limit.c`, `rate_limit.h`
- Modified: `telemetry.c`, `monitor_internal.h`, `win11_monitor_mgr.c`

**Risk**: Medium - requires spinlock, timer integration

---

### Tier 2 (Medium Priority)

#### A3: Additional Pool Tag Monitoring
**Rationale**: Detect WNF heap spray and pipe-based exploitation.

**Implementation**:
1. Extend `pool_tracker.c` with configurable tag table:
   - `'IrRB'` - IoRing RegBuffer (existing)
   - `'IoRg'` - IoRing Object
   - `'WNF '` - WNF State Data
   - `'Pipe'` - Pipe Attribute
   - `'Toke'` - Token Object
2. Add spray detection heuristics:
   - Track allocation count per PID per tag
   - Alert on >100 allocations in 1s window
3. New event type: `MonEvent_PoolSprayDetected`

**Files**:
- Modified: `pool_tracker.c`, `win11_monitor_public.h`, `telemetry_etw.c`

**Risk**: Low - extends existing infrastructure

---

### Tier 3 (Deferred)

#### A4: Named Pipe Detection
**Status**: DEFERRED to Phase 3

**Rationale**: Minifilter complexity, altitude requirement, performance impact.

**Alternative**: A3 provides lightweight pipe monitoring via `'Pipe'` tag.

---

## Implementation Order

```
Week 1: B2 (Address Masking)
  └─ Isolated module, no dependencies
  └─ Test: Verify all addresses masked in ETW output

Week 2: B3 (Per-Process Rate Limiting)
  └─ Depends on telemetry path
  └─ Test: Verify flood protection works

Week 3: A3 (Extended Pool Tags)
  └─ Extends existing pool_tracker
  └─ Test: WNF spray detection with synthetic allocations
```

---

## New Files Summary

| File | Purpose | LOC Est. |
|------|---------|----------|
| `addr_mask.c` | Address masking implementation | ~80 |
| `addr_mask.h` | Address masking public header | ~50 |
| `rate_limit.c` | Per-process rate limiting | ~150 |
| `rate_limit.h` | Rate limiting public header | ~60 |

---

## API Changes

### New IOCTLs

```c
/* IOCTL_MONITOR_SET_MASK_POLICY - Configure address masking */
#define IOCTL_MONITOR_SET_MASK_POLICY  CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x0D, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/* IOCTL_MONITOR_GET_RATE_STATS - Get per-process rate limit stats */
#define IOCTL_MONITOR_GET_RATE_STATS   CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x0E, METHOD_BUFFERED, FILE_READ_ACCESS)
```

### New Capability Flags

```c
#define WIN11MON_CAP_ADDR_MASKING      0x00000200u  /* B2 */
#define WIN11MON_CAP_PERPROC_RATELIMIT 0x00000400u  /* B3 */
#define WIN11MON_CAP_EXTENDED_TAGS     0x00000080u  /* A3 */
```

### Extended Settings Structure

```c
typedef struct _MONITOR_SETTINGS_V2 {
    ULONG Size;                           /* Must be sizeof(MONITOR_SETTINGS_V2) */
    ULONG EnableMonitoring;
    ULONG EnableTelemetry;
    ULONG EnableEncryption;
    ULONG RateLimitPerSec;
    MON_ADDRESS_MASK_POLICY AddressMaskPolicy;  /* NEW: B2 */
    ULONG PerProcessRateLimitEnabled;           /* NEW: B3 */
    ULONG Reserved[3];
} MONITOR_SETTINGS_V2;
```

---

## Test Contracts

### B2: Address Masking Tests

| Test ID | Description | Expected |
|---------|-------------|----------|
| B2-T01 | MonMaskPolicy_None returns full address | Address unchanged |
| B2-T02 | MonMaskPolicy_Truncate keeps high 16 bits | `0xFFFF800012340000` → `0xFFFF000000000000` |
| B2-T03 | MonMaskPolicy_Hash returns stable hash | Same input → same output |
| B2-T04 | MonMaskPolicy_Zero returns 0 | All addresses → 0 |
| B2-T05 | ETW events use configured policy | Captured events show masked addresses |

### B3: Rate Limiting Tests

| Test ID | Description | Expected |
|---------|-------------|----------|
| B3-T01 | Single process under limit | All events logged |
| B3-T02 | Single process over limit | Events dropped after threshold |
| B3-T03 | Multiple processes isolated | Each has independent limit |
| B3-T04 | Stale entries cleaned | Memory stable over time |
| B3-T05 | High IRQL safety | No deadlock at DISPATCH_LEVEL |

### A3: Extended Tags Tests

| Test ID | Description | Expected |
|---------|-------------|----------|
| A3-T01 | WNF tag detected | `'WNF '` allocations logged |
| A3-T02 | Spray threshold exceeded | Alert emitted at 100 allocs/s |
| A3-T03 | Token tag flagged | `'Toke'` with ALERT_ON_FIND triggers event |

---

## Security Considerations

1. **B2 Default Policy**: `MonMaskPolicy_Hash` prevents address leakage while allowing correlation
2. **B3 Lock Contention**: Use KSPIN_LOCK with minimal hold time; consider lock-free alternatives
3. **A3 False Positives**: Tune spray thresholds based on normal system baseline

---

## Success Criteria

- [ ] All Phase 2 tests pass under Driver Verifier
- [ ] No address leakage with MonMaskPolicy_Hash
- [ ] Rate limiting prevents >1000 events/s from single PID
- [ ] Extended tag monitoring detects synthetic WNF spray
- [ ] Memory stable under 24h stress test

---

## Open Questions

1. Should `MonMaskPolicy_Hash` use full SHA256 or truncated?
   - **Recommendation**: 8-byte truncation (64-bit) sufficient for correlation

2. Rate limit hash table size?
   - **Recommendation**: 256 buckets, LRU eviction

3. WNF spray threshold tuning?
   - **Recommendation**: Start at 100/s, make configurable via IOCTL
