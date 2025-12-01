# Xploit (Windows 11 Monitor Manager) - IoRing Exploitation Detection Driver

## Tech Stack

C | WDM Driver | WDK 10.0 | Windows 11 22H2+ | ETW TraceLogging | x64 Only

## Project Purpose

Xploit is a **Windows 11 kernel-mode security monitoring driver** that detects and prevents privilege escalation exploits abusing Windows 11's I/O Ring API. Developed by ziX Performance Labs (Colin MacRitchie).

**Core Mission:**

- Detect IoRing handle spray patterns indicating exploitation
- Validate RegisteredBuffers arrays against corruption
- Monitor pool allocations for suspicious IOP_MC entries
- Provide structured telemetry for incident response
- Block malicious IoRing operations before execution
- Profile process behavior with anomaly detection and ML feature export

## C Standards & Requirements

This project uses **C17** with Windows kernel-mode extensions. All code must be compatible with WDK 10.0.22621.0+.

### Compiler Settings (enforced via .vcxproj)

- `/W4` warning level
- Spectre mitigation enabled
- `/integritycheck` for process callbacks
- `POOL_NX_OPTIN` for non-executable pool by default

## Coding Style (ziX Labs Standard)

Based on CERT C Secure Coding Standard with security-critical emphasis.

### Philosophy Hierarchy

1. **Security first** - No untrusted pointer dereference without validation
2. **Elegance second** - Code must be immediately understandable to security reviewers
3. **Performance third** - Optimize only when profiling confirms the bottleneck

### File Headers

```c
/*
 * Module Name - Description
 *
 * Author: Colin MacRitchie
 * Organization: ziX Labs - Security Research Division
 * File: [name]
 * Version: X.Y
 * Date: YYYY-MM-DD
 * Copyright: © 2025 ziX Performance Labs. Proprietary.
 *
 * Summary: [Purpose]
 * Threading Model: [Concurrency description]
 *
 * SECURITY PROPERTIES:
 * - Input: [Threat model]
 * - Output: [Safety guarantees]
 * - Memory Safety: [Protections]
 * - IRQL: [Required level]
 */
```

### Function Documentation

```c
/**
 * @function   FunctionName
 * @purpose    One-line purpose
 * @precondition [IRQL/state requirements]
 * @postcondition [Guarantees after execution]
 * @returns    [STATUS codes with meanings]
 * @thread-safety [Lock type and scope]
 * @side-effects [What it modifies]
 */
```

### Naming Conventions

| Type | Pattern | Example |
|------|---------|---------|
| Public functions | `Mon*` prefix | `MonPoolTrackerInitialize` |
| Internal functions | Static, module prefix | `static VOID MonScanDpc(...)` |
| Types/structs | `_UPPER_CASE` internal | `_MONITOR_CONTEXT` |
| Public schemas | `_PUBLIC` suffix | `MON_PROFILE_SUMMARY_PUBLIC` |
| Constants | `MON_*`, `WIN11MON_*` | `WIN11MON_CAP_IORING_ENUM` |
| Pool tags | 4-char reversed | See Pool Tags table |
| IOCTLs | `IOCTL_MONITOR_*` | `IOCTL_MONITOR_GET_VERSION` |

### Pool Tags

| Tag | Constant | Purpose |
|-----|----------|---------|
| `'MnPr'` | `MON_PROFILE_TAG` | Profile allocations |
| `'MnEv'` | `MON_EVENT_TAG` | Event allocations |
| `'MnPl'` | `MON_POOL_TAG` | General allocations |

### Section Dividers

```c
/*--------------------------------------------------------------------------*/
/* Section Name                                                             */
/*--------------------------------------------------------------------------*/
```

## Critical Constraints (NEVER Violate)

- **NEVER** exceed 60 lines per function - Extract helpers if needed (NON-NEGOTIABLE)
- **NEVER** dereference untrusted pointers without SEH (`__try/__except`) guards
- **NEVER** use `METHOD_NEITHER` IOCTLs (CWE-781 prevention)
- **NEVER** return raw kernel addresses to user-mode (use address masking)
- **NEVER** assume structure offsets are constant across Windows builds
- **NEVER** allocate paged memory at IRQL > APC_LEVEL
- **NEVER** hold spinlocks across page faults
- **NEVER** trust user-mode buffer lengths without validation
- **NEVER** use `ProbeForWrite` on read-only buffers
- **NEVER** skip input validation on IOCTL handlers

## Required Patterns (ALWAYS Follow)

- **ALWAYS** keep functions ≤60 lines - This is enforced project-wide
- **ALWAYS** use SAL annotations (`_In_`, `_Out_`, `_IRQL_requires_`, etc.)
- **ALWAYS** validate `Size` field in variable-length structures before trusting
- **ALWAYS** use `METHOD_BUFFERED` for all IOCTLs (safe pointer handling)
- **ALWAYS** guard hostile memory access with SEH
- **ALWAYS** validate addresses are in expected range (user vs kernel)
- **ALWAYS** use interlocked operations for shared counters
- **ALWAYS** check IRQL requirements before calling kernel APIs
- **ALWAYS** use lookaside lists for frequent small allocations
- **ALWAYS** mask kernel addresses before returning to user-mode
- **ALWAYS** rate-limit event emission to prevent DoS
- **ALWAYS** use `ProbeForRead` on user-mode input buffers
- **ALWAYS** reference MITRE ATT&CK techniques in security events (e.g., T1068)

## Threading Model

### Synchronization Primitives by Subsystem

| Subsystem | Lock Type | Rationale |
|-----------|-----------|-----------|
| Profile List | `ERESOURCE` | Reader-writer lock for O(n) list traversal |
| Profile Counters | Interlocked ops | Lock-free updates to individual counters |
| Anomaly Rules | `FAST_MUTEX` | Infrequent modifications, snapshot-based evaluation |
| Event Queue | `SLIST` | Lock-free push at DISPATCH_LEVEL |
| Rate Limiting | Interlocked ops | Per-process atomic counter updates |

### IRQL Requirements

- IOCTL handlers: `PASSIVE_LEVEL`
- Event queue push: `≤ DISPATCH_LEVEL`
- Profile updates: `≤ DISPATCH_LEVEL`
- Telemetry logging: `≤ DISPATCH_LEVEL` (offloads heavy work)

## Key Data Structures

### MON_PROCESS_PROFILE (~400 bytes)

```
├── ProcessId, ProcessName[64]
├── Counters (TotalOperations, ReadCount, WriteCount, etc.)
├── SlidingWindow[60] (1-second slots for ops/sec calculation)
├── AnomalyScore (0-100 with decay)
├── ViolationCount, BurstCount
├── Flags (ELEVATED, SERVICE, NON_INTERACTIVE, BLACKLISTED, etc.)
└── Timestamps (FirstSeen, LastActivity)
```

### MON_ML_FEATURE_VECTOR (96 bytes)

```
├── 12 normalized float features (OpsPerSecond, HandleCount, etc.)
├── 4 categorical features (Elevation, Interactive, Service, Score)
└── Label field for supervised learning
```

## Built-in Anomaly Rules

| Rule ID | Name | Default Threshold | MITRE | Severity |
|---------|------|-------------------|-------|----------|
| 1 | HighOpsFrequency | 1000 ops/5sec | T1499 | Medium |
| 2 | LargeBufferRegistration | 100MB | T1068 | Medium |
| 3 | RapidHandleCreation | 10 handles/sec | T1499 | Low |
| 4 | ElevatedIoRingAbuse | N/A | T1548 | High |
| 5 | BurstPattern | 500 ops burst | T1499 | Medium |
| 6 | ConcurrentTargets | 50 files/60sec | T1083 | Medium |
| 7 | ViolationAccumulation | 5 violations | T1068 | High |

## Common Pitfalls

### Memory Safety

- Accessing paged memory at DISPATCH_LEVEL causes BSOD
- Integer overflow in buffer size calculations enables exploitation
- Missing SEH on hostile pointer dereference causes driver crash

### IOCTL Handling

- Trusting `InputBufferLength` without validation enables overflow
- Using `METHOD_NEITHER` exposes raw user-mode pointers
- Missing alignment checks on structure access causes traps

### Synchronization

- Holding ERESOURCE across page faults causes deadlock
- Using KSPIN_LOCK for long operations causes DPC starvation
- Missing interlocked ops on shared counters causes race conditions

### Windows Version Compatibility

- Structure offsets vary by Windows build (use runtime resolution)
- IoRing API behavior differs between 22H2/23H2/24H2
- Pool tag monitoring may miss new allocation patterns

## Project Structure

```
d:\Xploit\
├── src/
│   ├── core/                         # Core driver module
│   │   ├── win11_monitor_mgr.c       # Main driver entry, IOCTL dispatch (~1700 lines)
│   │   ├── win11_monitor_mgr.h       # Driver context structures
│   │   ├── monitor_internal.h        # Kernel-only internal structures
│   │   └── telemetry.c               # Core event logging
│   │
│   ├── detection/                    # Detection subsystems
│   │   ├── pool_tracker.c            # Pool allocation scanning
│   │   ├── iop_mc.h                  # IOP_MC buffer entry structures
│   │   ├── iop_mc_layout.h           # IOP_MC layout definitions
│   │   ├── ioring_enum.c/h           # IoRing handle enumeration (A1)
│   │   ├── regbuf_integrity.c/h      # RegisteredBuffers validation (A2)
│   │   ├── ioring_intercept.c/h      # Pre-submit SQE validation (Phase 6)
│   │   ├── cross_process.c/h         # Cross-process detection (Phase 9)
│   │   └── handle_correlator.c       # Handle enumeration, hash table grouping
│   │
│   ├── profiling/                    # Behavioral analysis
│   │   ├── process_profile.c/h       # Profile lifecycle, sliding window ops/sec
│   │   └── anomaly_rules.c/h         # 7 built-in rules, MITRE ATT&CK mapping
│   │
│   ├── memory/                       # Memory monitoring (Phase 8)
│   │   ├── mem_monitor.c/h           # MDL tracking, memory anomaly detection
│   │   └── vad_walker.c              # VAD tree traversal, runtime offset resolution
│   │
│   ├── telemetry/                    # Telemetry subsystems
│   │   ├── telemetry_etw.c/h         # ETW TraceLogging provider (B1)
│   │   └── telemetry_ringbuf.c/h     # Lock-free ring buffer (E1)
│   │
│   └── util/                         # Utility modules
│       ├── addr_mask.c/h             # Kernel address masking (B2)
│       ├── offset_resolver.c/h       # Runtime offset detection (C1)
│       └── rate_limit.c              # Per-process rate limiting (B3)
│
├── include/                          # Public API headers
│   └── win11_monitor_public.h        # Public IOCTL contracts (~600 lines)
│
├── tests/                            # Unit tests
│   ├── test_harness.c                # In-kernel test framework
│   ├── test_intercept.c              # Phase 6 unit tests
│   ├── test_profile.c                # Phase 7 unit tests
│   ├── test_memory.c                 # Phase 8 unit tests
│   └── test_xprocess.c               # Phase 9 unit tests
│
├── client/                           # User-mode client library
│   ├── win11mon_client.c/h           # Base client API
│   ├── win11mon_intercept.c/h        # IAT hooks for NtSubmitIoRing
│   ├── win11mon_profile.c/h          # Profile/anomaly client APIs
│   ├── win11mon_memory.c/h           # Memory monitoring client APIs
│   └── win11mon_xprocess.c/h         # Cross-process detection client APIs
│
├── Win11MonitorMgr/                  # Visual Studio project
│   └── Win11MonitorMgr.vcxproj
│
├── tools/                            # Build tools
│   └── layout_gen/                   # Structure layout generator
│
└── docs/                             # Documentation
    ├── ziX-labs-c-style.md           # Coding standards
    ├── enhancement_plan_v2_full_spec.md
    └── PLAN_phase*.md                # Phase implementation plans
```

## Build Commands

```bash
# Build Debug (Visual Studio Developer Command Prompt)
msbuild Win11MonitorMgr\Win11MonitorMgr.vcxproj /p:Configuration=Debug /p:Platform=x64

# Build Release
msbuild Win11MonitorMgr\Win11MonitorMgr.vcxproj /p:Configuration=Release /p:Platform=x64

# Clean build
msbuild Win11MonitorMgr\Win11MonitorMgr.vcxproj /t:Clean /p:Configuration=Debug /p:Platform=x64
```

### Output Locations

- Debug: `x64\Debug\win11_monitor_mgr.sys`
- Release: `x64\Release\win11_monitor_mgr.sys`

### Driver Installation (Test Mode)

```cmd
# Enable test signing
bcdedit /set testsigning on

# Install driver
sc create Win11MonitorMgr type= kernel binPath= "C:\path\to\win11_monitor_mgr.sys"
sc start Win11MonitorMgr

# Stop and remove
sc stop Win11MonitorMgr
sc delete Win11MonitorMgr
```

## IOCTL Interface

### Device Identity

- Device Name: `\Device\Win11MonitorMgr`
- Symbolic Link: `\DosDevices\Win11MonitorMgr`
- User-mode Path: `\\.\Win11MonitorMgr`

### IOCTL Layout

```
Base: 0x800

Core:                0x00-0x09
Enhancement:         0x0A-0x0F
Ring Buffer (E1):    0x10-0x13
Interception (Ph6):  0x20-0x28
Profile (Ph7):       0x30-0x36
Anomaly (Ph7):       0x38-0x3C
Memory (Ph8):        0x40-0x44
Cross-Process (Ph9): 0x50-0x57
```

### Core IOCTLs (0x00-0x09)

| IOCTL | Purpose |
|-------|---------|
| `IOCTL_MONITOR_GET_VERSION` | Query driver version |
| `IOCTL_MONITOR_GET_CAPABILITIES` | Query supported features |
| `IOCTL_MONITOR_ENABLE/DISABLE` | Control monitoring |
| `IOCTL_MONITOR_GET_STATS` | Query detection statistics |
| `IOCTL_MONITOR_FETCH_EVENTS` | Read event queue |
| `IOCTL_MONITOR_SCAN_NOW` | Trigger immediate scan |

### Enhancement IOCTLs

| IOCTL Range | Feature | Purpose |
|-------------|---------|---------|
| `0x0A-0x0F` | A1-C1 | IoRing enum, offsets, masking, rate stats |
| `0x10-0x13` | E1 | Ring buffer configure/snapshot/stats/clear |
| `0x20-0x28` | Phase 6 | Intercept validate/policy/stats/blacklist |
| `0x30-0x36` | Phase 7 | Profile get/list/export/stats/config/reset |
| `0x38-0x3C` | Phase 7 | Anomaly rules/threshold/enable/stats/reset |
| `0x40-0x44` | Phase 8 | Memory VAD/MDL/physical/sharing/stats |
| `0x50-0x57` | Phase 9 | Cross-process shared/tree/sections/alerts/stats/config |

## Capability Flags

```c
WIN11MON_CAP_IOP_MC              0x00000001u   /* Base: IOP_MC detection */
WIN11MON_CAP_POOL_TRACK          0x00000002u   /* Base: Pool tracking */
WIN11MON_CAP_TELEMETRY           0x00000004u   /* Base: Event logging */
WIN11MON_CAP_RATE_LIMIT          0x00000008u   /* Base: Rate limiting */
WIN11MON_CAP_IORING_ENUM         0x00000020u   /* A1: IoRing enumeration */
WIN11MON_CAP_REGBUF_INTEGRITY    0x00000040u   /* A2: RegBuffers validation */
WIN11MON_CAP_ETW_PROVIDER        0x00000100u   /* B1: ETW TraceLogging */
WIN11MON_CAP_ADDR_MASKING        0x00000200u   /* B2: Address masking */
WIN11MON_CAP_PERPROC_RATELIMIT   0x00000400u   /* B3: Per-process limiting */
WIN11MON_CAP_RUNTIME_OFFSETS     0x00000800u   /* C1: Runtime offset resolution */
WIN11MON_CAP_ATTACK_TAGGING      0x00001000u   /* D1: MITRE ATT&CK tagging */
WIN11MON_CAP_RING_BUFFER         0x00002000u   /* E1: Ring buffer telemetry */
WIN11MON_CAP_IORING_INTERCEPT    0x00004000u   /* Phase 6: IoRing interception */
WIN11MON_CAP_PROCESS_PROFILE     0x00008000u   /* Phase 7: Process profiling */
WIN11MON_CAP_ANOMALY_RULES       0x00010000u   /* Phase 7: Anomaly rule engine */
WIN11MON_CAP_MEM_MONITOR         0x00020000u   /* Phase 8: Memory monitoring */
WIN11MON_CAP_CROSS_PROCESS       0x00040000u   /* Phase 9: Cross-process detection */
```

## Security Architecture

### Threat Model

- **All user-mode data is hostile** until validated
- All kernel pointers are untrusted unless verified in correct address range
- Structure offsets may vary by Windows build
- Attackers may attempt to corrupt kernel memory via IoRing

### Defense Layers

1. **Input Validation**: Strict SIZE checks, address range validation, magic verification
2. **Memory Safety**: SEH guards, ProbeForRead/Write, integer overflow checks
3. **Information Disclosure Prevention**: Address masking (Hash/Truncate/Zero policies)
4. **DoS Prevention**: Per-process and global rate limiting
5. **Behavioral Detection**: Process profiling with anomaly scoring

### Address Masking Policies

| Policy | Description | Use Case |
|--------|-------------|----------|
| `MonMaskPolicy_None` | No masking (debug only) | Development |
| `MonMaskPolicy_Truncate` | Keep high 16 bits | Debugging |
| `MonMaskPolicy_Hash` | SipHash transformation | **Production (default)** |
| `MonMaskPolicy_Zero` | Complete removal | Maximum security |

## Implementation Workflow

When implementing a new phase:

1. **Read the phase plan** in `docs/PLAN_phaseN_*.md`
2. **Create header file first** with all structures and API declarations
3. **Create implementation file** following the 60-line rule
4. **Create client APIs** (user-mode wrappers in `client/`)
5. **Update win11_monitor_public.h** with IOCTLs and public schemas (use `_PUBLIC` suffix)
6. **Integrate into win11_monitor_mgr.c**:
   - Add include
   - Add forward declarations for IOCTL handlers
   - Add init call in `DriverEntry`
   - Add shutdown call in `MonDriverUnload` (reverse order)
   - Add IOCTL dispatch cases
   - Update capability reporting
7. **Create unit tests** in `test_*.c`

## Testing

### In-Kernel Test Harness

Tests use `DbgPrintEx` for output and are kernel-mode compatible (no user-mode CRT):

- `IOCTL_TH_RUN_BASIC` - Basic functionality tests
- `IOCTL_TH_TEST_OFFSET_STATUS` - Offset resolution tests
- `IOCTL_TH_TEST_REGBUF_VALID` - RegBuffer validation tests
- `IOCTL_TH_TEST_ETW_EMIT` - ETW provider tests
- `IOCTL_TH_TEST_RATE_LIMIT` - Rate limiting tests
- `IOCTL_TH_TEST_RING_BUFFER` - Ring buffer tests

### Driver Verifier

Enable Driver Verifier with flags `0x9BB` for comprehensive testing:

```cmd
verifier /standard /driver win11_monitor_mgr.sys
```

## Documentation Index

| Document | Purpose |
|----------|---------|
| `docs/ziX-labs-c-style.md` | Coding standards (CERT C based) |
| `docs/enhancement_plan_v2_full_spec.md` | Complete feature specification |
| `docs/PLAN_phase6_ioring_interception.md` | SQE validation design |
| `docs/PLAN_phase7_process_profiling.md` | Behavioral analysis |
| `docs/PLAN_phase8_memory_monitoring.md` | Memory region tracking |
| `docs/PLAN_phase9_cross_process.md` | Cross-process detection |
| `PLAN_phase10_kernel_callbacks.md` | Kernel notification integration |
| `PLAN_phase11_forensic_export.md` | DFIR export capabilities |

## Development Status

**Version:** 1.6 (as of 2025-11-30)
**Current Phase:** Phase 9 Complete - Ready for Phase 10

| Phase | Feature | Status |
|-------|---------|--------|
| 1-5 | Core infrastructure (pool, IOP_MC, telemetry, ETW, rate limiting) | Complete |
| A1 | IoRing enumeration | Complete |
| A2 | RegBuffers validation | Complete |
| B1 | ETW TraceLogging provider | Complete |
| B2 | Address masking | Complete |
| B3 | Per-process rate limiting | Complete |
| C1 | Runtime offset resolution | Complete |
| E1 | Ring buffer telemetry | Complete |
| 6 | IoRing interception (pre-submit validation, blacklist, policy) | Complete |
| 7 | Process profiling (anomaly detection, ML export) | Complete |
| 8 | Memory monitoring (VAD walking, MDL tracking, anomaly detection) | Complete |
| 9 | Cross-process detection (IoRing sharing, handle correlation, risk scoring) | Complete |
| 10 | Kernel callbacks | Planning |
| 11 | Forensic export | Planning |

## References

- **IoRing Structures**: yardenshafir/IoRing_Demos
- **MITRE ATT&CK**: T1068 (Exploitation), T1499 (DoS), T1548 (Abuse Elevation), T1083 (Discovery)

---

*Security-first kernel driver for Windows 11 IoRing exploitation detection. Validate all inputs. Trust nothing. 60 lines max.*
