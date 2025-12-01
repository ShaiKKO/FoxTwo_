# Windows 11 IoRing / Pool Monitoring Sensor – Task Plan

## Overview

This document tracks the full task breakdown to evolve the existing Windows 11 kernel monitoring driver into a production-ready IoRing / pool anomaly sensor with a user-mode controller, telemetry, testing, and packaging.

---

## EXECUTIVE SUMMARY

- **Project/Feature**: Windows 11 IoRing / pool anomaly monitoring sensor (kernel driver + user-mode controller + telemetry)
- **Total estimated effort**: ~90 hours (~11–12 full-time days)
- **Team size (assumed)**: 1–2 engineers
- **Timeline**: T0 (now) → T0 + ~3 weeks (at ~30 h/week)
- **Risk level**: **HIGH** (kernel-mode code, security sensor, OS coupling)
- **Number of tasks**: 15 core tasks (2–8 hours each)

---

## MAJOR WORK STREAMS

### Work Stream 1: Kernel Sensor Finalization (KM)

- **Total effort**: ~22 hours  
- **Task count**: 4 (1.1, 1.2, 2.1, 4.2)
- **Key deliverables**:
  - Stable IOCTL contract & schemas.
  - Finalized detection policies & violation taxonomy.
  - Verified MC/pool analysis paths (including edge cases).
  - Verified no leaks/races under stress.

### Work Stream 2: User-Mode Controller & API (UM)

- **Total effort**: ~30 hours  
- **Task count**: 5 (1.3, 1.4, 2.2, 2.3, 3.2)

### Work Stream 3: Telemetry & Observability

- **Total effort**: ~18 hours  
- **Task count**: 3 (1.2, 2.4, 4.3)

### Work Stream 4: Testing & Validation

- **Total effort**: ~14 hours  
- **Task count**: 3 (3.1, 4.1, 5.1)

### Work Stream 5: Packaging & Documentation

- **Total effort**: ~16 hours  
- **Task count**: 3 (3.3, 5.2, 5.3)

---

## DETAILED TASKS

### PHASE 1: FOUNDATION [~16 hours]

#### Task 1.1: Finalize Kernel IOCTL & Data Contracts

- **Owner**: Kernel Engineer
- **Estimate**: 4 hours (Confidence: 0.8)
- **Dependencies**: Existing KM code (`win11_monitor_mgr.c/.h`, `iop_mc.h`)
- **Complexity**: MEDIUM
- **Risk**: MEDIUM
- **Description**:
  - Review all IOCTLs and their structures (settings, stats, events, MC parse).
  - Ensure SAL annotations, alignment, and versioning comments are consistent.
  - Decide on any last breaking changes now, and freeze the public contract.
- **Acceptance Criteria**:
  - [ ] IOCTLs documented in header + comments consistent with behavior.
  - [ ] No ambiguous or overlapping fields; versioning story written.
  - [ ] Build passes; `test_harness.c` compiles against final headers.
  - [ ] No TODOs left in KM surface regarding contracts.

---

#### Task 1.2: Define Telemetry Event Schema & Severity Model

- **Owner**: Principal Engineer (KM + Telemetry)
- **Estimate**: 4 hours (Confidence: 0.7)
- **Dependencies**: Task 1.1 (event structure fields).
- **Complexity**: MEDIUM
- **Risk**: MEDIUM
- **Description**:
  - Enumerate event types (MC violation types, pool anomalies, internal failures).
  - For each, define:
    - Schema (fields, types, masking rules).
    - Severity (info/warn/alert).
    - Cardinality (how often we expect it).
- **Acceptance Criteria**:
  - [ ] Event schema documented in one place (header or markdown).
  - [ ] All KM emission points mapped to this schema.
  - [ ] Address masking rules clearly defined (which fields, when).

##### Telemetry Schema (Current Design)

- **Event Envelope** (`EVENT_BLOB`)
  - `Size` (ULONG): `sizeof(EVENT_BLOB) + PayloadLength`.
  - `Type` (MONITOR_EVENT_TYPE): logical event type.
  - `PayloadLength` (ULONG): bytes in `Payload`.
  - `Payload` (UCHAR[]): type-specific structure.

- **Event Types & Payloads**
  - `MonEvent_IopMcDetected` (informational MC entry detection)
    - Payload: `IOP_MC_BUFFER_ENTRY_INFO` from `iop_mc.h`.
    - Semantics: MC entry validated; no cross-VM anomaly detected.
    - Severity: treated as **Info (1)** by consumers.
    - Privacy: `Address` is a kernel pointer; **must be masked/hashed** before leaving trusted context.

  - `MonEvent_CrossVmDetected` (critical cross-VM / user-range MC detection)
    - Payload: `CROSS_VM_EVENT_INFO`.
    - Fields: `Size`, `Type`, `ProcessId`, `ThreadId`, `PoolTag`, `Severity`, `SuspectAddress`, `Reserved`.
    - Semantics: MC entry validates but `Address < MmHighestUserAddress`.
    - Severity: **5 (critical)** set in payload.
    - Privacy: `SuspectAddress` is sensitive; **log numeric but mask/hash by default** in UM sinks.

  - `MonEvent_Anomaly` (IoRing reg-array anomaly)
    - Payload: `CROSS_VM_EVENT_INFO`.
    - Semantics: IoRing registered buffer array contains a user VA.
    - Severity: **3 (medium)** set in payload.
    - Privacy: same handling as `CrossVmDetected`.

  - `MonEvent_PoolAllocation` (future)
    - Payload: `POOL_ALLOCATION_EVENT_INFO` (TBD).
    - Semantics: interesting/suspicious pool allocation (tag/size based).
    - Severity: **2–4** depending on heuristics (to be defined during Task 2.1).

  - `MonEvent_PolicyViolation` (future)
    - Payload: `POLICY_VIOLATION_EVENT_INFO` (TBD).
    - Semantics: explicit policy rule violation (aggregated signals).
    - Severity: **3–5** depending on policy.

- **Severity Handling**
  - Severity is **explicit** for `CROSS_VM_EVENT_INFO`-backed events via the `Severity` field.
  - MC-entry informational events (`MonEvent_IopMcDetected`) do not carry an in-struct severity; user-mode consumers treat them as **Info (1)** by convention.
  - Future payloads (pool allocation, policy violation) must include a `Severity` field to keep severity encoding within the payload shape.

- **Address Masking Rules**
  - All pointer-like fields (`Address`, `SuspectAddress`) are numeric and treated as **sensitive**.
  - Kernel telemetry may enqueue raw numeric values for internal analysis.
  - Any user-mode sink (ETW/log/file) must:
    - Mask or hash addresses by default in production.
    - Only expose raw addresses in tightly controlled lab builds.

---

#### Task 1.3: Design User-Mode Controller Architecture

- **Owner**: User-Mode Engineer
- **Estimate**: 4 hours (Confidence: 0.7)
- **Dependencies**: Task 1.1 (stable IOCTL list).
- **Complexity**: MEDIUM
- **Risk**: LOW
- **Description**:
  - Decide shape of UM controller:
    - Single CLI binary vs service + CLI.
    - Command set (enable, disable, scan-now, get-stats, tail-events).
  - Define layering:
    - `monitor_client.lib` (thin IOCTL wrapper).
    - `monitor_ctl.exe` (CLI or service).
- **Acceptance Criteria**:
  - [ ] Short design doc (or README) with architecture and command list.
  - [ ] IOCTL mapping table from CLI/service to driver calls.
  - [ ] No contradictions with KM contracts.

---

#### Task 1.4: Set Up UM Repo Structure & Build System

- **Owner**: User-Mode Engineer
- **Estimate**: 4 hours (Confidence: 0.9)
- **Dependencies**: Task 1.3 (design).
- **Complexity**: LOW
- **Risk**: LOW
- **Description**:
  - Create UM project structure (e.g., `user\client`, `user\tools`).
  - Add build scripts (MSBuild/CMake/nmake) and integrate with existing repo.
- **Acceptance Criteria**:
  - [ ] UM code builds on dev machine with a single command.
  - [ ] Includes reference to shared headers (`win11_monitor_mgr.h`) safely.

---

### PHASE 2: CORE IMPLEMENTATION [~26 hours]

#### Task 2.1: Implement Remaining Kernel Detection & Telemetry Refinements

- **Owner**: Kernel Engineer
- **Estimate**: 6 hours (Confidence: 0.7)
- **Dependencies**: Tasks 1.1, 1.2.
- **Complexity**: HIGH
- **Risk**: HIGH
- **Description**:
  - Ensure all `IOP_MC_VIOL_*` cases are plumbed into telemetry/statistics.
  - Confirm pool tracker hook coverage (tags, edge cases).
  - Tune rate limiting thresholds; ensure no unbounded queue growth.
- **Acceptance Criteria**:
  - [ ] Every violation type can be forced via harness/test and observed in telemetry.
  - [ ] No KM crashes when parsing malformed/attacker-controlled MC entries.
  - [ ] Telemetry queue remains bounded under stress.

---

#### Task 2.2: Implement User-Mode Driver Binding Library (`monitor_client`)

- **Owner**: User-Mode Engineer
- **Estimate**: 6 hours (Confidence: 0.8)
- **Dependencies**: Tasks 1.1, 1.4.
- **Complexity**: MEDIUM
- **Risk**: MEDIUM
- **Description**:
  - Implement thin wrapper APIs around IOCTLs:
    - `MonOpen`, `MonClose`, `MonEnable`, `MonDisable`, `MonScanNow`, `MonGetStats`, `MonFetchEvents`, `MonParseMcEntry`.
  - Handle common errors (device not present, access denied).
- **Acceptance Criteria**:
  - [ ] Library builds and links into sample program.
  - [ ] Each public wrapper returns meaningful NTSTATUS/Win32 error.
  - [ ] Basic smoke test (enable → scan → fetch-events) works end-to-end.

---

#### Task 2.3: Implement User-Mode Controller (CLI/Service)

- **Owner**: User-Mode Engineer
- **Estimate**: 8 hours (Confidence: 0.7)
- **Dependencies**: Task 2.2.
- **Complexity**: MEDIUM
- **Risk**: MEDIUM
- **Description**:
  - Implement commands, e.g.:
    - `monitorctl enable --telemetry --scan-interval=N`
    - `monitorctl scan-now`
    - `monitorctl stats`
    - `monitorctl tail-events [--follow]`
  - Handle configuration file or CLI flags.
- **Acceptance Criteria**:
  - [ ] CLI/service binary builds and can drive all IOCTLs.
  - [ ] Clear non-zero exit codes on failures.
  - [ ] Help output documents all commands/flags.

---

#### Task 2.4: Implement Telemetry Sink (ETW or Log Files)

- **Owner**: Telemetry Engineer (UM/KM)
- **Estimate**: 6 hours (Confidence: 0.6)
- **Dependencies**: Task 1.2 (schema), Task 2.2 (event access).
- **Complexity**: MEDIUM
- **Risk**: MEDIUM
- **Description**:
  - Decide primary sink (ETW provider vs structured file logs).
  - Implement event rendering (JSON/structured text) from `MON_EVENT_BLOB`s.
  - Optionally register ETW provider and emit events.
- **Acceptance Criteria**:
  - [ ] Events from driver are visible via chosen sink (ETW viewer or logs).
  - [ ] Address masking applied per policy for user-visible data.
  - [ ] No uncontrolled log volume under expected workloads.

---

### PHASE 3: INTEGRATION [~14 hours]

#### Task 3.1: End-to-End Integration Tests (KM + UM)

- **Owner**: QA / Principal Engineer
- **Estimate**: 6 hours (Confidence: 0.7)
- **Dependencies**: 2.1, 2.2, 2.3, 2.4.
- **Complexity**: MEDIUM
- **Risk**: MEDIUM
- **Description**:
  - Implement scripted flows:
    - Enable monitor → run synthetic scenarios (using current `test_harness` + UM tool) → verify telemetry.
    - Malicious vs benign MC entries produce expected results.
  - Record expected output baselines.
- **Acceptance Criteria**:
  - [ ] Automated script can run full end-to-end scenario on test VM.
  - [ ] Positive and negative cases behave exactly as designed.
  - [ ] Script fails loudly on unexpected behavior.

---

#### Task 3.2: Harden Configuration & Error Handling

- **Owner**: Principal Engineer
- **Estimate**: 4 hours (Confidence: 0.8)
- **Dependencies**: 2.2, 2.3.
- **Complexity**: MEDIUM
- **Risk**: MEDIUM
- **Description**:
  - Ensure UM controller validates input (e.g., intervals, flags).
  - Implement robust handling of:
    - Driver unavailable.
    - Partial telemetry reads.
    - Retry/backoff on transient failures.
- **Acceptance Criteria**:
  - [ ] Fuzz or simple randomized inputs do not crash or wedge KM or UM.
  - [ ] Clear error messages for common operator mistakes.

---

#### Task 3.3: Implement Secure Defaults & Configuration Mechanism

- **Owner**: Principal Engineer
- **Estimate**: 4 hours (Confidence: 0.7)
- **Dependencies**: 1.2, 2.3, 2.4.
- **Complexity**: MEDIUM
- **Risk**: MEDIUM
- **Description**:
  - Decide default settings (telemetry on/off, masking on, rate limits).
  - Implement configuration source:
    - Simple config file or registry values consumed by UM tool/service.
- **Acceptance Criteria**:
  - [ ] Installing and running with no config yields safe, reasonable defaults.
  - [ ] Config changes can be applied without reboot (where possible).

---

### PHASE 4: REFINEMENT [~16 hours]

#### Task 4.1: Performance & Stress Testing

- **Owner**: Perf/QA Engineer
- **Estimate**: 6 hours (Confidence: 0.6)
- **Dependencies**: 3.1.
- **Complexity**: HIGH
- **Risk**: HIGH
- **Description**:
  - Stress MC parsing and pool scanning via harness.
  - Measure CPU overhead, memory usage, queue length behavior.
  - Identify and optimize hot paths.
- **Acceptance Criteria**:
  - [ ] Documented perf results under defined workloads.
  - [ ] No unbounded growth in telemetry queues or memory usage.
  - [ ] Tuning knobs (intervals, limits) validated.

---

#### Task 4.2: Memory & Race Auditing (VERIFIER, Stress Harness)

- **Owner**: Kernel Engineer
- **Estimate**: 6 hours (Confidence: 0.6)
- **Dependencies**: 2.1, 3.1.
- **Complexity**: HIGH
- **Risk**: HIGH
- **Description**:
  - Run Driver Verifier and other tools to detect leaks, pool misuse, IRQL misuse.
  - Validate SLIST/queue correctness under heavy concurrent events.
- **Acceptance Criteria**:
  - [ ] No high-severity issues from Verifier or similar tools.
  - [ ] Documented rationale for ignored low-priority warnings.

---

#### Task 4.3: Observability & Log-Level Tuning

- **Owner**: Principal Engineer
- **Estimate**: 4 hours (Confidence: 0.8)
- **Dependencies**: 2.4, 3.2, 3.3.
- **Complexity**: LOW
- **Risk**: LOW
- **Description**:
  - Ensure coherent log levels (debug vs info vs warn vs error).
  - Provide simple mechanism to toggle verbosity.
- **Acceptance Criteria**:
  - [ ] Production build yields minimal but sufficient logs.
  - [ ] Debug builds aid investigation without overwhelming.

---

### PHASE 5: VALIDATION & PACKAGING [~18 hours]

#### Task 5.1: Integrate Tests into Lightweight CI Script

- **Owner**: QA / Tools Engineer
- **Estimate**: 4 hours (Confidence: 0.8)
- **Dependencies**: 3.1, 4.1.
- **Complexity**: MEDIUM
- **Risk**: MEDIUM
- **Description**:
  - Create script (PowerShell or similar) that builds KM + UM.
  - Run integration/perf tests where feasible in a dev/test environment.
- **Acceptance Criteria**:
  - [ ] Single command performs build + tests in dev environment.
  - [ ] Clear pass/fail semantics.

---

#### Task 5.2: Packaging (INF, Install/Uninstall, Signing Story)

- **Owner**: Principal Engineer
- **Estimate**: 6 hours (Confidence: 0.7)
- **Dependencies**: 1.1, 2.3.
- **Complexity**: MEDIUM
- **Risk**: HIGH
- **Description**:
  - Create INF for driver.
  - Provide install script/instructions (test signing vs production).
- **Acceptance Criteria**:
  - [ ] Driver can be installed/uninstalled on a fresh test VM following docs.
  - [ ] Any signing requirements documented and tested (test cert).

---

#### Task 5.3: Documentation (Ops + Developer)

- **Owner**: Principal Engineer
- **Estimate**: 8 hours (Confidence: 0.7)
- **Dependencies**: All previous tasks.
- **Complexity**: MEDIUM
- **Risk**: MEDIUM
- **Description**:
  - Operator docs:
    - How to install/uninstall.
    - How to configure and run.
    - How to interpret telemetry & severity.
  - Developer docs:
    - IOCTL contracts and schemas.
    - Extension points and constraints.
- **Acceptance Criteria**:
  - [ ] README/Guide enabling a new engineer to bring up the system.
  - [ ] Operator can install and run based solely on docs.

---

## DEPENDENCY MATRIX (Summary)

See main conversation plan for the detailed matrix; high-level:

- 1.1 → 1.2, 1.3, 2.1, 5.2
- 1.2 → 2.1, 2.4, 3.3
- 1.3 → 1.4
- 1.4 → 2.2
- 2.1 → 3.1, 4.2
- 2.2 → 2.3, 2.4, 3.1
- 2.3 → 3.2, 3.3, 5.2
- 2.4 → 3.1, 3.3, 4.3
- 3.1 → 4.1, 4.2, 5.1
- 3.3, 4.2, 4.3 → 5.3

---

## MILESTONES

- **Milestone 1: Foundation Complete** – Tasks 1.1–1.4
- **Milestone 2: Core Features Complete** – Tasks 2.1–2.4
- **Milestone 3: Integrated & Hardened** – Tasks 3.1–3.3, 4.1–4.3
- **Milestone 4: Ready for Use** – Tasks 5.1–5.3
