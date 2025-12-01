# Windows 11 Monitor Manager Enhancement Plan

## Executive Summary

This document proposes a prioritized set of enhancements for the Windows 11 Monitor Manager kernel driver, derived from:
- Comprehensive review of existing documentation (`monitor_tasks_plan.md`, `ABI-Drift-Haardening-Research.md`, `Enchancement_research.md`, `ziX-labs-c-style.md`)
- Analysis of current implementation gaps
- Research into current IoRing exploitation techniques and EDR best practices (2024-2025)
- Alignment with ziX Labs security-first philosophy

**Key Insight from Research**: The IoRing technique is increasingly used in real-world exploits (CVE-2025-21333, CVE-2024-35250, Pwn2Own 2024/2025) because it leaves "very little visibility and few forensic traces" - I/O rings have nearly no ETW visibility except on creation. This validates the project's core mission and informs our enhancement priorities.

---

## Enhancement Categories

### Category A: Detection Capability Enhancements (High Priority)
Directly improve the sensor's ability to detect IoRing-based attacks.

### Category B: Telemetry & Observability (High Priority)
Per `Enchancement_research.md`: "ETW provides Microsoft's general-purpose, high-speed tracing facility" and is the industry standard for kernel security monitoring.

### Category C: ABI Drift Hardening (Medium Priority)
Per `ABI-Drift-Haardening-Research.md`: "Microsoft provides no formal ABI stability guarantees for Windows kernel structures."

### Category D: Integration & Interoperability (Medium Priority)
Enable consumption by SIEM/XDR platforms per `Enchancement_research.md` integration standards.

### Category E: Testing & Validation (Ongoing)
Aligned with `monitor_tasks_plan.md` Phase 4 (Refinement) and Phase 5 (Validation).

---

## Detailed Enhancement Proposals

### A1: IORING_OBJECT Handle Monitoring

**Rationale**: Research confirms attackers use `NtQuerySystemInformation(SystemHandleInformation)` to leak IORING_OBJECT kernel addresses as a KASLR bypass. Monitoring handle creation provides visibility at the earliest exploitation stage.

**Implementation**:
- Register `ObRegisterCallbacks` for IORING_OBJECT type
- Log: ProcessId, ThreadId, HandleValue, GrantedAccess, ObjectAddress
- Flag: Excessive IORING_OBJECT handle creation from single process
- Flag: Handles created by unusual processes (non-standard I/O patterns)

**Alignment**:
- `Enchancement_research.md` §Kernel callback mechanisms: "Object callbacks via ObRegisterCallbacks monitor handle operations"
- Fills gap: "I/O rings have nearly no visibility through ETW except on creation"

**Complexity**: MEDIUM | **Risk**: MEDIUM | **Effort**: 6-8 hours

---

### A2: RegBuffers Pointer Integrity Monitoring

**Rationale**: The IoRing exploit primitive works by corrupting `IORING_OBJECT->RegBuffers` to point to attacker-controlled memory. Detecting this corruption is the most direct countermeasure.

**Implementation**:
- Periodically validate `RegBuffers` pointer is in kernel address space
- Cross-check `RegBuffersCount` against allocated array size
- Detect: RegBuffers pointing to user-mode VA (attack signature)
- Detect: RegBuffersCount incremented without corresponding allocation

**Technical Notes**:
- `IORING_OBJECT` structure is in public symbols (per research)
- Access via existing pool scanning infrastructure (`pool_tracker.c`)
- Extend `MonAnalyzeIoRingRegArray` to validate pointer origin

**Alignment**:
- Core project mission per `iop_mc.h`: "Cross-VM detection techniques"
- `ziX-labs-c-style.md`: "Assume all inputs are hostile until proven safe"

**Complexity**: HIGH | **Risk**: HIGH | **Effort**: 10-12 hours

---

### A3: Additional Pool Tag Monitoring

**Rationale**: Current implementation only monitors `'IrRB'` (IoRing Registered Buffer). Expanding coverage provides broader visibility into related attack surfaces.

**Proposed Tags**:

| Tag | Description | Security Relevance |
|-----|-------------|-------------------|
| `IoRg` | IORING_OBJECT allocations | Primary exploitation target |
| `MdlP` | MDL Pool allocations | MDL manipulation attacks |
| `WNF ` | WNF State Data | Used in CVE-2025-21333 heap spray |
| `Pipe` | Named Pipe structures | Used for IoRing I/O operations (less forensic traces than files) |
| `Toke` | Token objects | Privilege escalation target |

**Implementation**:
- Refactor `pool_tracker.c` to accept configurable tag list
- Add per-tag analysis callbacks
- Implement tag-specific heuristics (e.g., WNF spray detection)

**Alignment**:
- `Enchancement_research.md` §Pool tag quick scanning: "Pool tag scanning...enables investigators to discover evidence of artifacts"
- Extensibility for future threat vectors

**Complexity**: MEDIUM | **Risk**: LOW | **Effort**: 6-8 hours

---

### A4: Named Pipe I/O Detection for IoRing

**Rationale**: Research confirms: "Named pipes can be used instead of files, which is less visible and leaves no traces on disk." Attackers prefer pipes for IoRing read/write primitives.

**Implementation**:
- Monitor NPFS (Named Pipe File System) operations associated with IORING_OBJECT handles
- Correlate: IoRing handle + unusual pipe activity = potential exploitation
- Log: Pipe name, direction (read/write), byte count, associated IoRing

**Alignment**:
- Direct countermeasure to documented evasion technique
- `Enchancement_research.md` §High-performance data transport: minifilter integration patterns

**Complexity**: HIGH | **Risk**: MEDIUM | **Effort**: 12-16 hours

---

### B1: Full ETW Provider Implementation

**Rationale**: Current implementation uses DbgPrintEx stub. Production EDR requires proper ETW for:
- Integration with Windows Event Log
- Consumption by SIEM/XDR platforms
- Tamper-resistant telemetry (ETW-TI considerations)

**Implementation**:
- Define ETW manifest with provider GUID
- Register via `TraceLoggingRegister` in `MonTelemetryInitialize`
- Emit structured events using `TraceLoggingWrite`
- Event types: IopMcDetected, CrossVmDetected, Anomaly, PoolAllocation, HandleCreated

**Event Schema** (aligned with `monitor_tasks_plan.md` §Telemetry Schema):
```xml
<event value="1" symbol="IopMcDetected" level="win:Informational">
  <data name="ProcessId" inType="win:UInt32"/>
  <data name="ThreadId" inType="win:UInt32"/>
  <data name="EntryAddress" inType="win:HexInt64"/>
  <data name="Length" inType="win:UInt32"/>
  <data name="Flags" inType="win:UInt16"/>
</event>
```

**Alignment**:
- `Enchancement_research.md` §ETW: "lock-free, per-processor buffer architecture that minimizes contention"
- `monitor_tasks_plan.md` Task 2.4: "Implement Telemetry Sink (ETW or Log Files)"
- Microsoft Defender uses "approximately 111 providers" per research

**Complexity**: MEDIUM | **Risk**: LOW | **Effort**: 8-10 hours

---

### B2: Address Masking Policy Enhancement

**Rationale**: Current implementation has basic address masking via `IOP_MC_QF_MASK_ADDRESS`. Per `monitor_tasks_plan.md`: "All pointer-like fields are numeric and treated as sensitive."

**Implementation**:
- Implement configurable masking policies:
  - `MASK_NONE`: Full address (internal/lab use only)
  - `MASK_HASH`: SHA256 hash for correlation without disclosure
  - `MASK_TRUNCATE`: High bits only (pool region identification)
  - `MASK_ZERO`: Complete suppression
- Apply policy at ETW emission point
- Default to `MASK_HASH` for production

**Alignment**:
- `monitor_tasks_plan.md` §Address Masking Rules: "Mask or hash addresses by default in production"
- `ziX-labs-c-style.md`: "No PII; addresses are numeric and treated as sensitive"

**Complexity**: LOW | **Risk**: LOW | **Effort**: 4-6 hours

---

### B3: Per-Process Rate Limiting

**Rationale**: Current rate limiting is global. Per-process limits prevent single noisy process from consuming telemetry budget.

**Implementation**:
- Track event counts per ProcessId using hash table
- Configurable per-process limit (default: RateLimitPerSec / 10)
- Separate high-severity events from rate limiting (critical always logged)
- Periodic cleanup of stale process entries

**Alignment**:
- `monitor_internal.h` already has placeholder: "Rate Limiting (simple global; per-PID optional)"
- `Enchancement_research.md`: "Rate limiting sets maximum actions per time window"

**Complexity**: MEDIUM | **Risk**: LOW | **Effort**: 6-8 hours

---

### C1: Runtime Structure Offset Resolution

**Rationale**: Per `ABI-Drift-Haardening-Research.md`: "The _IOP_MC_BUFFER_ENTRY structure exemplifies this volatility: introduced in Windows 11 build 22610, it changed buffer management."

**Implementation**:
- Implement `RtlGetVersion`-based Windows build detection
- Maintain offset lookup table for known builds (22H2, 23H2, 24H2)
- Fallback chain per research:
  1. Embedded lookup tables (fastest, most reliable)
  2. PDB parsing via KPDB-style approach (adaptation)
  3. Pattern scanning (last resort)
  4. Safe mode (disable features requiring unknown offsets)

**Offset Table Example**:
```c
typedef struct _IOP_MC_OFFSET_TABLE {
    ULONG BuildNumber;
    ULONG TypeOffset;
    ULONG SizeOffset;
    ULONG AddressOffset;
    ULONG MdlOffset;
    // ...
} IOP_MC_OFFSET_TABLE;

static const IOP_MC_OFFSET_TABLE g_OffsetTables[] = {
    { 22621, 0x00, 0x04, 0x20, 0x38 },  // Win11 22H2
    { 22631, 0x00, 0x04, 0x20, 0x38 },  // Win11 23H2
    // ...
};
```

**Alignment**:
- `ABI-Drift-Haardening-Research.md` §Robust fallback strategies
- Current `iop_mc_layout.h` provides build-time offsets; this adds runtime adaptation

**Complexity**: HIGH | **Risk**: MEDIUM | **Effort**: 12-16 hours

---

### C2: Build-Time PDB Offset Generation

**Rationale**: Automate offset extraction to support new Windows builds without manual reverse engineering.

**Implementation**:
- Enhance `tools/layout_gen/mc_layout_gen.cpp` to use DIA SDK
- PowerShell wrapper (`GenMcLayout.ps1`) downloads ntoskrnl.pdb from symbol server
- Generate `iop_mc_layout.h` with offsets and C_ASSERT validations
- Integrate into MSBuild pre-compile step

**Alignment**:
- `ABI-Drift-Haardening-Research.md` §Extracting structure layouts from PDB files
- `ABI-Drift-Haardening-Research.md` §Integrating symbol processing into CI/CD pipelines
- Existing infrastructure in `Win11MonitorMgr/scripts/`

**Complexity**: MEDIUM | **Risk**: LOW | **Effort**: 8-10 hours

---

### D1: MITRE ATT&CK Technique Tagging

**Rationale**: Per `Enchancement_research.md`: "MITRE ATT&CK framework has become the universal language for describing adversary behavior."

**Technique Mapping**:

| Detection | ATT&CK Technique | Tactic |
|-----------|------------------|--------|
| Cross-VM (user VA in kernel) | T1068 (Exploitation for Privilege Escalation) | TA0004 |
| IORING_OBJECT handle abuse | T1106 (Native API) | TA0002 |
| Pool corruption | T1574.002 (DLL Side-Loading variant) | TA0005 |
| Token manipulation | T1134 (Access Token Manipulation) | TA0004 |

**Implementation**:
- Add `ATT&CK_Technique` and `ATT&CK_Tactic` fields to event payloads
- Document mappings in header comments
- Enable SIEM correlation via standardized tagging

**Alignment**:
- `Enchancement_research.md` §MITRE ATT&CK: Tactics, techniques, and data sources
- MITRE ATT&CK Evaluations demonstrate vendor adoption (100% detection rates)

**Complexity**: LOW | **Risk**: LOW | **Effort**: 4-6 hours

---

### D2: CEF/LEEF Export Format

**Rationale**: Per `Enchancement_research.md`: "CEF and LEEF serve as structured syslog formats for SIEM integration."

**Implementation**:
- User-mode component (`monitor_cli.exe`) with `--format=cef` option
- Transform EVENT_BLOB to CEF string:
  ```
  CEF:0|ziX Labs|Win11Monitor|1.0|CrossVmDetected|Cross-VM Memory Reference|5|src=<endpoint> suser=SYSTEM cs1=<masked_address>
  ```
- Syslog output option for direct SIEM ingestion

**Alignment**:
- `Enchancement_research.md` §CEF and LEEF: SIEM exchange formats
- Existing `user/monitor_cli.c` provides foundation

**Complexity**: LOW | **Risk**: LOW | **Effort**: 6-8 hours

---

### E1: Synthetic Attack Scenario Tests

**Rationale**: Current `test_harness.c` has basic smoke test. Need adversarial scenarios matching real exploits.

**Test Scenarios**:
1. **RegBuffers Corruption**: Simulate pointer modification to user VA
2. **Excessive Handle Creation**: Rapid IORING_OBJECT handle spray
3. **WNF Heap Spray**: Simulate CVE-2025-21333 pattern
4. **Cross-VM Reference**: Kernel structure with user-mode Address field
5. **MDL Inconsistency**: Mismatched MDL length vs entry length

**Implementation**:
- Extend `ThRunBasicScenario` with negative test cases
- Add `IOCTL_TH_RUN_ATTACK_SCENARIO` with scenario selector
- Validate detection counters after each scenario

**Alignment**:
- `monitor_tasks_plan.md` Task 3.1: "Malicious vs benign MC entries produce expected results"
- `monitor_tasks_plan.md` Task 4.1: "Stress MC parsing and pool scanning via harness"

**Complexity**: MEDIUM | **Risk**: LOW | **Effort**: 8-10 hours

---

### E2: Driver Verifier Integration

**Rationale**: Per `monitor_tasks_plan.md` Task 4.2: "Run Driver Verifier and other tools to detect leaks, pool misuse, IRQL misuse."

**Implementation**:
- Document Verifier flags for testing (Special Pool, IRQL checking, Pool tracking)
- Add CI script to run with Verifier enabled
- Address any Verifier findings (currently: unknown)

**Alignment**:
- `ABI-Drift-Haardening-Research.md` §Runtime validation techniques: "Driver Verifier's Special Pool mode"
- `monitor_tasks_plan.md` Phase 4: Refinement

**Complexity**: LOW | **Risk**: LOW | **Effort**: 4-6 hours

---

## Prioritized Implementation Roadmap

### Phase 1: Critical Detection Gaps (Weeks 1-2)

| ID | Enhancement | Effort | Priority |
|----|-------------|--------|----------|
| A1 | IORING_OBJECT Handle Monitoring | 6-8h | P0 |
| A2 | RegBuffers Pointer Integrity | 10-12h | P0 |
| B1 | Full ETW Provider | 8-10h | P0 |

**Rationale**: These directly address the research finding that IoRing exploitation "leaves few forensic traces" by adding visibility at attack entry points.

### Phase 2: Expanded Coverage (Weeks 3-4)

| ID | Enhancement | Effort | Priority |
|----|-------------|--------|----------|
| A3 | Additional Pool Tags | 6-8h | P1 |
| B2 | Address Masking Enhancement | 4-6h | P1 |
| B3 | Per-Process Rate Limiting | 6-8h | P1 |
| D1 | MITRE ATT&CK Tagging | 4-6h | P1 |

### Phase 3: ABI Hardening (Weeks 5-6)

| ID | Enhancement | Effort | Priority |
|----|-------------|--------|----------|
| C1 | Runtime Offset Resolution | 12-16h | P1 |
| C2 | Build-Time PDB Generation | 8-10h | P2 |

### Phase 4: Integration & Validation (Weeks 7-8)

| ID | Enhancement | Effort | Priority |
|----|-------------|--------|----------|
| A4 | Named Pipe Detection | 12-16h | P2 |
| D2 | CEF/LEEF Export | 6-8h | P2 |
| E1 | Attack Scenario Tests | 8-10h | P1 |
| E2 | Driver Verifier Integration | 4-6h | P1 |

---

## Total Effort Estimate

| Category | Hours |
|----------|-------|
| Detection (A1-A4) | 34-44h |
| Telemetry (B1-B3) | 18-24h |
| ABI Hardening (C1-C2) | 20-26h |
| Integration (D1-D2) | 10-14h |
| Testing (E1-E2) | 12-16h |
| **Total** | **94-124h** |

---

## Risk Assessment

### High Risk Items
- **A2 (RegBuffers Integrity)**: Accessing IORING_OBJECT internals requires careful validation; incorrect parsing could cause BSOD
- **A4 (Named Pipe Detection)**: Minifilter complexity; potential performance impact

### Mitigation Strategies
- Per `ziX-labs-c-style.md`: All dereferences guarded by SEH
- Incremental rollout with Driver Verifier validation
- Lenient validation mode for forward compatibility

---

## Dependencies

```
A1 (Handle Monitoring) ──┐
                        ├──> B1 (ETW) ──> D1 (ATT&CK)
A2 (RegBuffers) ────────┘                    │
                                             v
A3 (Pool Tags) ────────────────────────> E1 (Attack Tests)
                                             │
C1 (Runtime Offsets) ──> C2 (PDB Gen)        │
                                             v
B2 (Masking) ──> B3 (Rate Limit) ──> D2 (CEF/LEEF)
```

---

## Success Criteria

1. **Detection Rate**: IoRing exploitation attempts detected with <1s latency
2. **False Positive Rate**: <0.1% under normal system operation
3. **Performance**: <2% additional CPU overhead vs current implementation
4. **Coverage**: Support Windows 11 22H2, 23H2, and 24H2 builds
5. **Integration**: Events consumable by Splunk/Elastic via CEF or native ingestion

---

## References

- [One I/O Ring to Rule Them All](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/) - Yarden Shafir, Winsider
- [IoRingReadWritePrimitive GitHub](https://github.com/yardenshafir/IoRingReadWritePrimitive)
- [CVE-2025-21333 POC](https://github.com/MrAle98/CVE-2025-21333-POC)
- [Vergilius Project: _IOP_MC_BUFFER_ENTRY](https://www.vergiliusproject.com/kernels/x64/windows-11/22h2/_IOP_MC_BUFFER_ENTRY)
- [Kernel ETW is the best ETW](https://www.elastic.co/security-labs/kernel-etw-best-etw) - Elastic Security Labs
- [Microsoft: Adding Event Tracing to Kernel-Mode Drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/adding-event-tracing-to-kernel-mode-drivers)
- [EDRSandblast](https://github.com/wavestone-cdt/EDRSandblast) - EDR bypass techniques informing detection requirements

---

**Document Version**: 1.0
**Author**: Claude (AI Assistant) in collaboration with ziX Labs
**Date**: 2025-11-30
**Status**: Draft for Review
