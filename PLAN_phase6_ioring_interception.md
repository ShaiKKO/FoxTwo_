# Phase 6: Real-time IoRing Operation Interception

## Implementation Plan

**Author:** Colin MacRitchie | ziX Labs
**Version:** 1.0
**Date:** 2025-11-30
**Status:** Planning

---

## 1. Executive Summary

This phase implements real-time interception and validation of IoRing operations (NtCreateIoRing, NtSubmitIoRing) to detect exploitation attempts before kernel execution. Unlike passive monitoring, this provides pre-execution policy enforcement.

---

## 2. Research Findings

### 2.1 IoRing Syscall Architecture

**Key Syscalls:**
- `NtCreateIoRing` - Creates IORING_OBJECT with submission/completion queues
- `NtSubmitIoRing` - Submits queued operations for kernel processing
- Internal: `IopProcessIoRingEntry` processes each SQE, `IopIoRingDispatchComplete` fills CQE

**IORING_OBJECT Structure (from windows-internals.com):**
```
- Type, Size, NT_IORING_INFO
- SectionObject (backing section for queues)
- KernelMappedBase
- SubmissionQueue, CompletionQueue
- RegBuffersCount, RegBuffers (pre-registered buffer array)
- RegFilesCount, RegFiles (pre-registered file handles)
```

**Submission Queue Entry (NT_IORING_SQE):**
- OpCode: IORING_OP_READ (1), IORING_OP_REGISTERED_FILES, IORING_OP_REGISTERED_BUFFERS, IORING_OP_CANCEL
- FileRef: Handle or pre-registered index (flag 0x1)
- Buffer: Output buffer or pre-registered index (flag 0x2)
- FileOffset, BufferSize

### 2.2 Interception Approaches Evaluated

| Approach | PatchGuard Safe | HVCI Safe | Complexity | Detection Coverage |
|----------|-----------------|-----------|------------|-------------------|
| **ETW-based (Avast-style)** | Yes | Yes | Medium | Post-execution only |
| **SSDT Hooking (Hells Hollow)** | Yes* | No | High | Pre-execution |
| **InfinityHook (ETW hijack)** | No | No | High | Pre-execution |
| **Minifilter Callbacks** | Yes | Yes | Low | IRP-level, not syscall |
| **Instrumentation Callback** | Yes | Yes | Medium | User-mode only |
| **Alt-Syscalls Mechanism** | Yes | No | High | Pre-execution |

*\*Hells Hollow claims PatchGuard resistance but requires disabled HVCI*

### 2.3 Recommended Approach: Hybrid ETW + Validation

Given the constraints:
1. Must be PatchGuard-compliant
2. Should work with HVCI enabled
3. Production-ready security driver

**Primary Strategy:**
- **NOT direct syscall hooking** (incompatible with production environments)
- Instead: **Enhanced polling + ETW correlation + pre-registered buffer validation**

**Rationale:**
Direct NtSubmitIoRing hooking is not viable for a production security driver because:
- SSDT modification triggers PatchGuard BSOD
- HVCI prevents the Alt-Syscalls approach
- InfinityHook requires disabling kernel protections

**Alternative Real-time Detection:**
1. High-frequency IoRing handle enumeration (existing A1)
2. Immediate RegBuffers validation on new handles (existing A2)
3. ETW syscall tracing correlation (requires kernel debug mode - informational only)
4. Pre-submit validation via user-mode interception (companion DLL)

---

## 3. Architecture Design

### 3.1 Component Overview

```
+------------------------------------------------------------------+
|                    User-Mode Components                           |
|  +----------------------------+  +-----------------------------+  |
|  | win11mon_intercept.dll     |  | win11mon_client.dll         |  |
|  | - IAT hook NtSubmitIoRing  |  | - Async event polling       |  |
|  | - Pre-validation callback  |  | - Ring buffer monitoring    |  |
|  | - Policy enforcement       |  | - Alert aggregation         |  |
|  +----------------------------+  +-----------------------------+  |
+------------------------------------------------------------------+
                          |  DeviceIoControl
                          v
+------------------------------------------------------------------+
|                    Kernel-Mode Driver                             |
|  +----------------------------+  +-----------------------------+  |
|  | ioring_intercept.c (NEW)   |  | ioring_enum.c (existing)    |  |
|  | - Policy engine            |  | - Handle enumeration        |  |
|  | - Validation dispatcher    |  | - Object discovery          |  |
|  | - Block/Allow decisions    |  +-----------------------------+  |
|  +----------------------------+                                   |
|  +----------------------------+  +-----------------------------+  |
|  | regbuf_integrity.c (exist) |  | telemetry_ringbuf.c (exist) |  |
|  | - RegBuffers validation    |  | - Event logging             |  |
|  | - Corruption detection     |  | - Forensic capture          |  |
|  +----------------------------+  +-----------------------------+  |
+------------------------------------------------------------------+
```

### 3.2 Interception Flow (User-Mode Assisted)

```
1. win11mon_intercept.dll injected into target process
2. IAT/inline hook installed on ntdll!NtSubmitIoRing
3. Pre-submit hook fires:
   a. Serialize submission queue entries
   b. Call kernel driver for validation
   c. Driver checks:
      - RegBuffers integrity (A2)
      - Buffer address validation
      - Operation policy compliance
   d. Return allow/block decision
4. If blocked: return STATUS_ACCESS_DENIED to caller
5. If allowed: call original NtSubmitIoRing
6. Post-submit: log operation to ring buffer
```

### 3.3 Kernel-Mode Policy Engine

```c
// New file: ioring_intercept.h

typedef enum _MON_INTERCEPT_ACTION {
    MonIntercept_Allow = 0,
    MonIntercept_Block = 1,
    MonIntercept_LogOnly = 2
} MON_INTERCEPT_ACTION;

typedef enum _MON_INTERCEPT_REASON {
    MonReason_None = 0,
    MonReason_RegBuffersCorrupted = 1,
    MonReason_KernelAddressInBuffer = 2,
    MonReason_ExcessiveOperations = 3,
    MonReason_SuspiciousOpCode = 4,
    MonReason_ProcessBlacklisted = 5,
    MonReason_RateLimitExceeded = 6
} MON_INTERCEPT_REASON;

typedef struct _MON_INTERCEPT_POLICY {
    BOOLEAN Enabled;
    BOOLEAN BlockKernelAddresses;
    BOOLEAN BlockCorruptedRegBuffers;
    ULONG   MaxOperationsPerSubmit;
    ULONG   MaxBufferSize;
    BOOLEAN AuditMode;  // Log but don't block
} MON_INTERCEPT_POLICY, *PMON_INTERCEPT_POLICY;

typedef struct _MON_INTERCEPT_REQUEST {
    ULONG   Size;
    ULONG   ProcessId;
    HANDLE  IoRingHandle;
    ULONG   OperationCount;
    // Serialized SQE data follows
} MON_INTERCEPT_REQUEST, *PMON_INTERCEPT_REQUEST;

typedef struct _MON_INTERCEPT_RESPONSE {
    ULONG   Size;
    MON_INTERCEPT_ACTION Action;
    MON_INTERCEPT_REASON Reason;
    ULONG   ViolatingOperationIndex;
    CHAR    ATT_CK_Technique[16];
} MON_INTERCEPT_RESPONSE, *PMON_INTERCEPT_RESPONSE;
```

---

## 4. Implementation Tasks

### 4.1 Kernel-Mode Components

**File: ioring_intercept.h**
- Policy structures and enums
- Validation request/response formats
- IOCTL definitions

**File: ioring_intercept.c**
- `MonInterceptInitialize()` - Initialize policy engine
- `MonInterceptShutdown()` - Cleanup
- `MonInterceptValidateSubmission()` - Main validation entry point
- `MonInterceptCheckRegBuffers()` - Verify RegBuffers integrity
- `MonInterceptCheckBufferAddresses()` - Validate buffer pointers
- `MonInterceptCheckPolicy()` - Apply configured policy rules
- `MonInterceptSetPolicy()` - Update runtime policy

**IOCTL Additions:**
```c
#define IOCTL_MONITOR_INTERCEPT_VALIDATE   CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x20, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONITOR_INTERCEPT_SET_POLICY CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x21, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_MONITOR_INTERCEPT_GET_POLICY CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x22, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MONITOR_INTERCEPT_GET_STATS  CTL_CODE(FILE_DEVICE_UNKNOWN, WIN11MON_IOCTL_BASE + 0x23, METHOD_BUFFERED, FILE_READ_ACCESS)
```

### 4.2 User-Mode Components

**File: client/win11mon_intercept.h**
- Hook installation APIs
- Pre/Post submit callback signatures

**File: client/win11mon_intercept.c**
- `Mon_InterceptInstall()` - Install hooks on target process
- `Mon_InterceptRemove()` - Remove hooks
- `Mon_InterceptSetCallback()` - Register custom validation callback
- `PreSubmitIoRing_Hook()` - Hook trampoline
- `SerializeSubmissionQueue()` - Capture SQE data for validation

### 4.3 Integration Points

1. **win11_monitor_mgr.c**: Add IOCTL dispatch for interception
2. **monitor_internal.h**: Include ioring_intercept.h
3. **win11_monitor_public.h**: Add public interception structures
4. **client/win11mon_client.h**: Add interception client APIs

---

## 5. Security Considerations

### 5.1 Attack Surface

- User-mode hook can be bypassed by direct syscall
- Mitigation: Combine with kernel-mode polling for defense-in-depth

### 5.2 Privilege Requirements

- Hook installation requires process injection capability
- Policy modification requires admin privileges
- Validation requests from non-admin processes logged but may be limited

### 5.3 Tampering Resistance

- User-mode DLL can be unloaded by attacker
- Kernel driver maintains independent polling as fallback
- Ring buffer preserves forensic evidence of bypass attempts

---

## 6. Testing Plan

### 6.1 Unit Tests

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| INT-T01 | Validate clean IoRing submission | Allow |
| INT-T02 | Submit with corrupted RegBuffers | Block |
| INT-T03 | Submit with kernel address in buffer | Block |
| INT-T04 | Excessive operations (>MaxOps) | Block |
| INT-T05 | Audit mode with violation | Allow + Log |
| INT-T06 | Rate limit exceeded | Block |
| INT-T07 | Blacklisted process submission | Block |
| INT-T08 | Policy hot-reload | Apply immediately |

### 6.2 Integration Tests

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| INT-I01 | Hook + validation + original call | Transparent to app |
| INT-I02 | Block propagation to caller | STATUS_ACCESS_DENIED |
| INT-I03 | Ring buffer event on block | Event captured |
| INT-I04 | Client library callback | Callback invoked |
| INT-I05 | Hook removal cleanup | No resource leaks |

### 6.3 Performance Tests

| Test ID | Description | Target |
|---------|-------------|--------|
| INT-P01 | Validation latency | < 100us per submission |
| INT-P02 | Hook overhead | < 5% throughput impact |
| INT-P03 | Memory overhead | < 1MB per process |

---

## 7. Limitations and Caveats

### 7.1 Known Limitations

1. **Direct Syscall Bypass**: Attackers using direct syscalls (Hell's Gate, etc.) bypass user-mode hooks
   - Mitigation: Kernel-mode polling catches post-execution state

2. **HVCI Environments**: Cannot use kernel-mode syscall interception
   - Mitigation: User-mode hooks + polling provides detection

3. **Kernel Debugging Dependency**: ETW syscall tracing requires kernel debug
   - Mitigation: Production mode uses handle enumeration instead

### 7.2 Defense-in-Depth Strategy

```
Layer 1: User-mode NtSubmitIoRing hook (pre-execution, bypassable)
Layer 2: Kernel-mode handle enumeration (post-execution, robust)
Layer 3: RegBuffers integrity validation (corruption detection)
Layer 4: Ring buffer forensics (evidence preservation)
```

---

## 8. Dependencies

- Phase 5A: Ring Buffer Telemetry (logging)
- Phase 5B: Dynamic Offset Resolution (structure access)
- Phase 5C: Usermode Client Library (client APIs)
- A1: IoRing Handle Enumeration
- A2: RegBuffers Integrity Validation

---

## 9. File Deliverables

| File | Type | Description |
|------|------|-------------|
| `ioring_intercept.h` | Header | Policy engine interfaces |
| `ioring_intercept.c` | Source | Kernel-mode validation |
| `client/win11mon_intercept.h` | Header | User-mode hook APIs |
| `client/win11mon_intercept.c` | Source | Hook implementation |
| `test_intercept.c` | Test | Unit tests |

---

## 10. Research Sources

- [I/O Rings - Windows Internals](https://windows-internals.com/i-o-rings-when-one-i-o-operation-is-not-enough/)
- [Hells Hollow - SSDT Hooking via Alt Syscalls](https://fluxsec.red/hells-hollow-a-new-SSDT-hooking-technique-with-alt-syscalls-rootkit)
- [Hooking System Calls like Avast](https://the-deniss.github.io/posts/2022/12/08/hooking-system-calls-in-windows-11-22h2-like-avast-antivirus.html)
- [Windows Syscall Table](https://j00ru.vexillium.org/syscalls/nt/64/)
- [Minifilter Pre/Post Operations](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/writing-preoperation-callback-routines)
- [GitHub: IoRingReadWritePrimitive](https://github.com/yardenshafir/IoRingReadWritePrimitive)
- [One I/O Ring to Rule Them All](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)

---

## 11. Approval

- [ ] Architecture review completed
- [ ] Security review completed
- [ ] Implementation approved

---

*End of Phase 6 Plan*
