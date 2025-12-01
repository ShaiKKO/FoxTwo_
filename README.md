# Fox2_

Fox2_ is a Windows kernel-mode driver (WDM) designed for monitoring and security analysis of Windows 11 I/O Ring operations. It provides comprehensive detection capabilities for IoRing-based exploitation attempts, pool spray attacks, and cross-process buffer manipulation.

## Table of Contents

- [About Fox2_](#about)
- [Key Features](#features)
- [Architecture](#architecture)
- [Security Capabilities](#security)
- [Requirements](#requirements)
- [Building](#build)
- [Installation](#installation)
- [Usage](#usage)
- [Codemap](#codemap)
- [Contributing](#contributing)
- [License](#license)

<a name="about"></a>
## About Fox2_

IoRing (I/O Ring) is a high-performance asynchronous I/O interface introduced in Windows 11, analogous to Linux's io_uring. While beneficial for performance, IoRing has become a target for kernel exploitation due to its minimal Event Tracing for Windows (ETW) visibility and complex internal structures. Fox2_ fills this security gap by providing:

- **Real-time IoRing operation interception** with pre-execution policy enforcement
- **RegBuffers pointer integrity validation** to detect cross-VM attacks
- **Pool allocation tracking** for heap spray detection (IoRing, WNF, Named Pipes, Tokens)
- **Behavioral profiling** with ML-ready feature extraction
- **ETW TraceLogging integration** for seamless SIEM compatibility

The driver is developed by ziX Performance Labs and has been tested against real-world CVEs including CVE-2025-21333, CVE-2024-35250, and techniques demonstrated at Pwn2Own 2024/2025.

<a name="features"></a>
## Key Features

### Implemented Features

| Feature | Module | Description |
|---------|--------|-------------|
| **IoRing Enumeration (A1)** | `ioring_enum.c` | System-wide enumeration of all IoRing handles via `NtQuerySystemInformation(SystemHandleInformation)` with RegBuffers inspection |
| **RegBuffers Integrity (A2)** | `regbuf_integrity.c` | Detection of corrupted RegBuffers pointing to user-mode addresses with SEH-protected access |
| **Pool Spray Detection (A3)** | `pool_tracker.c` | Heuristic detection of heap feng shui attacks across 6 pool tags (IrRB, IoRg, Wnf, WnNm, NpFr, Toke) |
| **Operation Interception** | `ioring_intercept.c` | Pre-submission SQE validation with opcode whitelisting, kernel address blocking, and process blacklisting |
| **Process Profiling** | `process_profile.c` | Per-process behavioral baselines with sliding window ops/sec calculation and anomaly scoring |
| **Anomaly Detection** | `anomaly_rules.c` | 7 built-in rules with configurable thresholds and severity levels |
| **ETW Provider (B1)** | `telemetry_etw.c` | TraceLogging provider (GUID: `7E8B92A1-5C3D-4F2E-B8A9-1D2E3F4A5B6C`) for security monitoring integration |
| **Address Masking (B2)** | `addr_mask.c` | SipHash-2-4 based kernel address sanitization with per-boot 128-bit random key |
| **Rate Limiting (B3)** | `rate_limit.c` | O(1) per-process sliding window rate limiting via 256-bucket hash table |
| **Ring Buffer Telemetry (E1)** | `telemetry_ringbuf.c` | Lock-free circular buffer with snapshot capability and automatic oldest-event overwrite |
| **Dynamic Offsets (E2)** | `offset_resolver.c` | Three-tier offset resolution: embedded tables, signature-based, inference |

### Anomaly Detection Rules

| Rule ID | Name | Description | Default Threshold |
|---------|------|-------------|-------------------|
| 1 | HighOpsFrequency | Excessive operations per second | 1000 ops/sec |
| 2 | LargeBufferRegistration | Unusually large buffer registrations | 64 MB |
| 3 | RapidHandleCreation | Rapid IoRing handle creation | 10 handles/sec |
| 4 | ElevatedIoRingAbuse | IoRing usage from elevated processes | N/A |
| 5 | BurstPattern | Burst submission patterns | 100 ops/burst |
| 6 | ConcurrentTargets | Multiple file targets in single submission | 50 targets |
| 7 | ViolationAccumulation | Accumulated policy violations | 5 violations |

<a name="architecture"></a>
## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              User Mode                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────────┐  │
│  │  monitor_cli    │  │ win11mon_client │  │  win11mon_intercept         │  │
│  │  (CLI Tool)     │  │ (Sync API)      │  │  (IAT/Inline Hooks)         │  │
│  └────────┬────────┘  └────────┬────────┘  └──────────────┬──────────────┘  │
│           │                    │                          │                  │
│           └────────────────────┼──────────────────────────┘                  │
│                                │ DeviceIoControl                             │
├────────────────────────────────┼────────────────────────────────────────────┤
│                              Kernel Mode                                     │
├────────────────────────────────┼────────────────────────────────────────────┤
│                                ▼                                             │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                     win11_monitor_mgr.sys                               ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ ││
│  │  │ IOCTL       │  │ Pool        │  │ IoRing      │  │ Offset          │ ││
│  │  │ Dispatcher  │  │ Tracker     │  │ Enum        │  │ Resolver        │ ││
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └────────┬────────┘ ││
│  │         │                │                │                  │          ││
│  │  ┌──────┴──────┐  ┌──────┴──────┐  ┌──────┴──────┐  ┌────────┴────────┐ ││
│  │  │ Intercept   │  │ Profile     │  │ Anomaly     │  │ RegBuf          │ ││
│  │  │ Engine      │  │ Manager     │  │ Rules       │  │ Integrity       │ ││
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └────────┬────────┘ ││
│  │         │                │                │                  │          ││
│  │  ┌──────┴────────────────┴────────────────┴──────────────────┴────────┐ ││
│  │  │                    Telemetry Subsystem                             │ ││
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────┐  │ ││
│  │  │  │ ETW         │  │ Ring Buffer │  │ Rate Limit  │  │ Addr Mask │  │ ││
│  │  │  │ Provider    │  │ (Lock-free) │  │ (Per-PID)   │  │ (SipHash) │  │ ││
│  │  │  └─────────────┘  └─────────────┘  └─────────────┘  └───────────┘  │ ││
│  │  └────────────────────────────────────────────────────────────────────┘ ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

### Subsystem Initialization Order

The driver initializes 12+ subsystems in a specific order during `DriverEntry`:

1. **PoolTracker** - Big pool scanning infrastructure
2. **OffsetResolver** - Dynamic structure offset resolution
3. **IoRingEnum** - Handle enumeration via SystemHandleInformation
4. **ETW Provider** - TraceLogging registration
5. **AddrMask** - SipHash key generation
6. **RateLimit** - Per-process rate limiting tables
7. **RingBuffer** - Lock-free telemetry buffer
8. **Intercept** - Policy engine initialization
9. **Profile** - Process profiling with ERESOURCE lock
10. **Anomaly** - Rule engine with FAST_MUTEX protection

<a name="security"></a>
## Security Capabilities

Fox2_ detects and reports the following attack patterns:

| Attack Pattern | Detection Method | MITRE ATT&CK |
|----------------|------------------|--------------|
| **Cross-VM Attacks** | User-mode virtual addresses in kernel buffer arrays | T1068 |
| **RegBuffers Corruption** | Manipulation of IoRing registered buffer pointers | T1068 |
| **Pool Spraying** | Excessive allocations of exploitation-relevant pool tags | T1068 |
| **Privilege Escalation** | Token object spray detection | T1134 |
| **DoS via IoRing** | Excessive SQE submission rates | T1499 |
| **Kernel Address Leak** | Kernel addresses in user-mode buffers | T1083 |
| **Process Injection** | Suspicious cross-process IoRing usage | T1055 |

### Monitored Pool Tags

| Tag | Name | Spray Threshold | Purpose |
|-----|------|-----------------|---------|
| `IrRB` | IoRing RegBuffers | 50 | Primary IoRing exploitation target |
| `IoRg` | IoRing Object | 100 | IoRing object spray |
| `Wnf ` | WNF State Data | 200 | CVE-2021-31956 style heap spray |
| `WnNm` | WNF Name Instance | 100 | Additional WNF structure |
| `NpFr` | Named Pipe DATA_ENTRY | 300 | Pipe-based pool spray |
| `Toke` | Token Object | 50 | Privilege escalation target |

<a name="requirements"></a>
## Requirements

### Build Requirements

- **Windows 11 SDK** (10.0.22621.0 or later)
- **Windows Driver Kit (WDK)** for Windows 11
- **Visual Studio 2022** with Desktop development with C++ workload
- **Spectre-mitigated libraries** (automatically selected by build)
- **DIA SDK** (for `mc_layout_gen` tool)

### Runtime Requirements

- **Windows 11 22H2** (Build 22621) or later (x64 only)
- **Supported builds**: 22621-27000 (embedded offset tables)
- **Test signing enabled** or a valid kernel-mode code signing certificate
- **Administrator privileges** for driver installation and client access

### Supported IORING_OBJECT Offsets

| Build Range | RegBuffers Offset | RegBuffersCount Offset |
|-------------|-------------------|------------------------|
| 22621-27000 | 0xB8 | 0xB0 |

<a name="build"></a>
## Building

Fox2_ uses Visual Studio project files with WDK integration.

### Building with Visual Studio

```powershell
# Open the solution
cd Fox2_
start Fox2_.sln

# Build from Developer Command Prompt
msbuild Fox2_.vcxproj /p:Configuration=Release /p:Platform=x64
```

### Build Output

| Artifact | Location | Description |
|----------|----------|-------------|
| `win11_monitor_mgr.sys` | `x64\Release\` | Kernel driver |
| `monitor_cli.exe` | `user\` | Command-line client |
| `mc_layout_gen.exe` | `tools\layout_gen\` | DIA-based offset extractor |

### Build Configurations

- **Debug**: Full debug symbols, assertions enabled, verbose logging via `DbgPrintEx`
- **Release**: Optimized, Control Flow Guard (CFG) enabled, Spectre mitigation

### Layout Generator Tool

The `mc_layout_gen` tool extracts `_IOP_MC_BUFFER_ENTRY` structure offsets from PDB files:

```powershell
mc_layout_gen.exe --image ntoskrnl.exe --pdb ntkrnlmp.pdb --out-header iop_mc_layout.h
```

<a name="installation"></a>
## Installation

> **Warning**: This is a kernel-mode driver. Improper installation can cause system instability.

### Test Mode Installation

```powershell
# Enable test signing (requires restart)
bcdedit /set testsigning on

# Create and start the driver service
sc create Fox2_ type=kernel binPath="C:\path\to\win11_monitor_mgr.sys"
sc start Fox2_
```

### Verification

```powershell
# Check driver status
sc query Fox2_

# Verify device creation (device name: \Device\Fox2_)
# Symbolic link: \DosDevices\Fox2_
```

<a name="usage"></a>
## Usage

### Command-Line Client

```c
// user/monitor_cli.c - Basic usage example
#include "monitor_client.h"

int main(void) {
    HANDLE hMon = NULL;
    MonOpen(&hMon);

    // Enable monitoring
    MONITOR_SETTINGS settings = {0};
    settings.Size = sizeof(settings);
    settings.EnableMonitoring = 1;
    settings.EnableTelemetry = 1;
    MonEnable(hMon, &settings);

    // Trigger a pool scan
    MonScanNow(hMon);

    // Fetch statistics
    MONITOR_STATS stats;
    MonGetStats(hMon, &stats);
    printf("Stats: TotalAllocations=%llu IopMcDetections=%llu\n",
        stats.TotalAllocations, stats.IopMcDetections);

    MonDisable(hMon);
    MonClose(hMon);
    return 0;
}
```

### C API Client Library

The `win11mon_client` library provides a comprehensive synchronous API:

```c
#include "win11mon_client.h"

HWIN11MON hMon = NULL;
Win11MonOpen(&hMon);

// Check driver version
DWORD version;
Win11MonGetVersion(hMon, &version);

// Check capabilities
if (Win11MonHasCapability(hMon, WIN11MON_CLIENT_CAP_IORING_ENUM)) {
    WIN11MON_IORING_INFO rings[64];
    DWORD count;
    Win11MonEnumerateIoRings(hMon, rings, 64, &count);
}

// Ring buffer operations
WIN11MON_RINGBUF_STATS rbStats;
Win11MonRingBufGetStats(hMon, &rbStats);

Win11MonClose(hMon);
```

### User-Mode Interception

The `win11mon_intercept` library provides IAT/inline hook-based interception:

```c
#include "win11mon_intercept.h"

// Install hooks on NtSubmitIoRing
WIN11MON_INTERCEPT_CONFIG config = {0};
config.Size = sizeof(config);
config.EnableIATHook = TRUE;
config.PreSubmitCallback = MyPreSubmitCallback;
config.PostSubmitCallback = MyPostSubmitCallback;

Win11MonInterceptInstall(&config);

// Callback receives serialized SQE data
BOOL CALLBACK MyPreSubmitCallback(
    PWIN11MON_SUBMIT_CONTEXT ctx,
    PVOID userData
) {
    // Inspect/modify submission
    return TRUE;  // Allow submission
}
```

### IOCTL Interface

The driver exposes 40+ IOCTLs across subsystems:

| Category | Example IOCTLs |
|----------|----------------|
| **Core** | `IOCTL_MONITOR_ENABLE`, `IOCTL_MONITOR_GET_STATS`, `IOCTL_MONITOR_SCAN_NOW` |
| **Ring Buffer** | `IOCTL_MONITOR_RINGBUF_SNAPSHOT`, `IOCTL_MONITOR_RINGBUF_GET_STATS` |
| **Interception** | `IOCTL_MONITOR_INTERCEPT_SET_POLICY`, `IOCTL_MONITOR_INTERCEPT_ADD_BLACKLIST` |
| **Profiling** | `IOCTL_MONITOR_PROFILE_GET_SUMMARY`, `IOCTL_MONITOR_PROFILE_EXPORT_ML` |
| **Anomaly** | `IOCTL_MONITOR_ANOMALY_GET_RULE`, `IOCTL_MONITOR_ANOMALY_SET_THRESHOLD` |

<a name="codemap"></a>
## Codemap

### Directory Structure

```
Fox2_/
├── client/                     # User-mode client libraries
│   ├── win11mon_client.c       # Synchronous IOCTL wrapper API (785 lines)
│   ├── win11mon_client.h       # Client API header
│   ├── win11mon_intercept.c    # IAT/inline hook interception (1335 lines)
│   ├── win11mon_intercept.h    # Interception API header
│   ├── win11mon_profile.c      # Profile/anomaly client APIs (478 lines)
│   └── win11mon_profile.h      # Profile API header
├── tools/
│   └── layout_gen/
│       └── mc_layout_gen.cpp   # DIA-based _IOP_MC_BUFFER_ENTRY extractor
├── user/                       # Simple CLI client
│   ├── monitor_cli.c           # Command-line interface
│   └── monitor_client.c        # Basic IOCTL wrapper
├── win11_monitor_mgr.c         # Core driver: DriverEntry, IOCTL dispatcher (1884 lines)
├── win11_monitor_mgr.h         # Driver public header with IOCTL definitions
├── monitor_internal.h          # Internal structures and MONITOR_CONTEXT
├── ioring_enum.c               # IoRing handle enumeration (431 lines)
├── ioring_enum.h               # Enumeration API
├── ioring_intercept.c          # SQE validation & policy engine (1068 lines)
├── ioring_intercept.h          # Interception structures
├── regbuf_integrity.c          # RegBuffers pointer validation (230 lines)
├── regbuf_integrity.h          # Integrity check API
├── pool_tracker.c              # Big pool scanning for target tags (433 lines)
├── offset_resolver.c           # Dynamic offset resolution (654 lines)
├── offset_resolver.h           # Offset resolver API
├── process_profile.c           # Per-process behavior profiling (1017 lines)
├── process_profile.h           # Profile structures
├── anomaly_rules.c             # Extensible rule evaluation (512 lines)
├── anomaly_rules.h             # Anomaly rule definitions
├── addr_mask.c                 # SipHash-2-4 address masking (364 lines)
├── addr_mask.h                 # Address masking API
├── rate_limit.c                # Per-process rate limiting (765 lines)
├── rate_limit.h                # Rate limit structures
├── telemetry.c                 # Event queuing facade (168 lines)
├── telemetry_ringbuf.c         # Lock-free ring buffer (595 lines)
├── telemetry_ringbuf.h         # Ring buffer API
├── telemetry_etw.c             # ETW TraceLogging provider (555 lines)
├── telemetry_etw.h             # ETW event definitions
├── iop_mc.h                    # _IOP_MC_BUFFER_ENTRY structure
├── test_harness.c              # In-kernel test driver (799 lines)
├── test_intercept.c            # Interception unit tests (555 lines)
└── test_profile.c              # Profile/anomaly unit tests (524 lines)
```

### Core Components

| Component | File | Purpose |
|-----------|------|---------|
| **Driver Entry** | `win11_monitor_mgr.c` | WDM driver initialization, IOCTL dispatch, subsystem orchestration |
| **Pool Tracker** | `pool_tracker.c` | `SystemBigPoolInformation` scanning with spray detection heuristics |
| **IoRing Enum** | `ioring_enum.c` | Handle enumeration via `NtQuerySystemInformation(SystemHandleInformation)` |
| **Offset Resolver** | `offset_resolver.c` | Three-tier offset resolution for IORING_OBJECT and IOP_MC structures |
| **Intercept Engine** | `ioring_intercept.c` | SQE validation, opcode whitelisting, process blacklist management |
| **Profile Manager** | `process_profile.c` | ERESOURCE-protected profile list, ML feature vector export |
| **Anomaly Engine** | `anomaly_rules.c` | FAST_MUTEX-protected rule evaluation with configurable thresholds |
| **ETW Provider** | `telemetry_etw.c` | TraceLogging events for SIEM integration |
| **Ring Buffer** | `telemetry_ringbuf.c` | Lock-free circular buffer using `InterlockedCompareExchange64` |
| **Rate Limiter** | `rate_limit.c` | 256-bucket hash table with sliding window per-PID limiting |
| **Address Masker** | `addr_mask.c` | SipHash-2-4 with per-boot random key for kernel address sanitization |

### Key Data Structures

| Structure | Location | Purpose |
|-----------|----------|---------|
| `MONITOR_CONTEXT` | `monitor_internal.h` | Global driver state, subsystem handles, statistics |
| `IORING_OBJECT` | (Windows internal) | IoRing kernel object (offsets at 0xB0/0xB8 for RegBuffers) |
| `IOP_MC_BUFFER_ENTRY` | `iop_mc.h` | Registered buffer entry structure |
| `MON_INTERCEPT_REQUEST` | `ioring_intercept.h` | Serialized SQE submission for validation |
| `MON_PROCESS_PROFILE` | `process_profile.h` | Per-process behavioral profile |
| `MON_ANOMALY_RULE` | `anomaly_rules.h` | Configurable anomaly detection rule |
| `MON_RING_EVENT_HEADER` | `telemetry_ringbuf.h` | Ring buffer event header with magic/sequence |

<a name="contributing"></a>
## Contributing

Contributions to Fox2_ are welcome. This project is open source under the GPL-3.0 license.

### Coding Standards

The project follows the [ziX Labs C Style Guide](docs/ziX-labs-c-style.md):

- CERT C Secure Coding compliance
- 60-line function limit for maintainability
- Security-first design with SEH for all untrusted memory access
- Comprehensive documentation with function contracts (preconditions, postconditions, thread-safety)

### Testing

The project includes in-kernel test harnesses:

```powershell
# Load test harness driver
sc create Win11MonTest type=kernel binPath="C:\path\to\test_harness.sys"
sc start Win11MonTest

# Run tests via DeviceIoControl to \\.\Win11MonTest
```

Test coverage includes:

- **Unit tests**: `test_intercept.c`, `test_profile.c`
- **Integration tests**: `test_harness.c`
- **IRQL safety tests**: DISPATCH_LEVEL operation verification

<a name="license"></a>
## License

This project is licensed under the **GNU General Public License v3.0** (GPL-3.0).

You are free to redistribute and modify this software under the terms of the GPL-3.0. See the [LICENSE.txt](LICENSE.txt) file for the full license text.

```text
Copyright (C) 2025 ziX Performance Labs

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
```

---

## References

- [Windows IoRing Documentation](https://learn.microsoft.com/en-us/windows/win32/api/ioringapi/)
- [IORING_OBJECT Structure (Vergilius Project)](https://www.vergiliusproject.com/kernels/x64/windows-11/22h2/_IORING_OBJECT)
- [CVE-2021-31956 Analysis](https://www.nccgroup.com/research-blog/cve-2021-31956-exploiting-the-windows-kernel-ntfs-with-wnf-part-1/)
- [Windows Kernel Pool Exploitation](https://whiteknightlabs.com/2025/03/24/understanding-windows-kernel-pool-memory/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
