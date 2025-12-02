/*
 * Windows 11 Monitor Manager – Public Interfaces and IOCTLs
 *
 * Author: Colin MacRitchie
 * Organization: ziX Performance Labs
 * File: win11_monitor_mgr.h
 * Version: 1.3
 * Date: 2025-12-01
 * Copyright:
 *   © 2025 ziX Performance Labs. All rights reserved. Proprietary and
 * confidential. Redistribution or disclosure without prior written consent is
 * prohibited.
 *
 * Summary
 * -------
 * This header defines the public API surface for the Windows11MonitorManager
 * WDM kernel driver. It exposes device naming, IOCTL contracts, and the
 * minimal data schemas consumed by privileged user-mode tooling or an
 * in-kernel test harness. All IOCTLs are defined with METHOD_BUFFERED to
 * leverage the I/O Manager for buffer marshalling and to avoid METHOD_NEITHER
 * pitfalls (see CWE-781). The driver itself performs strict input validation.
 *
 * Scope
 * -----
 * - Pure NT kernel (WDM), Windows 11 22H2+
 * - No KMDF dependency
 * - No cryptography in this surface; telemetry encryption is an internal,
 *   optional feature and not exposed here.
 *
 * Security Notes
 * --------------
 * - IOCTLs use FILE_ANY_ACCESS or READ/WRITE_ACCESS as appropriate.
 * - METHOD_NEITHER is intentionally avoided to reduce attack surface.
 * - All variable-length payloads must declare sizes explicitly; the driver
 *   enforces these at the boundary.
 */

#ifndef _WIN11_MONITOR_MGR_PUBLIC_H_
#define _WIN11_MONITOR_MGR_PUBLIC_H_

#ifndef _KERNEL_MODE
#error "This header is for kernel-mode and privileged tooling only."
#endif

#include <ntddk.h>

#include "win11_monitor_public.h"

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------
 * IOCTL Contracts
 *  - CATEGORY: FILE_DEVICE_UNKNOWN
 *  - METHOD:   METHOD_BUFFERED (safer default; the I/O Manager allocates
 *              a system buffer and copies user data in/out).
 *  - ACCESS:   FILE_ANY_ACCESS unless write semantics are required.
 *-------------------------------------------------------------------------*/

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _WIN11_MONITOR_MGR_PUBLIC_H_ */
