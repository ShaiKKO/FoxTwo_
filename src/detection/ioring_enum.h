/*
 * IoRing Handle Enumeration Module – Public Header
 *
 * Author: Colin MacRitchie | ziX Labs
 * Organization: ziX Labs — Security Research Division
 * File: ioring_enum.h
 * Version: 1.0
 * Date: 2025-11-30
 *
 * Summary
 * -------
 * Provides IoRing handle enumeration and analysis capabilities for the
 * Windows 11 Monitor Manager. Since ObRegisterCallbacks does not support
 * IoRing object type (only Process, Thread, Desktop), this module uses
 * handle table enumeration via SystemHandleInformation.
 *
 * SECURITY PROPERTIES:
 * - Input: All IORING_OBJECT pointers treated as hostile until validated
 * - Output: Object addresses masked per configurable policy
 * - Memory Safety: SEH guards all dereferences
 * - IRQL: Most functions require PASSIVE_LEVEL
 *
 * References:
 * - Vergilius Project: _IORING_OBJECT structure
 * - Microsoft Docs: ObRegisterCallbacks limitations
 */

#ifndef _ZIX_LABS_IORING_ENUM_H_
#define _ZIX_LABS_IORING_ENUM_H_

#ifndef _KERNEL_MODE
# error "This header is for kernel-mode only."
#endif

#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------
 * IORING_OBJECT Structure Offsets
 *
 * Source: Vergilius Project
 * https://www.vergiliusproject.com/kernels/x64/windows-11/22h2/_IORING_OBJECT
 *
 * SECURITY: These offsets are build-specific. Runtime validation required.
 *-------------------------------------------------------------------------*/

#define IORING_OBJECT_SIZE_22H2         0xD0
#define IORING_REGBUFFERSCOUNT_OFFSET   0xB0
#define IORING_REGBUFFERS_OFFSET        0xB8
#define IORING_REGFILESCOUNT_OFFSET     0xC0
#define IORING_REGFILES_OFFSET          0xC8

/*--------------------------------------------------------------------------
 * Build-Specific Offset Table
 *-------------------------------------------------------------------------*/
typedef struct _IORING_OFFSET_TABLE {
    ULONG BuildNumber;
    ULONG StructureSize;
    ULONG RegBuffersCountOffset;
    ULONG RegBuffersOffset;
    ULONG RegFilesCountOffset;
    ULONG RegFilesOffset;
} IORING_OFFSET_TABLE, *PIORING_OFFSET_TABLE;

/*--------------------------------------------------------------------------
 * IoRing Type Resolution State
 *-------------------------------------------------------------------------*/
typedef struct _MON_IORING_TYPE_INFO {
    UCHAR   TypeIndex;          /* Resolved object type index */
    USHORT  ObjectBodySize;     /* Expected: 0xD0 */
    BOOLEAN Initialized;        /* TRUE after successful init */
    ULONG   WindowsBuild;       /* Current OS build number */
} MON_IORING_TYPE_INFO, *PMON_IORING_TYPE_INFO;

/*--------------------------------------------------------------------------
 * Handle Info Structure for Enumeration Output
 *-------------------------------------------------------------------------*/
typedef struct _MON_IORING_HANDLE_INFO {
    ULONG   ProcessId;
    ULONG64 HandleValue;
    ULONG64 ObjectAddress;      /* Masked per policy */
    ULONG   AccessMask;
    ULONG   RegBuffersCount;
    ULONG   ViolationFlags;
} MON_IORING_HANDLE_INFO, *PMON_IORING_HANDLE_INFO;

/*--------------------------------------------------------------------------
 * Callback Signature for Enumeration
 *
 * Returns TRUE to continue enumeration, FALSE to stop early.
 *-------------------------------------------------------------------------*/
typedef BOOLEAN (NTAPI *PMON_IORING_CALLBACK)(
    _In_ ULONG ProcessId,
    _In_ HANDLE HandleValue,
    _In_ PVOID ObjectAddress,       /* Kernel address of IORING_OBJECT */
    _In_ ACCESS_MASK GrantedAccess,
    _In_opt_ PVOID Context
);

/*--------------------------------------------------------------------------
 * Public Function Prototypes
 *
 * NOTE: MON_OFFSET_RESOLUTION_METHOD is defined in win11_monitor_public.h
 *       to avoid duplication between kernel and user-mode headers.
 *-------------------------------------------------------------------------*/

/**
 * @function   MonIoRingEnumInitialize
 * @purpose    Initialize IoRing enumeration subsystem and resolve type info
 * @precondition IRQL == PASSIVE_LEVEL; Called from DriverEntry
 * @postcondition On success, g_IoRingTypeInfo populated and ready for use
 * @thread-safety Single-threaded init; not re-entrant
 * @side-effects Caches IoRing object type index and offset table
 * @returns    STATUS_SUCCESS if initialization succeeded
 *             STATUS_NOT_SUPPORTED if IoRing type not found
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS MonIoRingEnumInitialize(VOID);

/**
 * @function   MonIoRingEnumShutdown
 * @purpose    Clean up IoRing enumeration subsystem
 * @precondition IRQL == PASSIVE_LEVEL; Called from DriverUnload
 * @postcondition Type info cleared
 * @thread-safety Single-threaded shutdown
 * @side-effects None
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID MonIoRingEnumShutdown(VOID);

/**
 * @function   MonEnumerateIoRingObjects
 * @purpose    Enumerate all IoRing handles in the system
 * @precondition IRQL == PASSIVE_LEVEL; Monitoring enabled
 * @postcondition Callback invoked for each discovered IoRing handle
 * @thread-safety Re-entrant; uses local allocations only
 * @side-effects Allocates from paged pool; may trigger telemetry events
 *
 * @param[in] Callback - Function to call for each IoRing
 * @param[in] Context - Caller context passed to callback
 * @returns STATUS_SUCCESS if enumeration completed
 *          STATUS_INSUFFICIENT_RESOURCES on allocation failure
 *          STATUS_NOT_SUPPORTED if type info not initialized
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MonEnumerateIoRingObjects(
    _In_ PMON_IORING_CALLBACK Callback,
    _In_opt_ PVOID Context
);

/**
 * @function   MonGetIoRingOffsets
 * @purpose    Retrieve current build's IORING_OBJECT offset table
 * @precondition IRQL <= DISPATCH_LEVEL; Type info initialized
 * @postcondition Returns pointer to static offset table or NULL
 * @thread-safety Thread-safe read-only access
 * @side-effects None
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
const IORING_OFFSET_TABLE* MonGetIoRingOffsets(VOID);

/**
 * @function   MonGetIoRingTypeInfo
 * @purpose    Retrieve current IoRing type resolution state
 * @precondition IRQL <= DISPATCH_LEVEL
 * @postcondition Returns pointer to global type info (may be uninitialized)
 * @thread-safety Thread-safe read-only access
 * @side-effects None
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
const MON_IORING_TYPE_INFO* MonGetIoRingTypeInfo(VOID);

/**
 * @function   MonDetectWindowsBuild
 * @purpose    Detect current Windows build number via RtlGetVersion
 * @precondition IRQL == PASSIVE_LEVEL
 * @postcondition Returns build number or 0 on failure
 * @thread-safety Thread-safe
 * @side-effects None
 */
_IRQL_requires_(PASSIVE_LEVEL)
ULONG MonDetectWindowsBuild(VOID);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _ZIX_LABS_IORING_ENUM_H_ */
