/*
 * Windows 11 Monitor Manager – Core Driver (WDM)
 *
 * Author: Colin MacRitchie
 * Organization: ziX Performance Labs
 * File: win11_monitor_mgr.c
 * Version: 1.4
 * Original Date: 2025-06-11
 * Revision Date: 2025-12-01
 * Copyright:
 *   © 2025 ziX Performance Labs. All rights reserved. Proprietary and confidential.
 *   Redistribution or disclosure without prior written consent is prohibited.
 *
 * Summary
 * -------
 * Central orchestration for kernel security monitoring on Windows 11.
 * Responsibilities:
 *  • Initialize device + public IOCTL surface
 *  • Coordinate pool tracking and IOP_MC inspection
 *  • Enforce zero-trust validation of inputs
 *  • Provide rate-limited, structured telemetry (ETW stub)
 *
 * Design Rationale
 * ----------------
 * - METHOD_BUFFERED IOCTLs minimize pointer risk (CWE-781).
 * - Lookaside + lock-free SLIST cut allocation/lock overhead on hot paths.
 * - All external inputs validated at the boundary before any dereference.
 * - Pool scanning is *eventually consistent* via work item/DPC scheduling
 *   to keep ISR/DPC latency low.
 *
 * IRQL & Concurrency
 * ------------------
 * - IOCTL handlers run at PASSIVE_LEVEL.
 * - Event queue push can occur at DISPATCH_LEVEL.
 * - Telemetry logging supports DISPATCH_LEVEL but offloads heavy work.
 */

#include <ntddk.h>
#include <ntstrsafe.h>

#include "win11_monitor_mgr.h"
#include "monitor_internal.h"
#include "iop_mc.h"           /* Structure parser: IopIsValidMcBufferEntry, IopQueryMcBufferEntry */
#include "telemetry_ringbuf.h" /* Ring buffer telemetry (E1) */
#include "ioring_intercept.h" /* IoRing interception (Phase 6) */
#include "process_profile.h"  /* Process behavior profiling (Phase 7) */
#include "anomaly_rules.h"    /* Anomaly detection rules (Phase 7) */

#pragma warning(push)
#pragma warning(disable: 4201) /* nameless struct/union in SAL headers */
#pragma warning(disable: 4214) /* bit field types other than int */

/* Global context (zero-init by loader) */
MONITOR_CONTEXT g_Mon;

/* Forward declarations (local) */
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     MonDriverUnload;

_Dispatch_type_(IRP_MJ_CREATE)         DRIVER_DISPATCH MonIrpCreate;
_Dispatch_type_(IRP_MJ_CLOSE)          DRIVER_DISPATCH MonIrpClose;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH MonIrpDeviceControl;

/* Internal helpers */
static VOID MonInitNames(_Out_ PUNICODE_STRING Dev, _Out_ PUNICODE_STRING Sym);
static NTSTATUS MonCreateDevice(_In_ PDRIVER_OBJECT DriverObject);
static VOID MonInitQueues(_Inout_ PMONITOR_CONTEXT Ctx);
static VOID MonDestroyQueues(_Inout_ PMONITOR_CONTEXT Ctx);
static VOID MonStopScan(_Inout_ PMONITOR_CONTEXT Ctx);
static NTSTATUS MonIoctlGetVersion(_Out_writes_bytes_(sizeof(ULONG)) PVOID Out, _In_ ULONG OutLen);
static NTSTATUS MonIoctlGetCaps(_Out_writes_bytes_(sizeof(ULONG)) PVOID Out, _In_ ULONG OutLen);
static NTSTATUS MonIoctlEnable(_In_reads_bytes_(sizeof(MONITOR_SETTINGS)) PVOID In, _In_ ULONG InLen);
static NTSTATUS MonIoctlDisable(VOID);
static NTSTATUS MonIoctlGetStats(_Out_writes_bytes_(sizeof(MONITOR_STATS)) PVOID Out, _In_ ULONG OutLen);
static NTSTATUS MonIoctlFetchEvents(_Out_writes_bytes_to_(OutLen, *BytesOut) PVOID Out, _In_ ULONG OutLen, _Out_ ULONG* BytesOut);
static NTSTATUS MonIoctlSetTelemetry(_In_reads_bytes_(sizeof(ULONG)) PVOID In, _In_ ULONG InLen);
static NTSTATUS MonIoctlSetEncryption(_In_reads_bytes_(sizeof(ULONG)) PVOID In, _In_ ULONG InLen);
static NTSTATUS MonIoctlScanNow(VOID);
static NTSTATUS MonIoctlParseIopMc(_In_reads_bytes_(sizeof(IOP_MC_BUFFER_ENTRY)) PVOID In, _In_ ULONG InLen, _Out_writes_bytes_(sizeof(IOP_MC_BUFFER_ENTRY_INFO)) PVOID Out, _In_ ULONG OutLen);
static NTSTATUS MonIoctlGetOffsetStatus(_Out_writes_bytes_(sizeof(MON_OFFSET_STATUS_OUTPUT)) PVOID Out, _In_ ULONG OutLen);
static NTSTATUS MonIoctlGetIoRingHandles(_Out_writes_bytes_to_(OutLen, *BytesOut) PVOID Out, _In_ ULONG OutLen, _Out_ ULONG* BytesOut);
static NTSTATUS MonIoctlSetMaskPolicy(_In_reads_bytes_(sizeof(MON_MASK_POLICY_INPUT)) PVOID In, _In_ ULONG InLen);
static NTSTATUS MonIoctlGetRateStats(_Out_writes_bytes_(sizeof(MON_RATE_LIMIT_STATS)) PVOID Out, _In_ ULONG OutLen);

/* Ring buffer IOCTLs (E1) */
static NTSTATUS MonIoctlRingBufConfigure(_In_reads_bytes_(sizeof(MON_RINGBUF_CONFIG_INPUT)) PVOID In, _In_ ULONG InLen);
static NTSTATUS MonIoctlRingBufSnapshot(_Out_writes_bytes_to_(OutLen, *BytesOut) PVOID Out, _In_ ULONG OutLen, _Out_ ULONG* BytesOut);
static NTSTATUS MonIoctlRingBufGetStats(_Out_writes_bytes_(sizeof(MON_RINGBUF_STATS_OUTPUT)) PVOID Out, _In_ ULONG OutLen);
static NTSTATUS MonIoctlRingBufClear(VOID);

/* Interception IOCTLs (Phase 6) */
static NTSTATUS MonIoctlInterceptValidate(_In_reads_bytes_(InLen) PVOID In, _In_ ULONG InLen, _Out_writes_bytes_(OutLen) PVOID Out, _In_ ULONG OutLen);
static NTSTATUS MonIoctlInterceptSetPolicy(_In_reads_bytes_(InLen) PVOID In, _In_ ULONG InLen);
static NTSTATUS MonIoctlInterceptGetPolicy(_Out_writes_bytes_(OutLen) PVOID Out, _In_ ULONG OutLen);
static NTSTATUS MonIoctlInterceptGetStats(_Out_writes_bytes_(OutLen) PVOID Out, _In_ ULONG OutLen);
static NTSTATUS MonIoctlInterceptResetStats(VOID);
static NTSTATUS MonIoctlInterceptEnable(_In_reads_bytes_(InLen) PVOID In, _In_ ULONG InLen);
static NTSTATUS MonIoctlInterceptAddBlacklist(_In_reads_bytes_(InLen) PVOID In, _In_ ULONG InLen);
static NTSTATUS MonIoctlInterceptRemoveBlacklist(_In_reads_bytes_(InLen) PVOID In, _In_ ULONG InLen);
static NTSTATUS MonIoctlInterceptGetBlacklist(_In_reads_bytes_(InLen) PVOID In, _In_ ULONG InLen, _Out_writes_bytes_to_(OutLen, *BytesOut) PVOID Out, _In_ ULONG OutLen, _Out_ ULONG* BytesOut);

/* Profile IOCTLs (Phase 7) */
static NTSTATUS MonIoctlProfileGet(_In_reads_bytes_(InLen) PVOID In, _In_ ULONG InLen, _Out_writes_bytes_(OutLen) PVOID Out, _In_ ULONG OutLen);
static NTSTATUS MonIoctlProfileList(_In_reads_bytes_(InLen) PVOID In, _In_ ULONG InLen, _Out_writes_bytes_to_(OutLen, *BytesOut) PVOID Out, _In_ ULONG OutLen, _Out_ ULONG* BytesOut);
static NTSTATUS MonIoctlProfileExportML(_In_reads_bytes_(InLen) PVOID In, _In_ ULONG InLen, _Out_writes_bytes_(OutLen) PVOID Out, _In_ ULONG OutLen);
static NTSTATUS MonIoctlProfileGetStats(_Out_writes_bytes_(OutLen) PVOID Out, _In_ ULONG OutLen);
static NTSTATUS MonIoctlProfileGetConfig(_Out_writes_bytes_(OutLen) PVOID Out, _In_ ULONG OutLen);
static NTSTATUS MonIoctlProfileSetConfig(_In_reads_bytes_(InLen) PVOID In, _In_ ULONG InLen);
static NTSTATUS MonIoctlProfileReset(VOID);

/* Anomaly IOCTLs (Phase 7) */
static NTSTATUS MonIoctlAnomalyGetRules(_In_reads_bytes_(InLen) PVOID In, _In_ ULONG InLen, _Out_writes_bytes_to_(OutLen, *BytesOut) PVOID Out, _In_ ULONG OutLen, _Out_ ULONG* BytesOut);
static NTSTATUS MonIoctlAnomalySetThreshold(_In_reads_bytes_(InLen) PVOID In, _In_ ULONG InLen);
static NTSTATUS MonIoctlAnomalyEnableRule(_In_reads_bytes_(InLen) PVOID In, _In_ ULONG InLen);
static NTSTATUS MonIoctlAnomalyGetStats(_Out_writes_bytes_(OutLen) PVOID Out, _In_ ULONG OutLen);
static NTSTATUS MonIoctlAnomalyResetStats(VOID);

/* Timer DPC -> schedules pool scan work */
_Function_class_(KDEFERRED_ROUTINE)
static VOID MonScanDpc(_In_ KDPC* Dpc, _In_opt_ PVOID DeferredContext, _In_opt_ PVOID SysArg1, _In_opt_ PVOID SysArg2);

/* Work item to perform scan */
_Function_class_(IO_WORKITEM_ROUTINE)
static VOID MonScanWorkItem(_In_ PDEVICE_OBJECT DeviceObject, _In_opt_ PVOID Context);

/*---------------------------------------------------------------------------
 * Driver Entry
 *-------------------------------------------------------------------------*/
_Use_decl_annotations_
NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    RtlZeroMemory(&g_Mon, sizeof(g_Mon));
    MonInitNames(&g_Mon.DeviceName, &g_Mon.SymLink);

    NTSTATUS status = MonCreateDevice(DriverObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Dispatch table */
    DriverObject->DriverUnload = MonDriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = MonIrpCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]  = MonIrpClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MonIrpDeviceControl;

    /* Initialize queues & telemetry */
    MonInitQueues(&g_Mon);
    (VOID)MonTelemetryInitialize(&g_Mon);

    /* Initialize pool tracker (periodic scan via DPC+work item) */
    status = MonPoolTrackerInitialize(&g_Mon, MonAnalyzeIoRingRegArray);
    if (!NT_SUCCESS(status)) {
        MonTelemetryShutdown(&g_Mon);
        MonDestroyQueues(&g_Mon);
        IoDeleteSymbolicLink(&g_Mon.SymLink);
        IoDeleteDevice(g_Mon.DeviceObject);
        return status;
    }

    /* Initialize dynamic offset resolver (E2) */
    status = MonOffsetResolverInitialize(NULL);
    if (!NT_SUCCESS(status)) {
        /* Non-fatal: continue without dynamic offset resolution */
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WIN11MON] Offset resolver init failed: 0x%08X\n", status);
    }

    /* Initialize IoRing enumeration subsystem (A1) */
    status = MonIoRingEnumInitialize();
    if (!NT_SUCCESS(status)) {
        /* Non-fatal: continue in degraded mode without IoRing enumeration */
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WIN11MON] IoRing enum init failed: 0x%08X (degraded mode)\n", status);
    }

    /* Initialize ETW TraceLogging provider (B1) */
    status = MonEtwInitialize();
    if (!NT_SUCCESS(status)) {
        /* Non-fatal: continue without ETW */
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WIN11MON] ETW init failed: 0x%08X\n", status);
    }

    /* Initialize address masking subsystem (B2) */
    status = MonAddrMaskInitialize();
    if (!NT_SUCCESS(status)) {
        /* Non-fatal: continue without address masking (uses default policy) */
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WIN11MON] Address masking init failed: 0x%08X\n", status);
    }

    /* Initialize per-process rate limiting (B3) */
    status = MonRateLimitInitialize();
    if (!NT_SUCCESS(status)) {
        /* Non-fatal: continue without per-process rate limiting */
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WIN11MON] Rate limiting init failed: 0x%08X\n", status);
    }

    /* Set device object for rate limiting cleanup timer */
    status = MonRateLimitSetDeviceObject(g_Mon.DeviceObject);
    if (!NT_SUCCESS(status)) {
        /* Non-fatal: cleanup will not be automated but rate limiting still works */
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WIN11MON] Rate limit cleanup timer init failed: 0x%08X\n", status);
    }

    /* Initialize ring buffer telemetry (E1) - uses default 1MB size */
    status = MonRingBufferInitialize(0);
    if (!NT_SUCCESS(status)) {
        /* Non-fatal: continue without ring buffer telemetry */
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WIN11MON] Ring buffer init failed: 0x%08X\n", status);
    }

    /* Initialize IoRing interception subsystem (Phase 6) */
    status = MonInterceptInitialize();
    if (!NT_SUCCESS(status)) {
        /* Non-fatal: continue without interception */
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WIN11MON] Intercept init failed: 0x%08X\n", status);
    }

    /* Initialize process behavior profiling (Phase 7) */
    status = MonProfileInitialize();
    if (!NT_SUCCESS(status)) {
        /* Non-fatal: continue without profiling */
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WIN11MON] Profile init failed: 0x%08X\n", status);
    }

    /* Initialize anomaly detection rules (Phase 7) */
    status = MonAnomalyInitialize();
    if (!NT_SUCCESS(status)) {
        /* Non-fatal: continue without anomaly detection */
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WIN11MON] Anomaly rules init failed: 0x%08X\n", status);
    }

    /* Timer/DPC for periodic scanning */
    KeInitializeTimer(&g_Mon.ScanTimer);
    KeInitializeDpc(&g_Mon.ScanDpc, MonScanDpc, &g_Mon);

    /* Default policy */
    g_Mon.RateLimitPerSec = MON_DEFAULT_RATE_LIMIT_PER_SEC;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON] Loaded v%d.%d.%d (caps=0x%X)\n",
        WIN11MON_VERSION_MAJOR, WIN11MON_VERSION_MINOR, WIN11MON_VERSION_BUILD,
        (WIN11MON_CAP_IOP_MC|WIN11MON_CAP_POOL_TRACK|WIN11MON_CAP_TELEMETRY|WIN11MON_CAP_RATE_LIMIT|WIN11MON_CAP_ENCRYPTION_STUB));

    return STATUS_SUCCESS;
}

/*---------------------------------------------------------------------------
 * Unload
 *-------------------------------------------------------------------------*/
_Use_decl_annotations_
VOID
MonDriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    /* Stop scanning and telemetry */
    MonStopScan(&g_Mon);
    MonPoolTrackerShutdown(&g_Mon);
    MonTelemetryShutdown(&g_Mon);

    /* Shutdown enhancement subsystems (reverse order of init) */
    MonAnomalyShutdown();     /* Phase 7: Anomaly rules */
    MonProfileShutdown();     /* Phase 7: Process profiling */
    MonInterceptShutdown();   /* Phase 6: IoRing interception */
    MonRingBufferShutdown();  /* E1: Ring buffer */
    MonRateLimitShutdown();
    MonAddrMaskShutdown();
    MonEtwShutdown();
    MonIoRingEnumShutdown();
    MonOffsetResolverShutdown();  /* E2: Offset resolver */

    /* Tear down queues */
    MonDestroyQueues(&g_Mon);

    /* Remove namespace */
    if (g_Mon.SymLink.Buffer) {
        IoDeleteSymbolicLink(&g_Mon.SymLink);
    }
    if (g_Mon.DeviceObject) {
        IoDeleteDevice(g_Mon.DeviceObject);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[WIN11MON] Unloaded\n");
}

/*---------------------------------------------------------------------------
 * Create/Close – minimal bookkeeping (no sharing restrictions)
 *-------------------------------------------------------------------------*/
_Use_decl_annotations_
NTSTATUS
MonIrpCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
MonIrpClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/*---------------------------------------------------------------------------
 * Device Control – IOCTL dispatcher
 *-------------------------------------------------------------------------*/
/**
 * @function   MonIrpDeviceControl
 * @purpose    IOCTL dispatcher (METHOD_BUFFERED); validates buffer sizes and sets exact bytesOut
 * @precondition IRQL == PASSIVE_LEVEL; DO_BUFFERED_IO set; uses SystemBuffer
 * @postcondition Output populated only on success; no persistent global state change
 * @thread-safety Serialized by I/O manager per device; independent IRPs may run concurrently
 * @side-effects Telemetry events may be enqueued on certain paths
 */
_Use_decl_annotations_
NTSTATUS
MonIrpDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = irpSp->Parameters.DeviceIoControl.IoControlCode;
    PVOID inBuf = Irp->AssociatedIrp.SystemBuffer;
    PVOID outBuf = Irp->AssociatedIrp.SystemBuffer;
    ULONG inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG bytesOut = 0;

    switch (code) {

    case IOCTL_MONITOR_GET_VERSION:
        status = MonIoctlGetVersion(outBuf, outLen);
        bytesOut = NT_SUCCESS(status) ? sizeof(ULONG) : 0;
        break;

    case IOCTL_MONITOR_GET_CAPABILITIES:
        status = MonIoctlGetCaps(outBuf, outLen);
        bytesOut = NT_SUCCESS(status) ? sizeof(ULONG) : 0;
        break;

    case IOCTL_MONITOR_ENABLE:
        status = MonIoctlEnable(inBuf, inLen);
        break;

    case IOCTL_MONITOR_DISABLE:
        status = MonIoctlDisable();
        break;

    case IOCTL_MONITOR_GET_STATS:
        status = MonIoctlGetStats(outBuf, outLen);
        bytesOut = NT_SUCCESS(status) ? sizeof(MONITOR_STATS) : 0;
        break;

    case IOCTL_MONITOR_FETCH_EVENTS:
        status = MonIoctlFetchEvents(outBuf, outLen, &bytesOut);
        break;

    case IOCTL_MONITOR_SET_TELEMETRY:
        status = MonIoctlSetTelemetry(inBuf, inLen);
        break;

    case IOCTL_MONITOR_SET_ENCRYPTION:
        status = MonIoctlSetEncryption(inBuf, inLen);
        break;

    case IOCTL_MONITOR_SCAN_NOW:
        status = MonIoctlScanNow();
        break;

    case IOCTL_MONITOR_PARSE_IOP_MC:
        status = MonIoctlParseIopMc(inBuf, inLen, outBuf, outLen);
        bytesOut = NT_SUCCESS(status) ? sizeof(IOP_MC_BUFFER_ENTRY_INFO) : 0;
        break;

    case IOCTL_MONITOR_GET_OFFSET_STATUS:
        status = MonIoctlGetOffsetStatus(outBuf, outLen);
        bytesOut = NT_SUCCESS(status) ? sizeof(MON_OFFSET_STATUS_OUTPUT) : 0;
        break;

    case IOCTL_MONITOR_GET_IORING_HANDLES:
        status = MonIoctlGetIoRingHandles(outBuf, outLen, &bytesOut);
        break;

    case IOCTL_MONITOR_SET_MASK_POLICY:
        status = MonIoctlSetMaskPolicy(inBuf, inLen);
        break;

    case IOCTL_MONITOR_GET_RATE_STATS:
        status = MonIoctlGetRateStats(outBuf, outLen);
        bytesOut = NT_SUCCESS(status) ? sizeof(MON_RATE_LIMIT_STATS) : 0;
        break;

    /* Ring buffer IOCTLs (E1) */
    case IOCTL_MONITOR_RINGBUF_CONFIGURE:
        status = MonIoctlRingBufConfigure(inBuf, inLen);
        break;

    case IOCTL_MONITOR_RINGBUF_SNAPSHOT:
        status = MonIoctlRingBufSnapshot(outBuf, outLen, &bytesOut);
        break;

    case IOCTL_MONITOR_RINGBUF_GET_STATS:
        status = MonIoctlRingBufGetStats(outBuf, outLen);
        bytesOut = NT_SUCCESS(status) ? sizeof(MON_RINGBUF_STATS_OUTPUT) : 0;
        break;

    case IOCTL_MONITOR_RINGBUF_CLEAR:
        status = MonIoctlRingBufClear();
        break;

    /* Interception IOCTLs (Phase 6) */
    case IOCTL_MONITOR_INTERCEPT_VALIDATE:
        status = MonIoctlInterceptValidate(inBuf, inLen, outBuf, outLen);
        bytesOut = NT_SUCCESS(status) ? sizeof(MON_INTERCEPT_RESPONSE) : 0;
        break;

    case IOCTL_MONITOR_INTERCEPT_SET_POLICY:
        status = MonIoctlInterceptSetPolicy(inBuf, inLen);
        break;

    case IOCTL_MONITOR_INTERCEPT_GET_POLICY:
        status = MonIoctlInterceptGetPolicy(outBuf, outLen);
        bytesOut = NT_SUCCESS(status) ? sizeof(MON_INTERCEPT_POLICY) : 0;
        break;

    case IOCTL_MONITOR_INTERCEPT_GET_STATS:
        status = MonIoctlInterceptGetStats(outBuf, outLen);
        bytesOut = NT_SUCCESS(status) ? sizeof(MON_INTERCEPT_STATS) : 0;
        break;

    case IOCTL_MONITOR_INTERCEPT_RESET_STATS:
        status = MonIoctlInterceptResetStats();
        break;

    case IOCTL_MONITOR_INTERCEPT_ENABLE:
        status = MonIoctlInterceptEnable(inBuf, inLen);
        break;

    case IOCTL_MONITOR_INTERCEPT_ADD_BL:
        status = MonIoctlInterceptAddBlacklist(inBuf, inLen);
        break;

    case IOCTL_MONITOR_INTERCEPT_REMOVE_BL:
        status = MonIoctlInterceptRemoveBlacklist(inBuf, inLen);
        break;

    case IOCTL_MONITOR_INTERCEPT_GET_BL:
        status = MonIoctlInterceptGetBlacklist(inBuf, inLen, outBuf, outLen, &bytesOut);
        break;

    /* Profile IOCTLs (Phase 7) */
    case IOCTL_MONITOR_PROFILE_GET:
        status = MonIoctlProfileGet(inBuf, inLen, outBuf, outLen);
        bytesOut = NT_SUCCESS(status) ? sizeof(MON_PROFILE_SUMMARY_PUBLIC) : 0;
        break;

    case IOCTL_MONITOR_PROFILE_LIST:
        status = MonIoctlProfileList(inBuf, inLen, outBuf, outLen, &bytesOut);
        break;

    case IOCTL_MONITOR_PROFILE_EXPORT_ML:
        status = MonIoctlProfileExportML(inBuf, inLen, outBuf, outLen);
        bytesOut = NT_SUCCESS(status) ? sizeof(MON_ML_FEATURE_VECTOR_PUBLIC) : 0;
        break;

    case IOCTL_MONITOR_PROFILE_GET_STATS:
        status = MonIoctlProfileGetStats(outBuf, outLen);
        bytesOut = NT_SUCCESS(status) ? sizeof(MON_PROFILE_STATS_PUBLIC) : 0;
        break;

    case IOCTL_MONITOR_PROFILE_GET_CONFIG:
        status = MonIoctlProfileGetConfig(outBuf, outLen);
        bytesOut = NT_SUCCESS(status) ? sizeof(MON_PROFILE_CONFIG_PUBLIC) : 0;
        break;

    case IOCTL_MONITOR_PROFILE_SET_CONFIG:
        status = MonIoctlProfileSetConfig(inBuf, inLen);
        break;

    case IOCTL_MONITOR_PROFILE_RESET:
        status = MonIoctlProfileReset();
        break;

    /* Anomaly IOCTLs (Phase 7) */
    case IOCTL_MONITOR_ANOMALY_GET_RULES:
        status = MonIoctlAnomalyGetRules(inBuf, inLen, outBuf, outLen, &bytesOut);
        break;

    case IOCTL_MONITOR_ANOMALY_SET_THRESHOLD:
        status = MonIoctlAnomalySetThreshold(inBuf, inLen);
        break;

    case IOCTL_MONITOR_ANOMALY_ENABLE_RULE:
        status = MonIoctlAnomalyEnableRule(inBuf, inLen);
        break;

    case IOCTL_MONITOR_ANOMALY_GET_STATS:
        status = MonIoctlAnomalyGetStats(outBuf, outLen);
        bytesOut = NT_SUCCESS(status) ? sizeof(MON_ANOMALY_STATS_PUBLIC) : 0;
        break;

    case IOCTL_MONITOR_ANOMALY_RESET_STATS:
        status = MonIoctlAnomalyResetStats();
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesOut;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/*---------------------------------------------------------------------------
 * IOCTL Implementations
 *-------------------------------------------------------------------------*/

static NTSTATUS MonIoctlGetVersion(PVOID Out, ULONG OutLen)
{
    if (Out == NULL) return STATUS_INVALID_PARAMETER;
    if (OutLen < sizeof(ULONG)) return STATUS_BUFFER_TOO_SMALL;
    ULONG v = (WIN11MON_VERSION_MAJOR << 24) |
              (WIN11MON_VERSION_MINOR << 16) |
              (WIN11MON_VERSION_BUILD  & 0xFFFF);
    RtlCopyMemory(Out, &v, sizeof(v));
    return STATUS_SUCCESS;
}

static NTSTATUS MonIoctlGetCaps(PVOID Out, ULONG OutLen)
{
    if (Out == NULL) return STATUS_INVALID_PARAMETER;
    if (OutLen < sizeof(ULONG)) return STATUS_BUFFER_TOO_SMALL;

    ULONG caps = WIN11MON_CAP_IOP_MC |
                 WIN11MON_CAP_POOL_TRACK |
                 WIN11MON_CAP_TELEMETRY |
                 WIN11MON_CAP_RATE_LIMIT |
                 WIN11MON_CAP_ENCRYPTION_STUB;

    /* Add enhancement capabilities if available */
    const MON_IORING_TYPE_INFO* typeInfo = MonGetIoRingTypeInfo();
    if (typeInfo != NULL && typeInfo->Initialized) {
        caps |= WIN11MON_CAP_IORING_ENUM;
    }

    if (MonIsRegBuffersValidationAvailable()) {
        caps |= WIN11MON_CAP_REGBUF_INTEGRITY;
    }

    if (MonEtwIsEnabled()) {
        caps |= WIN11MON_CAP_ETW_PROVIDER;
    }

    /* B2: Address masking - always available after init */
    caps |= WIN11MON_CAP_ADDR_MASKING;

    /* B3: Per-process rate limiting */
    if (MonRateLimitIsEnabled()) {
        caps |= WIN11MON_CAP_PERPROC_RATELIMIT;
    }

    /* C1: Runtime offset resolution - always available when IoRing offsets valid */
    if (MonGetIoRingOffsets() != NULL) {
        caps |= WIN11MON_CAP_RUNTIME_OFFSETS;
    }

    /* D1: MITRE ATT&CK tagging - always available with ETW */
    if (MonEtwIsEnabled()) {
        caps |= WIN11MON_CAP_ATTACK_TAGGING;
    }

    /* E1: Ring buffer telemetry */
    if (MonRingBufferIsInitialized()) {
        caps |= WIN11MON_CAP_RING_BUFFER;
    }

    /* Phase 6: IoRing interception */
    if (MonInterceptIsInitialized()) {
        caps |= WIN11MON_CAP_IORING_INTERCEPT;
    }

    /* Phase 7: Process profiling and anomaly detection */
    if (MonProfileIsInitialized()) {
        caps |= WIN11MON_CAP_PROCESS_PROFILE;
    }
    if (MonAnomalyIsInitialized()) {
        caps |= WIN11MON_CAP_ANOMALY_RULES;
    }

    RtlCopyMemory(Out, &caps, sizeof(caps));
    return STATUS_SUCCESS;
}

static NTSTATUS MonIoctlEnable(PVOID In, ULONG InLen)
{
    if (InLen != sizeof(MONITOR_SETTINGS) || In == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    const MONITOR_SETTINGS* s = (const MONITOR_SETTINGS*)In;
    if (s->Size != sizeof(MONITOR_SETTINGS)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (s->EnableMonitoring > 1 ||
        s->EnableTelemetry  > 1 ||
        s->EnableEncryption > 1) {
        return STATUS_INVALID_PARAMETER;
    }
    /* Apply flags (0/1 only) */
    InterlockedExchange(&g_Mon.TelemetryEnabled, s->EnableTelemetry ? 1 : 0);
    InterlockedExchange(&g_Mon.EncryptionEnabled, s->EnableEncryption ? 1 : 0);
    g_Mon.RateLimitPerSec = (s->RateLimitPerSec == 0) ? MON_DEFAULT_RATE_LIMIT_PER_SEC : s->RateLimitPerSec;

    /* Start scanning if requested */
    if (s->EnableMonitoring) {
        InterlockedExchange(&g_Mon.MonitoringEnabled, 1);
        MonPoolScanSchedule(&g_Mon, 100 /*ms*/);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS MonIoctlDisable(VOID)
{
    InterlockedExchange(&g_Mon.MonitoringEnabled, 0);
    return STATUS_SUCCESS;
}

static NTSTATUS MonIoctlGetStats(PVOID Out, ULONG OutLen)
{
    if (Out == NULL) return STATUS_INVALID_PARAMETER;
    if (OutLen < sizeof(MONITOR_STATS)) return STATUS_BUFFER_TOO_SMALL;
    MONITOR_STATS* st = (MONITOR_STATS*)Out;
    RtlZeroMemory(st, sizeof(*st));
    st->Size = sizeof(*st);
    st->TotalAllocations   = g_Mon.TotalAllocations;
    st->IopMcDetections    = g_Mon.IopMcDetections;
    st->CrossVmDetections  = g_Mon.CrossVmDetections;
    st->PolicyViolations   = g_Mon.PolicyViolations;
    st->DroppedEvents      = g_Mon.DroppedEvents;
    st->PoolEntryCount     = 0; /* filled by pool tracker if needed */
    st->TelemetryEventCount= (ULONG)g_Mon.EventCount;
    st->CurrentRateLimit   = g_Mon.RateLimitPerSec;
    return STATUS_SUCCESS;
}

static NTSTATUS MonIoctlFetchEvents(PVOID Out, ULONG OutLen, ULONG* BytesOut)
{
    *BytesOut = 0;
    if (Out == NULL || OutLen < sizeof(EVENT_BLOB)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Pop one event from SLIST */
    PSLIST_ENTRY le = InterlockedPopEntrySList(&g_Mon.EventQueue);
    if (!le) {
        return STATUS_NO_MORE_ENTRIES;
    }

    PMON_EVENT_NODE node = CONTAINING_RECORD(le, MON_EVENT_NODE, SListEntry);
    const ULONG baseSize = RTL_SIZEOF_THROUGH_FIELD(MON_EVENT_NODE, Event);
    if (node->NodeSize < baseSize) {
        ExFreeToNPagedLookasideList(&g_Mon.EventLookaside, node);
        InterlockedDecrement(&g_Mon.EventCount);
        return STATUS_INTERNAL_ERROR;
    }
    const ULONG need = node->NodeSize - baseSize;
    const ULONG total = sizeof(EVENT_BLOB) + need;
    if (OutLen < total) {
        /* push back event and ask for more space */
        InterlockedPushEntrySList(&g_Mon.EventQueue, le);
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(Out, &node->Event, sizeof(EVENT_BLOB) + need);
    InterlockedDecrement(&g_Mon.EventCount);

    ExFreeToNPagedLookasideList(&g_Mon.EventLookaside, node);

    *BytesOut = total;
    return STATUS_SUCCESS;
}

static NTSTATUS MonIoctlSetTelemetry(PVOID In, ULONG InLen)
{
    if (InLen != sizeof(ULONG) || In == NULL) return STATUS_INVALID_PARAMETER;
    ULONG enable = *(ULONG*)In ? 1 : 0;
    InterlockedExchange(&g_Mon.TelemetryEnabled, enable);
    return STATUS_SUCCESS;
}

static NTSTATUS MonIoctlSetEncryption(PVOID In, ULONG InLen)
{
    if (InLen != sizeof(ULONG) || In == NULL) return STATUS_INVALID_PARAMETER;
    ULONG enable = *(ULONG*)In ? 1 : 0;
    InterlockedExchange(&g_Mon.EncryptionEnabled, enable);
    return STATUS_SUCCESS;
}

static NTSTATUS MonIoctlScanNow(VOID)
{
    return MonPoolScanNow(&g_Mon);
}

static NTSTATUS MonIoctlParseIopMc(PVOID In, ULONG InLen, PVOID Out, ULONG OutLen)
{
    if (In == NULL || Out == NULL ||
        InLen < sizeof(IOP_MC_BUFFER_ENTRY) ||
        OutLen < sizeof(IOP_MC_BUFFER_ENTRY_INFO)) {
        return STATUS_INVALID_PARAMETER;
    }

    IOP_MC_BUFFER_ENTRY_INFO info;
    RtlZeroMemory(&info, sizeof(info));

    /* SECURITY: Treat In as hostile. IopQueryMcBufferEntryEx uses SEH and policy flags internally. */
    NTSTATUS status = IopQueryMcBufferEntryEx(
        (PIOP_MC_BUFFER_ENTRY)In,
        &info,
        IOP_MC_QF_MASK_ADDRESS
        );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlCopyMemory(Out, &info, sizeof(info));
    return STATUS_SUCCESS;
}

static NTSTATUS MonIoctlGetOffsetStatus(PVOID Out, ULONG OutLen)
{
    if (Out == NULL) return STATUS_INVALID_PARAMETER;
    if (OutLen < sizeof(MON_OFFSET_STATUS_OUTPUT)) return STATUS_BUFFER_TOO_SMALL;

    MON_OFFSET_STATUS_OUTPUT outStatus = {0};
    outStatus.Size = sizeof(MON_OFFSET_STATUS_OUTPUT);

    /* Use offset resolver for build and source info (E2) */
    if (MonOffsetResolverIsInitialized()) {
        MON_OFFSET_RESOLVER_STATS resolverStats = {0};
        MonOffsetResolverGetStats(&resolverStats);
        outStatus.WindowsBuildNumber = resolverStats.CurrentBuild;

        /* Map resolver source to public method enum */
        MON_OFFSET_SOURCE source = MonGetOffsetSource(MON_STRUCT_IORING_OBJECT);
        switch (source) {
        case MonOffsetSource_Embedded:
            outStatus.Method = MonOffsetMethod_Embedded;
            break;
        case MonOffsetSource_Signature:
            outStatus.Method = MonOffsetMethod_Detected;
            break;
        case MonOffsetSource_Inferred:
            outStatus.Method = MonOffsetMethod_Embedded; /* Treat inferred as embedded variant */
            break;
        default:
            outStatus.Method = MonOffsetMethod_Degraded;
            break;
        }

        /* Check if IORING_OBJECT offsets are available and validated */
        MON_STRUCTURE_OFFSETS ioringOffsets = {0};
        NTSTATUS st = MonGetStructureOffsets(MON_STRUCT_IORING_OBJECT, &ioringOffsets);
        if (NT_SUCCESS(st)) {
            outStatus.IoRingOffsetsValid = TRUE;
            outStatus.IoRingStructureSize = ioringOffsets.StructureSize;
        } else {
            outStatus.IoRingOffsetsValid = FALSE;
        }

        if (resolverStats.Degraded) {
            outStatus.Method = MonOffsetMethod_Degraded;
        }
    } else {
        /* Fallback to legacy path */
        const MON_IORING_TYPE_INFO* typeInfo = MonGetIoRingTypeInfo();
        if (typeInfo != NULL) {
            outStatus.WindowsBuildNumber = typeInfo->WindowsBuild;
        }

        const IORING_OFFSET_TABLE* offsets = MonGetIoRingOffsets();
        if (offsets != NULL) {
            outStatus.Method = MonOffsetMethod_Embedded;
            outStatus.IoRingOffsetsValid = TRUE;
            outStatus.IoRingStructureSize = offsets->StructureSize;
        } else {
            outStatus.Method = MonOffsetMethod_Degraded;
            outStatus.IoRingOffsetsValid = FALSE;
        }
    }

    /* IOP_MC offsets are always embedded */
    outStatus.IopMcOffsetsValid = TRUE;
    outStatus.IopMcStructureSize = IOP_MC_BUFFER_ENTRY_SIZE;

    RtlCopyMemory(Out, &outStatus, sizeof(outStatus));
    return STATUS_SUCCESS;
}

/**
 * @function   MonIoctlSetMaskPolicy
 * @purpose    Configure address masking policy (B2 enhancement)
 * @precondition IRQL == PASSIVE_LEVEL; input buffer valid
 * @postcondition Policy updated atomically
 * @thread-safety Thread-safe via MonAddrMaskSetPolicy
 */
static NTSTATUS MonIoctlSetMaskPolicy(PVOID In, ULONG InLen)
{
    if (In == NULL || InLen < sizeof(MON_MASK_POLICY_INPUT)) {
        return STATUS_INVALID_PARAMETER;
    }

    const MON_MASK_POLICY_INPUT* input = (const MON_MASK_POLICY_INPUT*)In;
    if (input->Size != sizeof(MON_MASK_POLICY_INPUT)) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Validate policy range */
    if (input->Policy > MonMaskPolicy_Zero_Public) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Map public enum to internal enum (they have matching values) */
    MON_ADDRESS_MASK_POLICY internalPolicy = (MON_ADDRESS_MASK_POLICY)input->Policy;

    return MonAddrMaskSetPolicy(internalPolicy);
}

/**
 * @function   MonIoctlGetRateStats
 * @purpose    Get per-process rate limiting statistics (B3 enhancement)
 * @precondition IRQL == PASSIVE_LEVEL; output buffer valid
 * @postcondition Statistics copied to output
 * @thread-safety Thread-safe via MonRateLimitGetStats
 */
static NTSTATUS MonIoctlGetRateStats(PVOID Out, ULONG OutLen)
{
    if (Out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (OutLen < sizeof(MON_RATE_LIMIT_STATS)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    MON_RATE_LIMIT_INTERNAL_STATS internalStats = {0};
    MonRateLimitGetStats(&internalStats);

    /* Map internal stats to public structure */
    MON_RATE_LIMIT_STATS* output = (MON_RATE_LIMIT_STATS*)Out;
    output->Size = sizeof(MON_RATE_LIMIT_STATS);
    output->ActiveProcessCount = internalStats.ActiveProcessCount;
    output->TotalEventsAllowed = internalStats.TotalEventsAllowed;
    output->TotalEventsDropped = internalStats.TotalEventsDropped;
    output->ProcessDropCount = internalStats.ProcessDropCount;
    output->GlobalDropCount = internalStats.GlobalDropCount;
    output->CurrentGlobalRate = internalStats.CurrentGlobalRate;
    output->PeakGlobalRate = internalStats.PeakGlobalRate;
    output->GlobalLimitPerSec = internalStats.GlobalLimitPerSec;
    output->PerProcessLimitPerSec = internalStats.PerProcessLimitPerSec;

    return STATUS_SUCCESS;
}

/*---------------------------------------------------------------------------
 * Ring Buffer IOCTL Implementations (E1)
 *-------------------------------------------------------------------------*/

/**
 * @function   MonIoctlRingBufConfigure
 * @purpose    Configure ring buffer size (E1 enhancement)
 * @note       Currently only logs the request - resize requires restart
 */
static NTSTATUS MonIoctlRingBufConfigure(PVOID In, ULONG InLen)
{
    if (In == NULL || InLen < sizeof(MON_RINGBUF_CONFIG_INPUT)) {
        return STATUS_INVALID_PARAMETER;
    }

    const MON_RINGBUF_CONFIG_INPUT* input = (const MON_RINGBUF_CONFIG_INPUT*)In;
    if (input->Size != sizeof(MON_RINGBUF_CONFIG_INPUT)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (input->Flags != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * Note: Ring buffer resize requires reinitialization which would lose
     * existing events. For now, just log the request. A future enhancement
     * could support runtime resize with event migration.
     */
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WIN11MON][RING] Configure request: size=%lu (current init=%s)\n",
        input->BufferSizeBytes,
        MonRingBufferIsInitialized() ? "YES" : "NO");

    return STATUS_SUCCESS;
}

/**
 * @function   MonIoctlRingBufSnapshot
 * @purpose    Non-destructive copy of ring buffer contents (E1 enhancement)
 */
static NTSTATUS MonIoctlRingBufSnapshot(PVOID Out, ULONG OutLen, ULONG* BytesOut)
{
    *BytesOut = 0;

    if (Out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!MonRingBufferIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS status = MonRingBufferSnapshot(Out, OutLen, BytesOut);
    return status;
}

/**
 * @function   MonIoctlRingBufGetStats
 * @purpose    Get ring buffer statistics (E1 enhancement)
 */
static NTSTATUS MonIoctlRingBufGetStats(PVOID Out, ULONG OutLen)
{
    if (Out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (OutLen < sizeof(MON_RINGBUF_STATS_OUTPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (!MonRingBufferIsInitialized()) {
        /* Return zeroed stats if not initialized */
        RtlZeroMemory(Out, sizeof(MON_RINGBUF_STATS_OUTPUT));
        ((PMON_RINGBUF_STATS_OUTPUT)Out)->Size = sizeof(MON_RINGBUF_STATS_OUTPUT);
        return STATUS_SUCCESS;
    }

    MON_RING_BUFFER_STATS internalStats = {0};
    MonRingBufferGetStats(&internalStats);

    /* Map to public structure */
    MON_RINGBUF_STATS_OUTPUT* output = (MON_RINGBUF_STATS_OUTPUT*)Out;
    output->Size = sizeof(MON_RINGBUF_STATS_OUTPUT);
    output->BufferSizeBytes = internalStats.BufferSizeBytes;
    output->UsedBytes = internalStats.UsedBytes;
    output->FreeBytes = internalStats.FreeBytes;
    output->EventCount = internalStats.EventCount;
    output->TotalEventsWritten = internalStats.TotalEventsWritten;
    output->EventsOverwritten = internalStats.EventsOverwritten;
    output->EventsDropped = internalStats.EventsDropped;
    output->WrapCount = internalStats.WrapCount;
    output->OldestTimestamp = internalStats.OldestTimestamp.QuadPart;
    output->NewestTimestamp = internalStats.NewestTimestamp.QuadPart;

    return STATUS_SUCCESS;
}

/**
 * @function   MonIoctlRingBufClear
 * @purpose    Clear all events from ring buffer (E1 enhancement)
 */
static NTSTATUS MonIoctlRingBufClear(VOID)
{
    if (!MonRingBufferIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    MonRingBufferClear();
    return STATUS_SUCCESS;
}

/*---------------------------------------------------------------------------
 * Interception IOCTL Implementations (Phase 6)
 *-------------------------------------------------------------------------*/

/**
 * @function   MonIoctlInterceptValidate
 * @purpose    Validate IoRing submission via policy engine
 */
static NTSTATUS MonIoctlInterceptValidate(PVOID In, ULONG InLen, PVOID Out, ULONG OutLen)
{
    if (In == NULL || Out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (OutLen < sizeof(MON_INTERCEPT_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (!MonInterceptIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    MON_INTERCEPT_RESPONSE response = {0};
    NTSTATUS status = MonInterceptValidateSubmission(
        (PMON_INTERCEPT_REQUEST)In,
        InLen,
        &response
    );

    RtlCopyMemory(Out, &response, sizeof(response));
    return status;
}

/**
 * @function   MonIoctlInterceptSetPolicy
 * @purpose    Configure interception policy
 */
static NTSTATUS MonIoctlInterceptSetPolicy(PVOID In, ULONG InLen)
{
    if (In == NULL || InLen < sizeof(MON_INTERCEPT_POLICY)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!MonInterceptIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    return MonInterceptSetPolicy((PMON_INTERCEPT_POLICY)In);
}

/**
 * @function   MonIoctlInterceptGetPolicy
 * @purpose    Get current interception policy
 */
static NTSTATUS MonIoctlInterceptGetPolicy(PVOID Out, ULONG OutLen)
{
    if (Out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (OutLen < sizeof(MON_INTERCEPT_POLICY)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    MonInterceptGetPolicy((PMON_INTERCEPT_POLICY)Out);
    return STATUS_SUCCESS;
}

/**
 * @function   MonIoctlInterceptGetStats
 * @purpose    Get interception statistics
 */
static NTSTATUS MonIoctlInterceptGetStats(PVOID Out, ULONG OutLen)
{
    if (Out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (OutLen < sizeof(MON_INTERCEPT_STATS)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    MonInterceptGetStats((PMON_INTERCEPT_STATS)Out);
    return STATUS_SUCCESS;
}

/**
 * @function   MonIoctlInterceptResetStats
 * @purpose    Reset interception statistics
 */
static NTSTATUS MonIoctlInterceptResetStats(VOID)
{
    if (!MonInterceptIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    MonInterceptResetStats();
    return STATUS_SUCCESS;
}

/**
 * @function   MonIoctlInterceptEnable
 * @purpose    Enable or disable interception
 */
static NTSTATUS MonIoctlInterceptEnable(PVOID In, ULONG InLen)
{
    if (In == NULL || InLen < sizeof(ULONG)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!MonInterceptIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    ULONG enable = *(PULONG)In;
    MonInterceptEnable(enable != 0);
    return STATUS_SUCCESS;
}

/**
 * @function   MonIoctlInterceptAddBlacklist
 * @purpose    Add process to blacklist
 */
static NTSTATUS MonIoctlInterceptAddBlacklist(PVOID In, ULONG InLen)
{
    if (In == NULL || InLen < sizeof(MON_INTERCEPT_BLACKLIST_ADD_INPUT)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!MonInterceptIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    const MON_INTERCEPT_BLACKLIST_ADD_INPUT* input = (const MON_INTERCEPT_BLACKLIST_ADD_INPUT*)In;

    return MonInterceptAddToBlacklist(
        input->ProcessId,
        NULL,  /* ProcessName - not provided in input */
        input->Reason
    );
}

/**
 * @function   MonIoctlInterceptRemoveBlacklist
 * @purpose    Remove process from blacklist
 */
static NTSTATUS MonIoctlInterceptRemoveBlacklist(PVOID In, ULONG InLen)
{
    if (In == NULL || InLen < sizeof(ULONG)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!MonInterceptIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    ULONG processId = *(PULONG)In;
    return MonInterceptRemoveFromBlacklist(processId) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/**
 * @function   MonIoctlInterceptGetBlacklist
 * @purpose    Enumerate blacklisted processes
 */
static NTSTATUS MonIoctlInterceptGetBlacklist(PVOID In, ULONG InLen, PVOID Out, ULONG OutLen, ULONG* BytesOut)
{
    NTSTATUS status;
    ULONG maxEntries;
    ULONG entryCount = 0;

    *BytesOut = 0;

    if (In == NULL || InLen < sizeof(ULONG)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!MonInterceptIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    /* Calculate max entries that fit in output buffer */
    maxEntries = OutLen / sizeof(MON_BLACKLIST_ENTRY);
    if (maxEntries == 0) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Cap to requested max from input */
    ULONG requestedMax = *(PULONG)In;
    if (requestedMax > 0 && requestedMax < maxEntries) {
        maxEntries = requestedMax;
    }

    /* Enumerate blacklist via kernel API */
    status = MonInterceptEnumerateBlacklist(
        (PMON_BLACKLIST_ENTRY)Out,
        maxEntries,
        &entryCount
    );

    if (NT_SUCCESS(status)) {
        *BytesOut = entryCount * sizeof(MON_BLACKLIST_ENTRY);
    }

    return status;
}

/*---------------------------------------------------------------------------
 * IoRing Handle Enumeration Context (for callback)
 *-------------------------------------------------------------------------*/
typedef struct _IORING_ENUM_CONTEXT {
    PMON_IORING_HANDLE_INFO OutputBuffer;
    ULONG MaxHandles;
    ULONG CurrentCount;
} IORING_ENUM_CONTEXT, *PIORING_ENUM_CONTEXT;

static BOOLEAN NTAPI MonIoRingEnumCallback(
    _In_ ULONG ProcessId,
    _In_ HANDLE HandleValue,
    _In_ PVOID ObjectAddress,
    _In_ ACCESS_MASK GrantedAccess,
    _In_opt_ PVOID Context
)
{
    PIORING_ENUM_CONTEXT ctx = (PIORING_ENUM_CONTEXT)Context;
    if (ctx == NULL || ctx->CurrentCount >= ctx->MaxHandles) {
        return FALSE;  /* Stop enumeration */
    }

    PMON_IORING_HANDLE_INFO info = &ctx->OutputBuffer[ctx->CurrentCount];
    info->ProcessId = ProcessId;
    info->HandleValue = (ULONG64)HandleValue;
    info->ObjectAddress = MonMaskAddress((ULONG64)ObjectAddress);
    info->AccessMask = GrantedAccess;
    info->RegBuffersCount = 0;
    info->ViolationFlags = 0;

    /* Try to validate RegBuffers if offsets available */
    if (MonIsRegBuffersValidationAvailable() && ObjectAddress != NULL) {
        MON_REGBUF_VIOLATION_INFO violInfo = {0};
        ULONG violations = MonValidateIoRingRegBuffers(ObjectAddress, &violInfo);
        info->ViolationFlags = violations;

        /* Try to read RegBuffersCount safely */
        const IORING_OFFSET_TABLE* offsets = MonGetIoRingOffsets();
        if (offsets != NULL) {
            __try {
                info->RegBuffersCount = *(PULONG)((PUCHAR)ObjectAddress +
                                                   offsets->RegBuffersCountOffset);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                info->RegBuffersCount = 0;
            }
        }
    }

    ctx->CurrentCount++;
    return TRUE;  /* Continue enumeration */
}

static NTSTATUS MonIoctlGetIoRingHandles(PVOID Out, ULONG OutLen, ULONG* BytesOut)
{
    *BytesOut = 0;

    if (Out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Check minimum buffer for header */
    if (OutLen < sizeof(ULONG) * 2) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Check if IoRing enumeration is available */
    const MON_IORING_TYPE_INFO* typeInfo = MonGetIoRingTypeInfo();
    if (typeInfo == NULL || !typeInfo->Initialized) {
        return STATUS_NOT_SUPPORTED;
    }

    /* Calculate how many handles can fit */
    const ULONG headerSize = sizeof(ULONG) * 2;  /* Size + HandleCount */
    const ULONG availableSpace = OutLen - headerSize;
    const ULONG maxHandles = availableSpace / sizeof(MON_IORING_HANDLE_INFO);

    if (maxHandles == 0) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Allocate temporary buffer for handles (will be copied to output) */
    PMON_IORING_HANDLE_INFO handleArray = (PMON_IORING_HANDLE_INFO)
        MonAllocatePoolPaged(maxHandles * sizeof(MON_IORING_HANDLE_INFO), MON_POOL_TAG);
    if (handleArray == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(handleArray, maxHandles * sizeof(MON_IORING_HANDLE_INFO));

    /* Set up enumeration context */
    IORING_ENUM_CONTEXT ctx = {0};
    ctx.OutputBuffer = handleArray;
    ctx.MaxHandles = maxHandles;
    ctx.CurrentCount = 0;

    /* Enumerate IoRing handles */
    NTSTATUS status = MonEnumerateIoRingObjects(MonIoRingEnumCallback, &ctx);
    if (!NT_SUCCESS(status) && status != STATUS_NOT_SUPPORTED) {
        ExFreePoolWithTag(handleArray, MON_POOL_TAG);
        return status;
    }

    /* Build output structure */
    PULONG outHeader = (PULONG)Out;
    const ULONG totalSize = headerSize + (ctx.CurrentCount * sizeof(MON_IORING_HANDLE_INFO));
    outHeader[0] = totalSize;        /* Size */
    outHeader[1] = ctx.CurrentCount; /* HandleCount */

    /* Copy handle array after header */
    if (ctx.CurrentCount > 0) {
        RtlCopyMemory((PUCHAR)Out + headerSize, handleArray,
                      ctx.CurrentCount * sizeof(MON_IORING_HANDLE_INFO));
    }

    ExFreePoolWithTag(handleArray, MON_POOL_TAG);

    *BytesOut = totalSize;
    return STATUS_SUCCESS;
}

/*---------------------------------------------------------------------------
 * Profile IOCTL Implementations (Phase 7)
 *-------------------------------------------------------------------------*/

static NTSTATUS MonIoctlProfileGet(PVOID In, ULONG InLen, PVOID Out, ULONG OutLen)
{
    ULONG processId;
    MON_PROFILE_SUMMARY summary;
    NTSTATUS status;

    if (In == NULL || InLen < sizeof(ULONG)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Out == NULL || OutLen < sizeof(MON_PROFILE_SUMMARY_PUBLIC)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (!MonProfileIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    processId = *(PULONG)In;
    status = MonProfileGetSummary(processId, &summary);

    if (NT_SUCCESS(status)) {
        /* Map internal to public structure */
        MON_PROFILE_SUMMARY_PUBLIC* pubOut = (MON_PROFILE_SUMMARY_PUBLIC*)Out;
        pubOut->Size = sizeof(MON_PROFILE_SUMMARY_PUBLIC);
        pubOut->ProcessId = summary.ProcessId;
        RtlCopyMemory(pubOut->ProcessName, summary.ProcessName, sizeof(pubOut->ProcessName));
        pubOut->ActiveHandles = summary.ActiveHandles;
        pubOut->TotalOperations = summary.TotalOperations;
        pubOut->OpsPerSecond = summary.OpsPerSecond;
        pubOut->TotalMemoryBytes = summary.TotalMemoryBytes;
        pubOut->AnomalyScore = summary.AnomalyScore;
        pubOut->AnomalyEventCount = summary.AnomalyEventCount;
        pubOut->ViolationCount = summary.ViolationCount;
        pubOut->TriggeredRules = summary.TriggeredRules;
        pubOut->FirstSeenTime = summary.FirstSeenTime;
        pubOut->LastActivityTime = summary.LastActivityTime;
        pubOut->ActiveDurationSec = summary.ActiveDurationSec;
        pubOut->Flags = summary.Flags;
    }

    return status;
}

static NTSTATUS MonIoctlProfileList(PVOID In, ULONG InLen, PVOID Out, ULONG OutLen, ULONG* BytesOut)
{
    ULONG maxCount, actualCount = 0;
    NTSTATUS status;
    PMON_PROFILE_SUMMARY internalBuf = NULL;

    *BytesOut = 0;

    if (In == NULL || InLen < sizeof(ULONG)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!MonProfileIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    maxCount = OutLen / sizeof(MON_PROFILE_SUMMARY_PUBLIC);
    if (maxCount == 0) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Cap to requested max from input */
    ULONG requestedMax = *(PULONG)In;
    if (requestedMax > 0 && requestedMax < maxCount) {
        maxCount = requestedMax;
    }

    /* Allocate temp buffer for internal structures */
    internalBuf = (PMON_PROFILE_SUMMARY)ExAllocatePoolWithTag(
        PagedPool, maxCount * sizeof(MON_PROFILE_SUMMARY), MON_PROFILE_TAG);
    if (internalBuf == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = MonProfileEnumerate(internalBuf, maxCount, &actualCount);

    if (NT_SUCCESS(status) && actualCount > 0) {
        MON_PROFILE_SUMMARY_PUBLIC* pubOut = (MON_PROFILE_SUMMARY_PUBLIC*)Out;
        for (ULONG i = 0; i < actualCount; i++) {
            pubOut[i].Size = sizeof(MON_PROFILE_SUMMARY_PUBLIC);
            pubOut[i].ProcessId = internalBuf[i].ProcessId;
            RtlCopyMemory(pubOut[i].ProcessName, internalBuf[i].ProcessName,
                          sizeof(pubOut[i].ProcessName));
            pubOut[i].ActiveHandles = internalBuf[i].ActiveHandles;
            pubOut[i].TotalOperations = internalBuf[i].TotalOperations;
            pubOut[i].OpsPerSecond = internalBuf[i].OpsPerSecond;
            pubOut[i].TotalMemoryBytes = internalBuf[i].TotalMemoryBytes;
            pubOut[i].AnomalyScore = internalBuf[i].AnomalyScore;
            pubOut[i].AnomalyEventCount = internalBuf[i].AnomalyEventCount;
            pubOut[i].ViolationCount = internalBuf[i].ViolationCount;
            pubOut[i].TriggeredRules = internalBuf[i].TriggeredRules;
            pubOut[i].FirstSeenTime = internalBuf[i].FirstSeenTime;
            pubOut[i].LastActivityTime = internalBuf[i].LastActivityTime;
            pubOut[i].ActiveDurationSec = internalBuf[i].ActiveDurationSec;
            pubOut[i].Flags = internalBuf[i].Flags;
        }
        *BytesOut = actualCount * sizeof(MON_PROFILE_SUMMARY_PUBLIC);
    }

    ExFreePoolWithTag(internalBuf, MON_PROFILE_TAG);
    return status;
}

static NTSTATUS MonIoctlProfileExportML(PVOID In, ULONG InLen, PVOID Out, ULONG OutLen)
{
    ULONG processId;
    MON_ML_FEATURE_VECTOR features;
    NTSTATUS status;

    if (In == NULL || InLen < sizeof(ULONG)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Out == NULL || OutLen < sizeof(MON_ML_FEATURE_VECTOR_PUBLIC)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (!MonProfileIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    processId = *(PULONG)In;
    status = MonProfileExportFeatures(processId, &features);

    if (NT_SUCCESS(status)) {
        /* Copy to public structure (same layout) */
        RtlCopyMemory(Out, &features, sizeof(MON_ML_FEATURE_VECTOR_PUBLIC));
    }

    return status;
}

static NTSTATUS MonIoctlProfileGetStats(PVOID Out, ULONG OutLen)
{
    MON_PROFILE_STATS stats;

    if (Out == NULL || OutLen < sizeof(MON_PROFILE_STATS_PUBLIC)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    MonProfileGetStats(&stats);

    /* Copy to public structure */
    MON_PROFILE_STATS_PUBLIC* pubOut = (MON_PROFILE_STATS_PUBLIC*)Out;
    pubOut->Size = sizeof(MON_PROFILE_STATS_PUBLIC);
    pubOut->Reserved = 0;
    pubOut->ActiveProfiles = stats.ActiveProfiles;
    pubOut->TotalProfilesCreated = stats.TotalProfilesCreated;
    pubOut->TotalProfilesDestroyed = stats.TotalProfilesDestroyed;
    pubOut->TotalAnomaliesDetected = stats.TotalAnomaliesDetected;
    pubOut->TotalUpdates = stats.TotalUpdates;
    pubOut->TotalExports = stats.TotalExports;

    return STATUS_SUCCESS;
}

static NTSTATUS MonIoctlProfileGetConfig(PVOID Out, ULONG OutLen)
{
    MON_PROFILE_CONFIG config;

    if (Out == NULL || OutLen < sizeof(MON_PROFILE_CONFIG_PUBLIC)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    MonProfileGetConfig(&config);

    /* Copy to public structure */
    MON_PROFILE_CONFIG_PUBLIC* pubOut = (MON_PROFILE_CONFIG_PUBLIC*)Out;
    pubOut->Size = sizeof(MON_PROFILE_CONFIG_PUBLIC);
    pubOut->Enabled = config.Enabled ? 1 : 0;
    pubOut->AutoExport = config.AutoExport ? 1 : 0;
    pubOut->AutoBlacklist = config.AutoBlacklist ? 1 : 0;
    pubOut->AnomalyThreshold = config.AnomalyThreshold;
    pubOut->BlacklistThreshold = config.BlacklistThreshold;
    pubOut->HistoryWindowSec = config.HistoryWindowSec;
    pubOut->Reserved = 0;

    return STATUS_SUCCESS;
}

static NTSTATUS MonIoctlProfileSetConfig(PVOID In, ULONG InLen)
{
    MON_PROFILE_CONFIG config;

    if (In == NULL || InLen < sizeof(MON_PROFILE_CONFIG_PUBLIC)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!MonProfileIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    const MON_PROFILE_CONFIG_PUBLIC* pubIn = (const MON_PROFILE_CONFIG_PUBLIC*)In;
    if (pubIn->Size != sizeof(MON_PROFILE_CONFIG_PUBLIC)) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Map public to internal */
    config.Size = sizeof(MON_PROFILE_CONFIG);
    config.Enabled = (BOOLEAN)pubIn->Enabled;
    config.AutoExport = (BOOLEAN)pubIn->AutoExport;
    config.AutoBlacklist = (BOOLEAN)pubIn->AutoBlacklist;
    config.AnomalyThreshold = pubIn->AnomalyThreshold;
    config.BlacklistThreshold = pubIn->BlacklistThreshold;
    config.HistoryWindowSec = pubIn->HistoryWindowSec;

    return MonProfileSetConfig(&config);
}

static NTSTATUS MonIoctlProfileReset(VOID)
{
    if (!MonProfileIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    MonProfileResetAll();
    return STATUS_SUCCESS;
}

/*---------------------------------------------------------------------------
 * Anomaly IOCTL Implementations (Phase 7)
 *-------------------------------------------------------------------------*/

static NTSTATUS MonIoctlAnomalyGetRules(PVOID In, ULONG InLen, PVOID Out, ULONG OutLen, ULONG* BytesOut)
{
    ULONG maxCount, actualCount = 0;
    NTSTATUS status;

    *BytesOut = 0;

    if (In == NULL || InLen < sizeof(ULONG)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!MonAnomalyIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    maxCount = OutLen / sizeof(MON_ANOMALY_RULE_PUBLIC);
    if (maxCount == 0) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Cap to requested max from input */
    ULONG requestedMax = *(PULONG)In;
    if (requestedMax > 0 && requestedMax < maxCount) {
        maxCount = requestedMax;
    }

    /* Enumerate rules (kernel structure is compatible) */
    status = MonAnomalyEnumerateRules((PMON_ANOMALY_RULE)Out, maxCount, &actualCount);

    if (NT_SUCCESS(status)) {
        *BytesOut = actualCount * sizeof(MON_ANOMALY_RULE_PUBLIC);
    }

    return status;
}

static NTSTATUS MonIoctlAnomalySetThreshold(PVOID In, ULONG InLen)
{
    if (In == NULL || InLen < sizeof(MON_ANOMALY_THRESHOLD_INPUT)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!MonAnomalyIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    const MON_ANOMALY_THRESHOLD_INPUT* input = (const MON_ANOMALY_THRESHOLD_INPUT*)In;
    return MonAnomalySetThreshold((MON_ANOMALY_RULE_ID)input->RuleId, input->Threshold);
}

static NTSTATUS MonIoctlAnomalyEnableRule(PVOID In, ULONG InLen)
{
    if (In == NULL || InLen < sizeof(MON_ANOMALY_ENABLE_INPUT)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!MonAnomalyIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    const MON_ANOMALY_ENABLE_INPUT* input = (const MON_ANOMALY_ENABLE_INPUT*)In;
    return MonAnomalyEnableRule((MON_ANOMALY_RULE_ID)input->RuleId, input->Enable != 0);
}

static NTSTATUS MonIoctlAnomalyGetStats(PVOID Out, ULONG OutLen)
{
    MON_ANOMALY_STATS stats;

    if (Out == NULL || OutLen < sizeof(MON_ANOMALY_STATS_PUBLIC)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    MonAnomalyGetStats(&stats);

    /* Copy to public structure */
    MON_ANOMALY_STATS_PUBLIC* pubOut = (MON_ANOMALY_STATS_PUBLIC*)Out;
    pubOut->Size = sizeof(MON_ANOMALY_STATS_PUBLIC);
    pubOut->TotalRules = stats.TotalRules;
    pubOut->EnabledRules = stats.EnabledRules;
    pubOut->TotalEvaluations = stats.TotalEvaluations;
    pubOut->TotalMatches = stats.TotalMatches;
    pubOut->Reserved = 0;

    return STATUS_SUCCESS;
}

static NTSTATUS MonIoctlAnomalyResetStats(VOID)
{
    if (!MonAnomalyIsInitialized()) {
        return STATUS_NOT_SUPPORTED;
    }

    MonAnomalyResetStats();
    return STATUS_SUCCESS;
}

/*---------------------------------------------------------------------------
 * Periodic Scan: DPC/Work
 *-------------------------------------------------------------------------*/
/**
 * @function   MonScanDpc
 * @purpose    DPC callback that enqueues the pool scan work item at most once until completion
 * @precondition IRQL == DISPATCH_LEVEL; DeferredContext is a valid PMONITOR_CONTEXT
 * @postcondition Work item is queued if not already pending; allocation of IoWorkItem may occur
 * @thread-safety Uses InterlockedCompareExchange on ScanWorkQueued to gate enqueue
 * @side-effects May allocate a work item lazily and schedule follow-on work
 */
static VOID MonScanDpc(KDPC* Dpc, PVOID DeferredContext, PVOID SysArg1, PVOID SysArg2)
{
    UNREFERENCED_PARAMETER(Dpc); UNREFERENCED_PARAMETER(SysArg1); UNREFERENCED_PARAMETER(SysArg2);
    PMONITOR_CONTEXT ctx = (PMONITOR_CONTEXT)DeferredContext;
    if (!ctx) return;

    if (InterlockedCompareExchange(&ctx->ScanWorkQueued, 1, 0) == 0) {
        if (!ctx->ScanWorkItem) {
            ctx->ScanWorkItem = IoAllocateWorkItem(ctx->DeviceObject);
            if (!ctx->ScanWorkItem) {
                InterlockedExchange(&ctx->ScanWorkQueued, 0);
                return;
            }
        }
        IoQueueWorkItem(ctx->ScanWorkItem, MonScanWorkItem, DelayedWorkQueue, ctx);
    }
}

/**
 * @function   MonScanWorkItem
 * @purpose    Executes pool scan at PASSIVE_LEVEL and reschedules next scan when enabled
 * @precondition IRQL == PASSIVE_LEVEL; Context is PMONITOR_CONTEXT
 * @postcondition May call MonPoolScanNow and reschedule via MonPoolScanSchedule
 * @thread-safety Single work item gated by ScanWorkQueued flag
 * @side-effects Updates ScanWorkQueued; may enqueue telemetry via scan path
 */
static VOID MonScanWorkItem(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PMONITOR_CONTEXT ctx = (PMONITOR_CONTEXT)Context;
    if (!ctx) return;

    if (ctx->MonitoringEnabled) {
        (VOID)MonPoolScanNow(ctx);
        /* Reschedule next scan */
        MonPoolScanSchedule(ctx, 500 /*ms*/);
    }

    InterlockedExchange(&ctx->ScanWorkQueued, 0);
}

/*---------------------------------------------------------------------------
 * Analysis: IoRing Registered Buffer Array ('IrRB') payload inspection
 *-------------------------------------------------------------------------*/
/**
 * @function   MonAnalyzeIoRingRegArray
 * @purpose    Validates and inspects IoRing registered buffer array entries; emits telemetry
 * @precondition IRQL == PASSIVE_LEVEL; ArrayVirtualAddress readable for ArrayByteLength bytes
 * @postcondition Increments policy counters and emits events on detections; no persistent mutation otherwise
 * @thread-safety Re-entrant; per-call SEH guards memory faults
 * @side-effects Telemetry events; PolicyViolations/IopMcDetections counters
 */
_Use_decl_annotations_
NTSTATUS
MonAnalyzeIoRingRegArray(PVOID ArrayVirtualAddress, SIZE_T ArrayByteLength)
{
    /* Defensive read: array assumed to be PVOID pointers */
    if (ArrayVirtualAddress == NULL || ArrayByteLength < sizeof(PVOID)) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        SIZE_T count = ArrayByteLength / sizeof(PVOID);
        PVOID* table = (PVOID*)ArrayVirtualAddress;

        for (SIZE_T i = 0; i < count; ++i) {
            PVOID p = table[i];
            if (p == NULL) continue;
            if (MonIsUserAddress(p)) {
                /* Immediate anomaly: IoRing reg array pointing to user VA */
                CROSS_VM_EVENT_INFO evt = {0};
                evt.Size = sizeof(evt);
                evt.Type = MonEvent_Anomaly;
                evt.ProcessId = HandleToUlong(PsGetCurrentProcessId());
                evt.ThreadId  = HandleToUlong(PsGetCurrentThreadId());
                evt.PoolTag   = TAG_IORING_REGBUF;
                evt.Severity  = 3;
                evt.SuspectAddress = (ULONG_PTR)p;
                MonTelemetryLogBlob(MonEvent_Anomaly, &evt, sizeof(evt));
                InterlockedIncrement64(&g_Mon.PolicyViolations);
                continue;
            }

            /* Try to parse as IOP_MC entry safely */
            ULONG violMask = 0;
            NTSTATUS vstatus = IopValidateMcBufferEntryEx(
                (PIOP_MC_BUFFER_ENTRY)p,
                IOP_MC_VF_DEFAULT,
                IOP_MC_KNOWN_TYPE_WIN11,
                &violMask
                );
            if (!NT_SUCCESS(vstatus)) {
                InterlockedIncrement64(&g_Mon.PolicyViolations);
                continue;
            }

            IOP_MC_BUFFER_ENTRY_INFO info;
            RtlZeroMemory(&info, sizeof(info));
            NTSTATUS st = IopQueryMcBufferEntry((PIOP_MC_BUFFER_ENTRY)p, &info);
            if (NT_SUCCESS(st)) {
                InterlockedIncrement64(&g_Mon.IopMcDetections);

                /* Cross-VM heuristic (documented; subject to refinement) */
                if (info.Address < (ULONG_PTR)MmHighestUserAddress) {
                    CROSS_VM_EVENT_INFO evt = {0};
                    evt.Size = sizeof(evt);
                    evt.Type = MonEvent_CrossVmDetected;
                    evt.ProcessId = HandleToUlong(PsGetCurrentProcessId());
                    evt.ThreadId  = HandleToUlong(PsGetCurrentThreadId());
                    evt.PoolTag   = TAG_IORING_REGBUF;
                    evt.Severity  = 5;
                    evt.SuspectAddress = info.Address;
                    MonTelemetryLogBlob(MonEvent_CrossVmDetected, &evt, sizeof(evt));
                    InterlockedIncrement64(&g_Mon.CrossVmDetections);
                } else {
                    /* Benign IOP_MC entry – optional telemetry */
                    MonTelemetryLogBlob(MonEvent_IopMcDetected, &info, sizeof(info));
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

/*---------------------------------------------------------------------------
 * Init / Teardown helpers
 *-------------------------------------------------------------------------*/
static VOID MonInitNames(PUNICODE_STRING Dev, PUNICODE_STRING Sym)
{
    RtlInitUnicodeString(Dev, WIN11MON_DEVICE_NAME_U);
    RtlInitUnicodeString(Sym, WIN11MON_SYMLINK_NAME_U);
}

static NTSTATUS MonCreateDevice(PDRIVER_OBJECT DriverObject)
{
    PDEVICE_OBJECT dev = NULL;
    NTSTATUS status = IoCreateDevice(DriverObject,
                                     0, /* no extension */
                                     &g_Mon.DeviceName,
                                     FILE_DEVICE_UNKNOWN,
                                     FILE_DEVICE_SECURE_OPEN,
                                     FALSE,
                                     &dev);
    if (!NT_SUCCESS(status)) return status;

    status = IoCreateSymbolicLink(&g_Mon.SymLink, &g_Mon.DeviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(dev);
        return status;
    }

    dev->Flags |= DO_BUFFERED_IO;
    dev->Flags &= ~DO_DEVICE_INITIALIZING;

    g_Mon.DeviceObject = dev;
    return STATUS_SUCCESS;
}

static VOID MonInitQueues(PMONITOR_CONTEXT Ctx)
{
    ExInitializeNPagedLookasideList(&Ctx->EventLookaside,
                                    NULL, NULL, 0,
                                    sizeof(MON_EVENT_NODE) + MON_MAX_EVENT_BLOB_BYTES,
                                    MON_EVENT_TAG,
                                    0);
    InitializeSListHead(&Ctx->EventQueue);
    Ctx->EventCount = 0;
    Ctx->TelemetryBuffer = NULL;
    Ctx->TelemetryBytes  = MON_TELEMETRY_RING_MB * 1024 * 1024;
}

static VOID MonDestroyQueues(PMONITOR_CONTEXT Ctx)
{
    /* Drain SLIST */
    PSLIST_ENTRY le;
    while ((le = InterlockedPopEntrySList(&Ctx->EventQueue)) != NULL) {
        PMON_EVENT_NODE node = CONTAINING_RECORD(le, MON_EVENT_NODE, SListEntry);
        ExFreeToNPagedLookasideList(&Ctx->EventLookaside, node);
    }
    ExDeleteNPagedLookasideList(&Ctx->EventLookaside);
}

/**
 * @function   MonStopScan
 * @purpose    Stops periodic scanning and drains pending work item before shutdown
 * @precondition IRQL == PASSIVE_LEVEL; Ctx non-NULL
 * @postcondition Timer canceled, DPCs flushed, work item freed when inactive
 * @thread-safety Must be called in unload/teardown path; uses interlocked gating
 * @side-effects Cancels timer; waits in short intervals for work to drain
 */
static VOID MonStopScan(PMONITOR_CONTEXT Ctx)
{
    if (Ctx == NULL) {
        return;
    }

    InterlockedExchange(&Ctx->MonitoringEnabled, 0);

    KeCancelTimer(&Ctx->ScanTimer);
    KeFlushQueuedDpcs();

    for (;;) {
        if (Ctx->ScanWorkQueued == 0) {
            break;
        }
        LARGE_INTEGER interval;
        interval.QuadPart = -10 * 1000 * 10; /* 10 ms */
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }

    if (Ctx->ScanWorkItem) {
        IoFreeWorkItem(Ctx->ScanWorkItem);
        Ctx->ScanWorkItem = NULL;
    }
}

#pragma warning(pop)
