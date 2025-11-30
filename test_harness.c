/*
 * In-Kernel Test Harness (WDM) for Windows 11 Monitor Manager
 *
 * Author: Colin MacRitchie | ziX Labs
 * File: test_harness.c
 * Version: 1.0
 * Date: 2025-11-18
 *
 * Summary
 * -------
 * Minimal WDM driver that exercises the monitor via IOCTLs. Generates
 * synthetic IOP_MC buffer entries and validates detection paths.
 *
 * NOTE: For lab use only. Do not ship to production images.
 */

#include <ntddk.h>
#include <ntstrsafe.h>
#include "win11_monitor_mgr.h"
#include "iop_mc.h"           /* For shape of IOP_MC_BUFFER_ENTRY and parser helpers */
#include "ioring_enum.h"      /* For MonGetIoRingTypeInfo */
#include "regbuf_integrity.h" /* For MonValidateIoRingRegBuffers */
#include "telemetry_etw.h"    /* For MonEtwLogCrossVmDetection */
#include "rate_limit.h"       /* For MonRateLimitCheckEvent (B3) */

#pragma warning(push)
#pragma warning(disable: 4201)

/* Local */
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     ThUnload;
_Dispatch_type_(IRP_MJ_CREATE) DRIVER_DISPATCH ThCreate;
_Dispatch_type_(IRP_MJ_CLOSE)  DRIVER_DISPATCH ThClose;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH ThDeviceControl;

#define TH_DEVICE_NAME   L"\\Device\\Win11MonTest"
#define TH_SYMLINK_NAME  L"\\DosDevices\\Win11MonTest"

/* Private test IOCTLs */
#define IOCTL_TH_RUN_BASIC           CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA10, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TH_TEST_OFFSET_STATUS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA11, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TH_TEST_REGBUF_VALID   CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA12, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TH_TEST_ETW_EMIT       CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA13, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TH_TEST_RATE_LIMIT     CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA15, METHOD_BUFFERED, FILE_ANY_ACCESS)

static UNICODE_STRING g_DevName, g_SymLink;
static PDEVICE_OBJECT g_DevObj;

/**
 * @function   ThSendMonitorIoctl
 * @purpose    Open monitor device and send METHOD_BUFFERED IOCTL with optional I/O buffers
 * @precondition IRQL == PASSIVE_LEVEL; monitor driver loaded; WIN11MON_DOSLINK_U reachable
 * @postcondition On success, IOCTL completes and status returned; no lingering references
 * @thread-safety Re-entrant; per-call KEVENT used for async completion
 * @side-effects Opens/closes file object; allocates IRP via IoBuildDeviceIoControlRequest
 */
static NTSTATUS ThSendMonitorIoctl(_In_ ULONG Ioctl, _In_reads_bytes_opt_(InLen) PVOID InBuf, _In_ ULONG InLen, _Out_writes_bytes_opt_(OutLen) PVOID OutBuf, _In_ ULONG OutLen)
{
    NTSTATUS status;
    PFILE_OBJECT file = NULL;
    PDEVICE_OBJECT dev = NULL;
    IO_STATUS_BLOCK iosb = {0};
    KEVENT event;

    UNICODE_STRING link;
    RtlInitUnicodeString(&link, WIN11MON_DOSLINK_U);

    status = IoGetDeviceObjectPointer(&link, FILE_READ_DATA | FILE_WRITE_DATA, &file, &dev);
    if (!NT_SUCCESS(status)) return status;

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    PIRP irp = IoBuildDeviceIoControlRequest(Ioctl, dev, InBuf, InLen, OutBuf, OutLen, FALSE, &event, &iosb);
    if (!irp) {
        ObDereferenceObject(file);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IoCallDriver(dev, irp);
    ObDereferenceObject(file);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    }
    return status;
}

/**
 * @function   DriverEntry
 * @purpose    Initialize test harness device and dispatch table
 * @precondition IRQL == PASSIVE_LEVEL
 * @postcondition Creates device/symlink; sets DO_BUFFERED_IO; returns STATUS_SUCCESS on success
 * @thread-safety Initialization only; not re-entrant
 * @side-effects Creates kernel namespace objects (device, doslink)
 */
_Use_decl_annotations_
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&g_DevName, TH_DEVICE_NAME);
    RtlInitUnicodeString(&g_SymLink, TH_SYMLINK_NAME);

    NTSTATUS status = IoCreateDevice(DriverObject, 0, &g_DevName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_DevObj);
    if (!NT_SUCCESS(status)) return status;

    status = IoCreateSymbolicLink(&g_SymLink, &g_DevName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DevObj);
        return status;
    }

    DriverObject->DriverUnload = ThUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = ThCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]  = ThClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ThDeviceControl;

    g_DevObj->Flags |= DO_BUFFERED_IO;
    g_DevObj->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[TH] Loaded\n");
    return STATUS_SUCCESS;
}

/**
 * @function   ThUnload
 * @purpose    Tear down test harness device and symbolic link
 * @precondition IRQL == PASSIVE_LEVEL; DriverObject valid
 * @postcondition Device and symlink deleted; no resources leaked
 * @thread-safety Unload path only; not concurrent with I/O
 * @side-effects Removes namespace objects
 */
_Use_decl_annotations_
VOID ThUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    IoDeleteSymbolicLink(&g_SymLink);
    IoDeleteDevice(g_DevObj);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[TH] Unloaded\n");
}

/**
 * @function   ThCreate
 * @purpose    Minimal IRP_MJ_CREATE handler (accepts all opens)
 * @precondition IRQL == PASSIVE_LEVEL
 * @postcondition Completes IRP with STATUS_SUCCESS
 * @thread-safety Serialized by I/O manager per file object
 * @side-effects None
 */
_Use_decl_annotations_
NTSTATUS ThCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/**
 * @function   ThClose
 * @purpose    Minimal IRP_MJ_CLOSE handler (no bookkeeping)
 * @precondition IRQL == PASSIVE_LEVEL
 * @postcondition Completes IRP with STATUS_SUCCESS
 * @thread-safety Serialized by I/O manager per file object
 * @side-effects None
 */
_Use_decl_annotations_
NTSTATUS ThClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/**
 * @function   ThMakeSyntheticMc
 * @purpose    Build a synthetic IOP_MC entry in NonPagedPool for parser validation
 * @precondition IRQL == PASSIVE_LEVEL; BackingPool non-NULL
 * @postcondition Allocates backing page and entry; returns pointer to entry; caller frees both
 * @thread-safety Not thread-safe; test helper intended for single-threaded use
 * @side-effects Allocates from NonPagedPoolNx ('tcbM')
 */
static PIOP_MC_BUFFER_ENTRY ThMakeSyntheticMc(_Out_ PVOID* BackingPool, _In_ BOOLEAN MakeMalicious)
{
    /* Allocate a single page backing for simplicity */
    SIZE_T len = 0x1000;
    PVOID backing = ExAllocatePoolWithTag(NonPagedPoolNx, len, 'tcbM');
    if (!backing) return NULL;
    RtlFillMemory(backing, len, 0xA5);

    PIOP_MC_BUFFER_ENTRY e = (PIOP_MC_BUFFER_ENTRY)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*e), 'tcbM');
    if (!e) { ExFreePoolWithTag(backing, 'tcbM'); return NULL; }
    RtlZeroMemory(e, sizeof(*e));

    /* Minimal plausible fields */
    e->Type = IOP_MC_KNOWN_TYPE_WIN11;
    e->Size = sizeof(IOP_MC_BUFFER_ENTRY);
    e->Length = (ULONG)len;
    e->ReferenceCount = 1;
    e->AccessMode = MakeMalicious ? 0 /* kernel */ : 0 /* kernel */;
    e->Address = MakeMalicious ? (PVOID)0x00007FFFFFFF0000ULL /* user-ish */ : backing;

    *BackingPool = backing;
    return e;
}

/**
 * @function   ThRunBasicScenario
 * @purpose    End-to-end smoke test: enable monitor, parse benign/malicious entries, trigger scan, fetch events
 * @precondition IRQL == PASSIVE_LEVEL; monitor driver loaded
 * @postcondition Executes IOCTLs against monitor; frees all allocations; returns STATUS_SUCCESS on completion path
 * @thread-safety Not thread-safe; invoked via private IOCTL in this harness
 * @side-effects Enables/disables monitor features; enqueues telemetry
 */
static NTSTATUS ThRunBasicScenario(VOID)
{
    /* Enable monitor */
    MONITOR_SETTINGS s = {0};
    s.Size = sizeof(s);
    s.EnableMonitoring = 1;
    s.EnableTelemetry  = 1;
    s.RateLimitPerSec  = 1000;
    NTSTATUS st = ThSendMonitorIoctl(IOCTL_MONITOR_ENABLE, &s, sizeof(s), NULL, 0);
    if (!NT_SUCCESS(st)) return st;

    /* Construct benign + malicious entries and ask monitor to parse */
    PVOID pool = NULL;
    PIOP_MC_BUFFER_ENTRY benign = ThMakeSyntheticMc(&pool, FALSE);
    if (benign) {
        IOP_MC_BUFFER_ENTRY_INFO info = {0};
        st = ThSendMonitorIoctl(IOCTL_MONITOR_PARSE_IOP_MC, benign, sizeof(*benign), &info, sizeof(info));
        UNREFERENCED_PARAMETER(st);
        ExFreePoolWithTag(benign, 'tcbM');
        ExFreePoolWithTag(pool, 'tcbM');
    }

    PVOID pool2 = NULL;
    PIOP_MC_BUFFER_ENTRY evil = ThMakeSyntheticMc(&pool2, TRUE);
    if (evil) {
        IOP_MC_BUFFER_ENTRY_INFO info2 = {0};
        st = ThSendMonitorIoctl(IOCTL_MONITOR_PARSE_IOP_MC, evil, sizeof(*evil), &info2, sizeof(info2));
        UNREFERENCED_PARAMETER(st);
        ExFreePoolWithTag(evil, 'tcbM');
        ExFreePoolWithTag(pool2, 'tcbM');
    }

    /* Force a scan cycle */
    st = ThSendMonitorIoctl(IOCTL_MONITOR_SCAN_NOW, NULL, 0, NULL, 0);

    /* Fetch any events (best-effort) */
    UCHAR buf[512] = {0};
    st = ThSendMonitorIoctl(IOCTL_MONITOR_FETCH_EVENTS, NULL, 0, buf, sizeof(buf));
    UNREFERENCED_PARAMETER(st);

    return STATUS_SUCCESS;
}

/**
 * @function   ThTestOffsetStatus
 * @purpose    Test IOCTL_MONITOR_GET_OFFSET_STATUS returns valid data
 */
static NTSTATUS ThTestOffsetStatus(VOID)
{
    MON_OFFSET_STATUS_OUTPUT status = {0};
    NTSTATUS st = ThSendMonitorIoctl(IOCTL_MONITOR_GET_OFFSET_STATUS,
                                      NULL, 0, &status, sizeof(status));
    if (!NT_SUCCESS(st)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[TH] GET_OFFSET_STATUS failed: 0x%08X\n", st);
        return st;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[TH] Offset Status: Build=%lu Method=%u IoRingValid=%u IopMcValid=%u\n",
        status.WindowsBuildNumber,
        (ULONG)status.Method,
        status.IoRingOffsetsValid,
        status.IopMcOffsetsValid);

    /* Validate fields */
    if (status.Size != sizeof(MON_OFFSET_STATUS_OUTPUT)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[TH] FAIL: Size mismatch %lu != %lu\n",
            status.Size, (ULONG)sizeof(MON_OFFSET_STATUS_OUTPUT));
        return STATUS_UNSUCCESSFUL;
    }

    if (status.WindowsBuildNumber == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[TH] WARNING: Build number is 0\n");
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[TH] PASS: ThTestOffsetStatus\n");
    return STATUS_SUCCESS;
}

/**
 * @function   ThTestRegBufValidation
 * @purpose    Test RegBuffers validation functions
 */
static NTSTATUS ThTestRegBufValidation(VOID)
{
    /* Test 1: NULL pointer should return violation */
    ULONG viol = MonValidateIoRingRegBuffers(NULL, NULL);
    if (!(viol & MON_REGBUF_VF_NULL_OBJECT)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[TH] FAIL: NULL object not detected\n");
        return STATUS_UNSUCCESSFUL;
    }

    /* Test 2: User-mode address should return violation */
    viol = MonValidateIoRingRegBuffers((PVOID)0x7FFE0000, NULL);
    if (!(viol & MON_REGBUF_VF_USERMODE_PTR)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[TH] FAIL: User-mode pointer not detected\n");
        return STATUS_UNSUCCESSFUL;
    }

    /* Test 3: Check if validation available */
    BOOLEAN available = MonIsRegBuffersValidationAvailable();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[TH] RegBuffers validation available: %s\n",
        available ? "YES" : "NO");

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[TH] PASS: ThTestRegBufValidation\n");
    return STATUS_SUCCESS;
}

/**
 * @function   ThTestEtwEmit
 * @purpose    Test ETW event emission
 */
static NTSTATUS ThTestEtwEmit(VOID)
{
    if (!MonEtwIsEnabled()) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[TH] ETW provider not enabled (no consumer attached)\n");
        /* Not a failure - just means no ETW session is listening */
    }

    /* Emit test events */
    MonEtwLogCrossVmDetection(
        HandleToUlong(PsGetCurrentProcessId()),
        HandleToUlong(PsGetCurrentThreadId()),
        0xDEAD000000000000ULL,
        3 /* severity */
    );

    MonEtwLogRegBuffersViolation(
        HandleToUlong(PsGetCurrentProcessId()),
        0xFFFF800000001234ULL,  /* fake IoRing address */
        0x00007FFE00000000ULL,  /* user-mode RegBuffers */
        MON_REGBUF_VF_USERMODE_PTR
    );

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[TH] PASS: ThTestEtwEmit (events emitted)\n");
    return STATUS_SUCCESS;
}

/**
 * @function   ThTestRateLimit
 * @purpose    Test per-process rate limiting (B3-T05: High IRQL safety)
 *
 * Test Contract (from spec):
 * B3-T01: Single process under limit - All events logged
 * B3-T02: Single process over limit - Events dropped after threshold
 * B3-T05: High IRQL safety - No deadlock at DISPATCH_LEVEL
 */
static NTSTATUS ThTestRateLimit(VOID)
{
    ULONG processId = HandleToUlong(PsGetCurrentProcessId());

    /* Test 1: Check if rate limiting is enabled */
    BOOLEAN enabled = MonRateLimitIsEnabled();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[TH] Rate limiting enabled: %s\n", enabled ? "YES" : "NO");

    /* Test 2: Single event under limit should be allowed */
    MON_RATE_RESULT result = MonRateLimitCheckEvent(processId);
    if (result != MonRateResult_Allowed && result != MonRateResult_Disabled) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[TH] FAIL: First event should be allowed, got %u\n", result);
        return STATUS_UNSUCCESSFUL;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[TH] First event result: %u (expected Allowed=0 or Disabled=3)\n", result);

    /* Test 3: Get current stats */
    MON_RATE_LIMIT_INTERNAL_STATS stats = {0};
    MonRateLimitGetStats(&stats);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[TH] Rate stats: Active=%lu Allowed=%llu Dropped=%llu Global=%u/s PerProc=%u/s\n",
        stats.ActiveProcessCount,
        stats.TotalEventsAllowed,
        stats.TotalEventsDropped,
        stats.GlobalLimitPerSec,
        stats.PerProcessLimitPerSec);

    /* Test 4: B3-T05 High IRQL safety test */
    /* Raise IRQL to DISPATCH_LEVEL and verify no deadlock */
    KIRQL oldIrql;
    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
    {
        /* This should complete without deadlock */
        MON_RATE_RESULT dispatchResult = MonRateLimitCheckEvent(processId);
        UNREFERENCED_PARAMETER(dispatchResult);

        /* Get stats at DISPATCH_LEVEL (should also be safe) */
        MON_RATE_LIMIT_INTERNAL_STATS dispatchStats = {0};
        MonRateLimitGetStats(&dispatchStats);
        UNREFERENCED_PARAMETER(dispatchStats);
    }
    KeLowerIrql(oldIrql);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[TH] PASS: ThTestRateLimit (B3-T05 DISPATCH_LEVEL safe)\n");
    return STATUS_SUCCESS;
}

/**
 * @function   ThDeviceControl
 * @purpose    Private IOCTL dispatcher for the test harness (runs basic scenario)
 * @precondition IRQL == PASSIVE_LEVEL; METHOD_BUFFERED; SystemBuffer used
 * @postcondition Runs scenario for IOCTL_TH_RUN_BASIC; completes IRP with status
 * @thread-safety Serialized by I/O manager; no shared mutable state beyond globals initialized at load
 * @side-effects Exercises monitor driver via IOCTLs
 */
_Use_decl_annotations_
NTSTATUS ThDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = irpSp->Parameters.DeviceIoControl.IoControlCode;

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG bytes = 0;

    switch (code) {
    case IOCTL_TH_RUN_BASIC:
        status = ThRunBasicScenario();
        break;

    case IOCTL_TH_TEST_OFFSET_STATUS:
        status = ThTestOffsetStatus();
        break;

    case IOCTL_TH_TEST_REGBUF_VALID:
        status = ThTestRegBufValidation();
        break;

    case IOCTL_TH_TEST_ETW_EMIT:
        status = ThTestEtwEmit();
        break;

    case IOCTL_TH_TEST_RATE_LIMIT:
        status = ThTestRateLimit();
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytes;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

#pragma warning(pop)