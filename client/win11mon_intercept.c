/*
 * Windows 11 Monitor Manager - IoRing Interception Client Implementation
 *
 * Author: Colin MacRitchie | ziX Labs
 * Organization: ziX Performance Labs
 * File: client/win11mon_intercept.c
 * Version: 1.0
 * Date: 2025-11-30
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and
 * confidential. Redistribution or disclosure without prior written consent is
 * prohibited.
 *
 * Summary
 * -------
 * Implements user-mode IoRing interception via IAT/inline hooks on
 * NtSubmitIoRing. Pre-submission validation requests are sent to the
 * kernel driver for policy enforcement.
 *
 * Architecture
 * ------------
 * 1. Install IAT hook on ntdll!NtSubmitIoRing
 * 2. On hook invocation, serialize SQE array
 * 3. Call kernel driver via IOCTL_MONITOR_INTERCEPT_VALIDATE
 * 4. Apply kernel response (block returns STATUS_ACCESS_DENIED)
 * 5. If allowed, call original syscall
 *
 * SECURITY NOTES:
 * - User-mode hooks can be bypassed via direct syscall
 * - This provides defense-in-depth with kernel polling
 * - All buffer captures are bounded and validated
 */

#define WIN32_LEAN_AND_MEAN
#include "win11mon_intercept.h"

#include <strsafe.h>
#include <windows.h>
#include <winternl.h>

/*--------------------------------------------------------------------------
 * Build Configuration
 *-------------------------------------------------------------------------*/
#ifdef WIN11MON_CLIENT_EXPORTS
#define WIN11MON_API __declspec(dllexport)
#else
#define WIN11MON_API
#endif

/*--------------------------------------------------------------------------
 * IOCTL Definitions (must match kernel driver)
 *-------------------------------------------------------------------------*/
#define WIN11MON_IOCTL_BASE 0x800
#define WIN11MON_DEVICE_TYPE FILE_DEVICE_UNKNOWN

#define IOCTL_MONITOR_INTERCEPT_VALIDATE                                      \
  CTL_CODE(WIN11MON_DEVICE_TYPE, WIN11MON_IOCTL_BASE + 0x20, METHOD_BUFFERED, \
           FILE_ANY_ACCESS)
#define IOCTL_MONITOR_INTERCEPT_SET_POLICY                                    \
  CTL_CODE(WIN11MON_DEVICE_TYPE, WIN11MON_IOCTL_BASE + 0x21, METHOD_BUFFERED, \
           FILE_WRITE_ACCESS)
#define IOCTL_MONITOR_INTERCEPT_GET_POLICY                                    \
  CTL_CODE(WIN11MON_DEVICE_TYPE, WIN11MON_IOCTL_BASE + 0x22, METHOD_BUFFERED, \
           FILE_READ_ACCESS)
#define IOCTL_MONITOR_INTERCEPT_GET_STATS                                     \
  CTL_CODE(WIN11MON_DEVICE_TYPE, WIN11MON_IOCTL_BASE + 0x23, METHOD_BUFFERED, \
           FILE_READ_ACCESS)
#define IOCTL_MONITOR_INTERCEPT_RESET_STATS                                   \
  CTL_CODE(WIN11MON_DEVICE_TYPE, WIN11MON_IOCTL_BASE + 0x24, METHOD_BUFFERED, \
           FILE_WRITE_ACCESS)
#define IOCTL_MONITOR_INTERCEPT_ENABLE                                        \
  CTL_CODE(WIN11MON_DEVICE_TYPE, WIN11MON_IOCTL_BASE + 0x25, METHOD_BUFFERED, \
           FILE_WRITE_ACCESS)
#define IOCTL_MONITOR_INTERCEPT_ADD_BL                                        \
  CTL_CODE(WIN11MON_DEVICE_TYPE, WIN11MON_IOCTL_BASE + 0x26, METHOD_BUFFERED, \
           FILE_WRITE_ACCESS)
#define IOCTL_MONITOR_INTERCEPT_REMOVE_BL                                     \
  CTL_CODE(WIN11MON_DEVICE_TYPE, WIN11MON_IOCTL_BASE + 0x27, METHOD_BUFFERED, \
           FILE_WRITE_ACCESS)
#define IOCTL_MONITOR_INTERCEPT_GET_BL                                        \
  CTL_CODE(WIN11MON_DEVICE_TYPE, WIN11MON_IOCTL_BASE + 0x28, METHOD_BUFFERED, \
           FILE_READ_ACCESS)

/*--------------------------------------------------------------------------
 * NT IoRing Types (from Windows Internals / yardenshafir/IoRing_Demos)
 *
 * Source: https://github.com/yardenshafir/IoRing_Demos/blob/main/ioringnt.h
 * Reference:
 * https://windows-internals.com/i-o-rings-when-one-i-o-operation-is-not-enough/
 *-------------------------------------------------------------------------*/

/* Submission queue header - tracks head/tail positions */
typedef struct _IORING_SUB_QUEUE_HEAD {
  ULONG QueueHead; /* Index of next entry to process */
  ULONG QueueTail; /* Index of last submitted entry */
  ULONG64 Padding; /* Alignment */
} IORING_SUB_QUEUE_HEAD, *PIORING_SUB_QUEUE_HEAD;

/* Completion queue header */
typedef struct _IORING_COMP_QUEUE_HEAD {
  ULONG QueueHead;
  ULONG QueueTail;
} IORING_COMP_QUEUE_HEAD, *PIORING_COMP_QUEUE_HEAD;

/* NT_IORING_SQE - Submission Queue Entry (88 bytes with padding) */
typedef struct _NT_IORING_SQE {
  ULONG OpCode;
  ULONG Flags;
  ULONG64 FileRef;
  LARGE_INTEGER FileOffset;
  ULONG64 BufferAddress;
  ULONG BufferSize;
  ULONG BufferOffset;
  ULONG Key;
  ULONG Reserved;
  ULONG64 UserData;
  ULONG64 Padding[4];
} NT_IORING_SQE, *PNT_IORING_SQE;

C_ASSERT(sizeof(NT_IORING_SQE) == 0x58); /* 88 bytes */

/* NT_IORING_INFO - Ring metadata (embedded in HIORING) */
typedef struct _NT_IORING_INFO {
  ULONG Version;
  ULONG Flags; /* IORING_CREATE_FLAGS */
  ULONG SubmissionQueueSize;
  ULONG SubQueueSizeMask; /* For wrap-around: Size - 1 */
  ULONG CompletionQueueSize;
  ULONG CompQueueSizeMask;
  union {
    PIORING_SUB_QUEUE_HEAD SubQueueBase;
    ULONG64 SubQueuePadding;
  };
  union {
    PIORING_COMP_QUEUE_HEAD CompQueueBase;
    ULONG64 CompQueuePadding;
  };
} NT_IORING_INFO, *PNT_IORING_INFO;

/* HIORING - User-mode IoRing handle (KernelBase internal structure) */
typedef struct _HIORING_IMPL {
  ULONG SqePending;    /* Number of pending submissions */
  ULONG SqeCount;      /* Total SQEs queued */
  HANDLE KernelHandle; /* NT handle to IORING_OBJECT */
  NT_IORING_INFO Info; /* Ring info with queue pointers */
  ULONG IoRingKernelAcceptedVersion;
} HIORING_IMPL, *PHIORING_IMPL;

typedef PHIORING_IMPL HIORING;

/*--------------------------------------------------------------------------
 * NtSubmitIoRing Prototype
 *-------------------------------------------------------------------------*/
typedef NTSTATUS(NTAPI* PFN_NtSubmitIoRing)(_In_ HIORING IoRingHandle,
                                            _In_ ULONG Flags,
                                            _In_ ULONG WaitOperations,
                                            _In_opt_ PLARGE_INTEGER Timeout);

/*--------------------------------------------------------------------------
 * Internal State
 *-------------------------------------------------------------------------*/
typedef struct _WIN11MON_INTERCEPT_STATE {
  /* Initialization flag */
  volatile LONG Initialized;
  volatile LONG HooksInstalled;

  /* Driver handle */
  HANDLE DriverHandle;

  /* Original function pointer */
  PFN_NtSubmitIoRing OriginalNtSubmitIoRing;

  /* Hook trampoline storage */
  BYTE OriginalBytes[16];
  SIZE_T OriginalBytesSize;
  PVOID HookTarget;

  /* Callbacks */
  WIN11MON_PRE_VALIDATE_CALLBACK PreCallback;
  PVOID PreCallbackContext;
  WIN11MON_POST_VALIDATE_CALLBACK PostCallback;
  PVOID PostCallbackContext;

  /* Synchronization */
  CRITICAL_SECTION Lock;
  volatile LONG InFlightCount;

} WIN11MON_INTERCEPT_STATE, *PWIN11MON_INTERCEPT_STATE;

static WIN11MON_INTERCEPT_STATE g_InterceptState = {0};

/*--------------------------------------------------------------------------
 * Internal Helper: Get Driver Handle from Client Handle
 *-------------------------------------------------------------------------*/
static HANDLE GetDriverHandleFromClient(_In_ HWIN11MON Handle) {
  /* The HWIN11MON is an opaque pointer to a structure containing the driver
   * handle */
  /* For simplicity, assume first field is the driver handle */
  if (Handle == NULL) {
    return INVALID_HANDLE_VALUE;
  }

  /* Access the internal structure - this depends on win11mon_client.c
   * implementation */
  /* For now, we'll use our cached handle from init */
  if (g_InterceptState.DriverHandle != NULL &&
      g_InterceptState.DriverHandle != INVALID_HANDLE_VALUE) {
    return g_InterceptState.DriverHandle;
  }

  return INVALID_HANDLE_VALUE;
}

/*--------------------------------------------------------------------------
 * Internal Helper: Send IOCTL to Driver
 *-------------------------------------------------------------------------*/
static HRESULT SendIoctl(_In_ DWORD IoControlCode,
                         _In_reads_bytes_opt_(InputSize)
                             const VOID* InputBuffer,
                         _In_ DWORD InputSize,
                         _Out_writes_bytes_to_opt_(OutputSize, *BytesReturned)
                             VOID* OutputBuffer,
                         _In_ DWORD OutputSize,
                         _Out_opt_ DWORD* BytesReturned) {
  HANDLE hDriver = g_InterceptState.DriverHandle;
  DWORD returned = 0;

  if (hDriver == NULL || hDriver == INVALID_HANDLE_VALUE) {
    return WIN11MON_E_INVALID_HANDLE;
  }

  BOOL success =
      DeviceIoControl(hDriver, IoControlCode, (LPVOID)InputBuffer, InputSize,
                      OutputBuffer, OutputSize, &returned, NULL);

  if (BytesReturned != NULL) {
    *BytesReturned = returned;
  }

  if (!success) {
    DWORD err = GetLastError();
    switch (err) {
      case ERROR_ACCESS_DENIED:
        return WIN11MON_E_ACCESS_DENIED;
      case ERROR_INSUFFICIENT_BUFFER:
        return WIN11MON_E_BUFFER_TOO_SMALL;
      case ERROR_NOT_SUPPORTED:
        return WIN11MON_E_NOT_SUPPORTED;
      default:
        return HRESULT_FROM_WIN32(err);
    }
  }

  return S_OK;
}

/*--------------------------------------------------------------------------
 * Internal Helper: Resolve NtSubmitIoRing
 *-------------------------------------------------------------------------*/
static PFN_NtSubmitIoRing ResolveNtSubmitIoRing(VOID) {
  HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
  if (hNtdll == NULL) {
    return NULL;
  }

  return (PFN_NtSubmitIoRing)GetProcAddress(hNtdll, "NtSubmitIoRing");
}

/*--------------------------------------------------------------------------
 * Internal Helper: Build Validation Request
 *-------------------------------------------------------------------------*/
static HRESULT BuildValidationRequest(
    _In_ HANDLE IoRingHandle, _In_ DWORD OperationCount,
    _In_reads_bytes_(SqeBufferSize) const VOID* SqeBuffer,
    _In_ DWORD SqeBufferSize,
    _Out_writes_bytes_to_(RequestBufferSize, *RequestSize)
        PWIN11MON_INTERCEPT_REQUEST Request,
    _In_ DWORD RequestBufferSize, _Out_ DWORD* RequestSize) {
  /* Calculate required size */
  DWORD sqeArraySize = OperationCount * sizeof(WIN11MON_SERIALIZED_SQE);
  DWORD totalSize = WIN11MON_INTERCEPT_REQUEST_HEADER_SIZE + sqeArraySize;

  *RequestSize = totalSize;

  if (RequestBufferSize < totalSize) {
    return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
  }

  /* Fill header */
  ZeroMemory(Request, totalSize);
  Request->Size = totalSize;
  Request->Version = WIN11MON_INTERCEPT_REQUEST_VERSION;
  Request->ProcessId = GetCurrentProcessId();
  Request->ThreadId = GetCurrentThreadId();
  Request->IoRingHandle = (DWORD64)(ULONG_PTR)IoRingHandle;
  Request->OperationCount = OperationCount;
  Request->Flags = 0;

  /* Copy SQE data */
  if (OperationCount > 0 && SqeBuffer != NULL) {
    BYTE* destSqe = (BYTE*)Request + WIN11MON_INTERCEPT_REQUEST_HEADER_SIZE;
    DWORD copySize = min(sqeArraySize, SqeBufferSize);
    CopyMemory(destSqe, SqeBuffer, copySize);
  }

  return S_OK;
}

/*--------------------------------------------------------------------------
 * Internal Helper: Validate via Driver
 *-------------------------------------------------------------------------*/
static HRESULT ValidateViaDriver(_In_ HANDLE IoRingHandle,
                                 _In_ DWORD OperationCount,
                                 _In_reads_bytes_(SqeBufferSize)
                                     const VOID* SqeBuffer,
                                 _In_ DWORD SqeBufferSize,
                                 _Out_ PWIN11MON_INTERCEPT_RESPONSE Response) {
  HRESULT hr;
  DWORD requestSize;
  DWORD bytesReturned;

  /* Calculate request size */
  DWORD reqBufferSize = WIN11MON_INTERCEPT_REQUEST_HEADER_SIZE +
                        (OperationCount * sizeof(WIN11MON_SERIALIZED_SQE));

  /* Allocate request buffer */
  PWIN11MON_INTERCEPT_REQUEST request = (PWIN11MON_INTERCEPT_REQUEST)HeapAlloc(
      GetProcessHeap(), HEAP_ZERO_MEMORY, reqBufferSize);

  if (request == NULL) {
    return E_OUTOFMEMORY;
  }

  /* Build request */
  hr = BuildValidationRequest(IoRingHandle, OperationCount, SqeBuffer,
                              SqeBufferSize, request, reqBufferSize,
                              &requestSize);

  if (FAILED(hr)) {
    HeapFree(GetProcessHeap(), 0, request);
    return hr;
  }

  /* Initialize response */
  ZeroMemory(Response, sizeof(WIN11MON_INTERCEPT_RESPONSE));
  Response->Size = sizeof(WIN11MON_INTERCEPT_RESPONSE);

  /* Send to driver */
  hr = SendIoctl(IOCTL_MONITOR_INTERCEPT_VALIDATE, request, requestSize,
                 Response, sizeof(WIN11MON_INTERCEPT_RESPONSE), &bytesReturned);

  HeapFree(GetProcessHeap(), 0, request);
  return hr;
}

/*--------------------------------------------------------------------------
 * Internal Helper: Copy single SQE with volatile reads
 *-------------------------------------------------------------------------*/
static VOID CopySqeVolatile(_In_ const NT_IORING_SQE* Src,
                            _Out_ PWIN11MON_SERIALIZED_SQE Dst) {
  Dst->OpCode = *(volatile ULONG*)&Src->OpCode;
  Dst->Flags = *(volatile ULONG*)&Src->Flags;
  Dst->FileRef = *(volatile ULONG64*)&Src->FileRef;
  Dst->FileOffset.QuadPart = *(volatile LONGLONG*)&Src->FileOffset.QuadPart;
  Dst->BufferAddress = *(volatile ULONG64*)&Src->BufferAddress;
  Dst->BufferSize = *(volatile ULONG*)&Src->BufferSize;
  Dst->BufferOffset = *(volatile ULONG*)&Src->BufferOffset;
  Dst->Key = *(volatile ULONG*)&Src->Key;
  Dst->Reserved1 = 0;
  Dst->UserData = *(volatile ULONG64*)&Src->UserData;
}

/*--------------------------------------------------------------------------
 * Internal Helper: Serialize SQEs from HIORING Submission Queue
 *
 * Reads pending SQEs from the IoRing submission queue and converts them
 * to the WIN11MON_SERIALIZED_SQE format for driver validation.
 *
 * Queue layout: [IORING_SUB_QUEUE_HEAD][NT_IORING_SQE array...]
 * Pending entries: from current Head to Tail (wrap-around via mask)
 *-------------------------------------------------------------------------*/
static HRESULT SerializePendingSqes(_In_ HIORING IoRingHandle,
                                    _Out_ PWIN11MON_SERIALIZED_SQE* SqeBuffer,
                                    _Out_ DWORD* OperationCount,
                                    _Out_ DWORD* BufferSize) {
  *SqeBuffer = NULL;
  *OperationCount = 0;
  *BufferSize = 0;

  if (IoRingHandle == NULL) {
    return E_INVALIDARG;
  }

  __try {
    PIORING_SUB_QUEUE_HEAD subQueue = IoRingHandle->Info.SubQueueBase;
    if (subQueue == NULL) {
      return S_OK; /* No submission queue mapped */
    }

    /* Read queue positions with volatile semantics */
    ULONG head = *(volatile ULONG*)&subQueue->QueueHead;
    ULONG tail = *(volatile ULONG*)&subQueue->QueueTail;
    ULONG sizeMask = IoRingHandle->Info.SubQueueSizeMask;
    ULONG queueSize = IoRingHandle->Info.SubmissionQueueSize;

    /* Calculate pending count with wrap-around */
    ULONG pending = (tail >= head) ? (tail - head) : (queueSize - head + tail);
    if (pending == 0) {
      return S_OK;
    }
    if (pending > WIN11MON_INTERCEPT_MAX_OPS_PER_SUBMIT) {
      pending = WIN11MON_INTERCEPT_MAX_OPS_PER_SUBMIT;
    }

    /* Allocate output buffer */
    DWORD allocSize = pending * sizeof(WIN11MON_SERIALIZED_SQE);
    PWIN11MON_SERIALIZED_SQE buffer = (PWIN11MON_SERIALIZED_SQE)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, allocSize);
    if (buffer == NULL) {
      return E_OUTOFMEMORY;
    }

    /* Serialize each pending SQE */
    PNT_IORING_SQE sqeArray = (PNT_IORING_SQE)(subQueue + 1);
    for (ULONG i = 0; i < pending; i++) {
      ULONG idx = (head + i) & sizeMask;
      CopySqeVolatile(&sqeArray[idx], &buffer[i]);
    }

    *SqeBuffer = buffer;
    *OperationCount = pending;
    *BufferSize = allocSize;
    return S_OK;

  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
  }
}

/*--------------------------------------------------------------------------
 * Hook Implementation: NtSubmitIoRing Detour
 *
 * Intercepts NtSubmitIoRing calls to:
 * 1. Serialize pending SQEs from the submission queue
 * 2. Send to kernel driver for policy validation
 * 3. Block if policy violation detected
 *-------------------------------------------------------------------------*/
static NTSTATUS NTAPI HookedNtSubmitIoRing(_In_ HIORING IoRingHandle,
                                           _In_ ULONG Flags,
                                           _In_ ULONG WaitOperations,
                                           _In_opt_ PLARGE_INTEGER Timeout) {
  WIN11MON_INTERCEPT_RESPONSE response;
  PWIN11MON_SERIALIZED_SQE sqeBuffer = NULL;
  DWORD operationCount = 0;
  DWORD sqeBufferSize = 0;
  NTSTATUS status;
  HRESULT hr;

  /* Increment in-flight counter */
  InterlockedIncrement(&g_InterceptState.InFlightCount);

  /* Quick path if not initialized or no driver connection */
  if (!g_InterceptState.Initialized ||
      g_InterceptState.DriverHandle == INVALID_HANDLE_VALUE) {
    goto CallOriginal;
  }

  /*
   * Serialize pending SQEs from submission queue
   * This reads from the user-mode mapped queue shared with kernel
   */
  hr = SerializePendingSqes(IoRingHandle, &sqeBuffer, &operationCount,
                            &sqeBufferSize);
  if (FAILED(hr)) {
    /* Serialization failed - log but allow (fail-open for stability) */
    goto CallOriginal;
  }

  /* Pre-validation callback (allows caller to inspect/modify) */
  if (g_InterceptState.PreCallback != NULL) {
    BOOL proceed = g_InterceptState.PreCallback(
        g_InterceptState.PreCallbackContext,
        (HANDLE)(IoRingHandle ? IoRingHandle->KernelHandle : NULL),
        operationCount, sqeBuffer, sqeBufferSize);

    if (!proceed) {
      /* Callback requested skip validation */
      if (sqeBuffer != NULL) {
        HeapFree(GetProcessHeap(), 0, sqeBuffer);
      }
      goto CallOriginal;
    }
  }

  /* Validate via driver with serialized SQEs */
  ZeroMemory(&response, sizeof(response));
  response.Size = sizeof(response);

  hr = ValidateViaDriver(
      (HANDLE)(IoRingHandle ? IoRingHandle->KernelHandle : NULL),
      operationCount, sqeBuffer, sqeBufferSize, &response);

  /* Post-validation callback */
  if (g_InterceptState.PostCallback != NULL) {
    g_InterceptState.PostCallback(
        g_InterceptState.PostCallbackContext,
        (HANDLE)(IoRingHandle ? IoRingHandle->KernelHandle : NULL), &response);
  }

  /* Free serialized buffer */
  if (sqeBuffer != NULL) {
    HeapFree(GetProcessHeap(), 0, sqeBuffer);
    sqeBuffer = NULL;
  }

  /* Check validation result */
  if (SUCCEEDED(hr) && response.Action == Win11MonIntercept_Block) {
    InterlockedDecrement(&g_InterceptState.InFlightCount);
    return (NTSTATUS)0xC0000022L; /* STATUS_ACCESS_DENIED */
  }

CallOriginal:
  /* Cleanup if we haven't already */
  if (sqeBuffer != NULL) {
    HeapFree(GetProcessHeap(), 0, sqeBuffer);
  }

  /* Call original function */
  if (g_InterceptState.OriginalNtSubmitIoRing != NULL) {
    status = g_InterceptState.OriginalNtSubmitIoRing(IoRingHandle, Flags,
                                                     WaitOperations, Timeout);
  } else {
    status = (NTSTATUS)0xC0000002L; /* STATUS_NOT_IMPLEMENTED */
  }

  InterlockedDecrement(&g_InterceptState.InFlightCount);
  return status;
}

/*--------------------------------------------------------------------------
 * Internal Helper: Install Inline Hook
 *
 * Simple 14-byte absolute jump for x64:
 *   push rax
 *   mov rax, <target>
 *   xchg rax, [rsp]
 *   ret
 *-------------------------------------------------------------------------*/
static HRESULT InstallInlineHook(_In_ PVOID Target, _In_ PVOID Detour,
                                 _Out_ PVOID* Original) {
  DWORD oldProtect;
  SIZE_T hookSize = 14;

  /* Save original bytes */
  if (hookSize > sizeof(g_InterceptState.OriginalBytes)) {
    return E_FAIL;
  }

  CopyMemory(g_InterceptState.OriginalBytes, Target, hookSize);
  g_InterceptState.OriginalBytesSize = hookSize;
  g_InterceptState.HookTarget = Target;

  /* Make target writable */
  if (!VirtualProtect(Target, hookSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
    return HRESULT_FROM_WIN32(GetLastError());
  }

  /* Write hook:
   * 50              push rax
   * 48 B8 xx xx xx xx xx xx xx xx  mov rax, imm64
   * 48 87 04 24     xchg [rsp], rax
   * C3              ret
   */
  BYTE hookCode[14] = {
      0x50,                                           /* push rax */
      0x48, 0xB8,                                     /* mov rax, imm64 */
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* <address> */
      0x48, 0x87, 0x04, 0x24,                         /* xchg [rsp], rax */
      /* Note: This is only 15 bytes, need ret */
  };

  /* Actually use a simpler 12-byte jump:
   * 48 B8 xx xx xx xx xx xx xx xx  mov rax, imm64
   * FF E0                          jmp rax
   */
  BYTE simpleHook[12] = {
      0x48, 0xB8,                                     /* mov rax, imm64 */
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* <address> */
      0xFF, 0xE0                                      /* jmp rax */
  };

  /* Fill in address */
  *(PVOID*)(&simpleHook[2]) = Detour;

  /* Write hook */
  CopyMemory(Target, simpleHook, 12);

  /* Restore protection */
  VirtualProtect(Target, hookSize, oldProtect, &oldProtect);

  /* Flush instruction cache */
  FlushInstructionCache(GetCurrentProcess(), Target, hookSize);

  /* Create trampoline for original function */
  /* For now, we'll allocate executable memory for the trampoline */
  PVOID trampoline =
      VirtualAlloc(NULL, hookSize + 14, /* Original bytes + jump back */
                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

  if (trampoline == NULL) {
    /* Restore original bytes on failure */
    VirtualProtect(Target, hookSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    CopyMemory(Target, g_InterceptState.OriginalBytes, hookSize);
    VirtualProtect(Target, hookSize, oldProtect, &oldProtect);
    return E_OUTOFMEMORY;
  }

  /* Copy original bytes to trampoline */
  CopyMemory(trampoline, g_InterceptState.OriginalBytes,
             g_InterceptState.OriginalBytesSize);

  /* Add jump back to original + hookSize */
  BYTE* jumpBack = (BYTE*)trampoline + g_InterceptState.OriginalBytesSize;
  jumpBack[0] = 0x48;
  jumpBack[1] = 0xB8;
  *(PVOID*)(&jumpBack[2]) = (BYTE*)Target + 12; /* After our hook */
  jumpBack[10] = 0xFF;
  jumpBack[11] = 0xE0;

  *Original = trampoline;
  return S_OK;
}

/*--------------------------------------------------------------------------
 * Internal Helper: Remove Inline Hook
 *-------------------------------------------------------------------------*/
static HRESULT RemoveInlineHook(VOID) {
  DWORD oldProtect;

  if (g_InterceptState.HookTarget == NULL ||
      g_InterceptState.OriginalBytesSize == 0) {
    return S_OK; /* Nothing to remove */
  }

  /* Restore original bytes */
  if (!VirtualProtect(g_InterceptState.HookTarget,
                      g_InterceptState.OriginalBytesSize,
                      PAGE_EXECUTE_READWRITE, &oldProtect)) {
    return HRESULT_FROM_WIN32(GetLastError());
  }

  CopyMemory(g_InterceptState.HookTarget, g_InterceptState.OriginalBytes,
             g_InterceptState.OriginalBytesSize);

  VirtualProtect(g_InterceptState.HookTarget,
                 g_InterceptState.OriginalBytesSize, oldProtect, &oldProtect);

  FlushInstructionCache(GetCurrentProcess(), g_InterceptState.HookTarget,
                        g_InterceptState.OriginalBytesSize);

  /* Free trampoline if it was allocated */
  if (g_InterceptState.OriginalNtSubmitIoRing != NULL) {
    /* Check if it's in our allocated memory (not the original ntdll) */
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    PVOID tramp = (PVOID)g_InterceptState.OriginalNtSubmitIoRing;

    MODULEINFO modInfo;
    if (GetModuleInformation(GetCurrentProcess(), hNtdll, &modInfo,
                             sizeof(modInfo))) {
      BYTE* ntdllStart = (BYTE*)modInfo.lpBaseOfDll;
      BYTE* ntdllEnd = ntdllStart + modInfo.SizeOfImage;

      if ((BYTE*)tramp < ntdllStart || (BYTE*)tramp >= ntdllEnd) {
        /* Trampoline is outside ntdll - we allocated it */
        VirtualFree(tramp, 0, MEM_RELEASE);
      }
    }
  }

  g_InterceptState.HookTarget = NULL;
  g_InterceptState.OriginalBytesSize = 0;
  g_InterceptState.OriginalNtSubmitIoRing = NULL;

  return S_OK;
}

/*==========================================================================
 * Public API Implementation
 *=========================================================================*/

WIN11MON_API HRESULT Win11MonInterceptInit(_In_ HWIN11MON Handle) {
  if (InterlockedCompareExchange(&g_InterceptState.Initialized, 0, 0) != 0) {
    return S_OK; /* Already initialized */
  }

  /* Get driver handle from client handle */
  /* This assumes HWIN11MON contains or maps to a driver handle */
  g_InterceptState.DriverHandle = GetDriverHandleFromClient(Handle);

  if (g_InterceptState.DriverHandle == INVALID_HANDLE_VALUE) {
    /* Try to get it from the handle structure directly */
    /* For now, we need to open our own handle to the driver */
    g_InterceptState.DriverHandle =
        CreateFileW(L"\\\\.\\Win11Monitor", GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);

    if (g_InterceptState.DriverHandle == INVALID_HANDLE_VALUE) {
      return WIN11MON_E_DRIVER_NOT_FOUND;
    }
  }

  /* Initialize critical section */
  InitializeCriticalSection(&g_InterceptState.Lock);

  /* Resolve NtSubmitIoRing */
  PFN_NtSubmitIoRing pfnSubmit = ResolveNtSubmitIoRing();
  if (pfnSubmit == NULL) {
    DeleteCriticalSection(&g_InterceptState.Lock);
    return WIN11MON_E_NOT_SUPPORTED;
  }

  /* Store original (will be replaced with trampoline when hooks installed) */
  g_InterceptState.OriginalNtSubmitIoRing = pfnSubmit;

  /* Mark initialized */
  InterlockedExchange(&g_InterceptState.Initialized, 1);

  return S_OK;
}

WIN11MON_API VOID Win11MonInterceptShutdown(_In_ HWIN11MON Handle) {
  UNREFERENCED_PARAMETER(Handle);

  if (InterlockedCompareExchange(&g_InterceptState.Initialized, 0, 0) == 0) {
    return;
  }

  /* Remove hooks first */
  if (g_InterceptState.HooksInstalled) {
    Win11MonInterceptRemoveHooks(Handle);
  }

  /* Wait for in-flight operations */
  while (InterlockedCompareExchange(&g_InterceptState.InFlightCount, 0, 0) >
         0) {
    Sleep(1);
  }

  /* Cleanup */
  DeleteCriticalSection(&g_InterceptState.Lock);

  /* Close driver handle if we opened it */
  if (g_InterceptState.DriverHandle != NULL &&
      g_InterceptState.DriverHandle != INVALID_HANDLE_VALUE) {
    CloseHandle(g_InterceptState.DriverHandle);
    g_InterceptState.DriverHandle = INVALID_HANDLE_VALUE;
  }

  /* Clear callbacks */
  g_InterceptState.PreCallback = NULL;
  g_InterceptState.PreCallbackContext = NULL;
  g_InterceptState.PostCallback = NULL;
  g_InterceptState.PostCallbackContext = NULL;

  InterlockedExchange(&g_InterceptState.Initialized, 0);
}

WIN11MON_API BOOL Win11MonInterceptIsAvailable(_In_ HWIN11MON Handle) {
  UNREFERENCED_PARAMETER(Handle);

  /* Check if NtSubmitIoRing exists in ntdll */
  return ResolveNtSubmitIoRing() != NULL;
}

WIN11MON_API BOOL Win11MonInterceptIsInitialized(_In_ HWIN11MON Handle) {
  UNREFERENCED_PARAMETER(Handle);
  return InterlockedCompareExchange(&g_InterceptState.Initialized, 0, 0) != 0;
}

WIN11MON_API HRESULT Win11MonInterceptEnable(_In_ HWIN11MON Handle,
                                             _In_ BOOL Enable) {
  UNREFERENCED_PARAMETER(Handle);

  if (!g_InterceptState.Initialized) {
    return WIN11MON_E_INVALID_HANDLE;
  }

  /* Send enable command to driver */
  DWORD enableVal = Enable ? 1 : 0;
  return SendIoctl(IOCTL_MONITOR_INTERCEPT_ENABLE, &enableVal,
                   sizeof(enableVal), NULL, 0, NULL);
}

WIN11MON_API BOOL Win11MonInterceptIsEnabled(_In_ HWIN11MON Handle) {
  WIN11MON_INTERCEPT_POLICY policy;
  HRESULT hr = Win11MonInterceptGetPolicy(Handle, &policy);

  if (FAILED(hr)) {
    return FALSE;
  }

  return policy.Enabled != 0;
}

WIN11MON_API HRESULT Win11MonInterceptSetPolicy(
    _In_ HWIN11MON Handle, _In_ const WIN11MON_INTERCEPT_POLICY* Policy) {
  UNREFERENCED_PARAMETER(Handle);

  if (!g_InterceptState.Initialized) {
    return WIN11MON_E_INVALID_HANDLE;
  }

  if (Policy == NULL || Policy->Size != sizeof(WIN11MON_INTERCEPT_POLICY)) {
    return E_INVALIDARG;
  }

  return SendIoctl(IOCTL_MONITOR_INTERCEPT_SET_POLICY, Policy,
                   sizeof(WIN11MON_INTERCEPT_POLICY), NULL, 0, NULL);
}

WIN11MON_API HRESULT Win11MonInterceptGetPolicy(
    _In_ HWIN11MON Handle, _Out_ PWIN11MON_INTERCEPT_POLICY Policy) {
  UNREFERENCED_PARAMETER(Handle);
  DWORD bytesReturned;

  if (!g_InterceptState.Initialized) {
    return WIN11MON_E_INVALID_HANDLE;
  }

  if (Policy == NULL) {
    return E_INVALIDARG;
  }

  ZeroMemory(Policy, sizeof(WIN11MON_INTERCEPT_POLICY));
  Policy->Size = sizeof(WIN11MON_INTERCEPT_POLICY);

  return SendIoctl(IOCTL_MONITOR_INTERCEPT_GET_POLICY, NULL, 0, Policy,
                   sizeof(WIN11MON_INTERCEPT_POLICY), &bytesReturned);
}

WIN11MON_API HRESULT Win11MonInterceptSetDefaultPolicy(_In_ HWIN11MON Handle) {
  WIN11MON_INTERCEPT_POLICY policy;
  ZeroMemory(&policy, sizeof(policy));

  policy.Size = sizeof(WIN11MON_INTERCEPT_POLICY);
  policy.Enabled = FALSE;
  policy.AuditMode = FALSE;
  policy.BlockKernelAddresses = TRUE;
  policy.BlockCorruptedRegBuffers = TRUE;
  policy.EnforceOperationLimit = TRUE;
  policy.EnforceRateLimit = FALSE;
  policy.ValidateOpCodes = TRUE;
  policy.MaxOperationsPerSubmit = WIN11MON_INTERCEPT_DEFAULT_MAX_OPS;
  policy.MaxBufferSizeBytes = WIN11MON_INTERCEPT_MAX_BUFFER_SIZE;
  policy.MaxSubmitsPerSecond = WIN11MON_INTERCEPT_DEFAULT_RATE_LIMIT;
  policy.AllowedOpCodeMask = WIN11MON_INTERCEPT_DEFAULT_OPCODE_MASK;

  return Win11MonInterceptSetPolicy(Handle, &policy);
}

WIN11MON_API HRESULT Win11MonInterceptGetStats(
    _In_ HWIN11MON Handle, _Out_ PWIN11MON_INTERCEPT_STATS Stats) {
  UNREFERENCED_PARAMETER(Handle);
  DWORD bytesReturned;

  if (!g_InterceptState.Initialized) {
    return WIN11MON_E_INVALID_HANDLE;
  }

  if (Stats == NULL) {
    return E_INVALIDARG;
  }

  ZeroMemory(Stats, sizeof(WIN11MON_INTERCEPT_STATS));
  Stats->Size = sizeof(WIN11MON_INTERCEPT_STATS);

  return SendIoctl(IOCTL_MONITOR_INTERCEPT_GET_STATS, NULL, 0, Stats,
                   sizeof(WIN11MON_INTERCEPT_STATS), &bytesReturned);
}

WIN11MON_API HRESULT Win11MonInterceptResetStats(_In_ HWIN11MON Handle) {
  UNREFERENCED_PARAMETER(Handle);

  if (!g_InterceptState.Initialized) {
    return WIN11MON_E_INVALID_HANDLE;
  }

  return SendIoctl(IOCTL_MONITOR_INTERCEPT_RESET_STATS, NULL, 0, NULL, 0, NULL);
}

WIN11MON_API HRESULT Win11MonInterceptAddBlacklist(_In_ HWIN11MON Handle,
                                                   _In_ DWORD ProcessId,
                                                   _In_opt_ PCSTR Reason) {
  UNREFERENCED_PARAMETER(Handle);

  if (!g_InterceptState.Initialized) {
    return WIN11MON_E_INVALID_HANDLE;
  }

  if (ProcessId == 0) {
    return E_INVALIDARG;
  }

  /* Build blacklist add request */
  struct {
    DWORD ProcessId;
    CHAR Reason[64];
  } request;

  request.ProcessId = ProcessId;
  ZeroMemory(request.Reason, sizeof(request.Reason));

  if (Reason != NULL) {
    StringCchCopyA(request.Reason, sizeof(request.Reason), Reason);
  }

  return SendIoctl(IOCTL_MONITOR_INTERCEPT_ADD_BL, &request, sizeof(request),
                   NULL, 0, NULL);
}

WIN11MON_API HRESULT Win11MonInterceptRemoveBlacklist(_In_ HWIN11MON Handle,
                                                      _In_ DWORD ProcessId) {
  UNREFERENCED_PARAMETER(Handle);

  if (!g_InterceptState.Initialized) {
    return WIN11MON_E_INVALID_HANDLE;
  }

  return SendIoctl(IOCTL_MONITOR_INTERCEPT_REMOVE_BL, &ProcessId,
                   sizeof(ProcessId), NULL, 0, NULL);
}

WIN11MON_API HRESULT Win11MonInterceptClearBlacklist(_In_ HWIN11MON Handle) {
  WIN11MON_BLACKLIST_ENTRY entries[WIN11MON_INTERCEPT_MAX_BLACKLIST];
  DWORD entryCount = 0;
  HRESULT hr;

  if (!g_InterceptState.Initialized) {
    return WIN11MON_E_INVALID_HANDLE;
  }

  /* Get current blacklist entries */
  hr = Win11MonInterceptGetBlacklist(
      Handle, entries, WIN11MON_INTERCEPT_MAX_BLACKLIST, &entryCount);
  if (FAILED(hr)) {
    return hr;
  }

  /* Remove each entry individually */
  for (DWORD i = 0; i < entryCount; i++) {
    if (entries[i].ProcessId != 0) {
      hr = Win11MonInterceptRemoveBlacklist(Handle, entries[i].ProcessId);
      /* Continue even if individual removes fail */
    }
  }

  return S_OK;
}

WIN11MON_API BOOL Win11MonInterceptIsBlacklisted(_In_ HWIN11MON Handle,
                                                 _In_ DWORD ProcessId) {
  WIN11MON_BLACKLIST_ENTRY entries[WIN11MON_INTERCEPT_MAX_BLACKLIST];
  DWORD entryCount = 0;

  HRESULT hr = Win11MonInterceptGetBlacklist(
      Handle, entries, WIN11MON_INTERCEPT_MAX_BLACKLIST, &entryCount);

  if (FAILED(hr)) {
    return FALSE;
  }

  for (DWORD i = 0; i < entryCount; i++) {
    if (entries[i].ProcessId == ProcessId) {
      return TRUE;
    }
  }

  return FALSE;
}

WIN11MON_API HRESULT Win11MonInterceptGetBlacklist(
    _In_ HWIN11MON Handle,
    _Out_writes_to_(MaxEntries, *EntryCount) PWIN11MON_BLACKLIST_ENTRY Buffer,
    _In_ DWORD MaxEntries, _Out_ DWORD* EntryCount) {
  UNREFERENCED_PARAMETER(Handle);
  DWORD bytesReturned;

  if (!g_InterceptState.Initialized) {
    return WIN11MON_E_INVALID_HANDLE;
  }

  if (Buffer == NULL || EntryCount == NULL) {
    return E_INVALIDARG;
  }

  *EntryCount = 0;

  DWORD bufferSize = MaxEntries * sizeof(WIN11MON_BLACKLIST_ENTRY);

  HRESULT hr =
      SendIoctl(IOCTL_MONITOR_INTERCEPT_GET_BL, &MaxEntries, sizeof(MaxEntries),
                Buffer, bufferSize, &bytesReturned);

  if (SUCCEEDED(hr)) {
    *EntryCount = bytesReturned / sizeof(WIN11MON_BLACKLIST_ENTRY);
  }

  return hr;
}

WIN11MON_API HRESULT Win11MonInterceptSetPreCallback(
    _In_ HWIN11MON Handle, _In_opt_ WIN11MON_PRE_VALIDATE_CALLBACK Callback,
    _In_opt_ PVOID Context) {
  UNREFERENCED_PARAMETER(Handle);

  if (!g_InterceptState.Initialized) {
    return WIN11MON_E_INVALID_HANDLE;
  }

  EnterCriticalSection(&g_InterceptState.Lock);
  g_InterceptState.PreCallback = Callback;
  g_InterceptState.PreCallbackContext = Context;
  LeaveCriticalSection(&g_InterceptState.Lock);

  return S_OK;
}

WIN11MON_API HRESULT Win11MonInterceptSetPostCallback(
    _In_ HWIN11MON Handle, _In_opt_ WIN11MON_POST_VALIDATE_CALLBACK Callback,
    _In_opt_ PVOID Context) {
  UNREFERENCED_PARAMETER(Handle);

  if (!g_InterceptState.Initialized) {
    return WIN11MON_E_INVALID_HANDLE;
  }

  EnterCriticalSection(&g_InterceptState.Lock);
  g_InterceptState.PostCallback = Callback;
  g_InterceptState.PostCallbackContext = Context;
  LeaveCriticalSection(&g_InterceptState.Lock);

  return S_OK;
}

WIN11MON_API HRESULT Win11MonInterceptInstallHooks(_In_ HWIN11MON Handle) {
  UNREFERENCED_PARAMETER(Handle);
  HRESULT hr;

  if (!g_InterceptState.Initialized) {
    return WIN11MON_E_INVALID_HANDLE;
  }

  if (InterlockedCompareExchange(&g_InterceptState.HooksInstalled, 0, 0) != 0) {
    return S_OK; /* Already installed */
  }

  /* Get original function address */
  PFN_NtSubmitIoRing pfnOriginal = ResolveNtSubmitIoRing();
  if (pfnOriginal == NULL) {
    return WIN11MON_E_NOT_SUPPORTED;
  }

  /* Install inline hook */
  PVOID trampoline = NULL;
  hr = InstallInlineHook((PVOID)pfnOriginal, (PVOID)HookedNtSubmitIoRing,
                         &trampoline);

  if (FAILED(hr)) {
    return hr;
  }

  /* Store trampoline as our "original" */
  g_InterceptState.OriginalNtSubmitIoRing = (PFN_NtSubmitIoRing)trampoline;
  InterlockedExchange(&g_InterceptState.HooksInstalled, 1);

  return S_OK;
}

WIN11MON_API HRESULT Win11MonInterceptRemoveHooks(_In_ HWIN11MON Handle) {
  UNREFERENCED_PARAMETER(Handle);

  if (!g_InterceptState.Initialized) {
    return WIN11MON_E_INVALID_HANDLE;
  }

  if (InterlockedCompareExchange(&g_InterceptState.HooksInstalled, 0, 0) == 0) {
    return S_OK; /* Not installed */
  }

  /* Wait for in-flight calls to complete */
  while (InterlockedCompareExchange(&g_InterceptState.InFlightCount, 0, 0) >
         0) {
    Sleep(1);
  }

  /* Remove hook */
  HRESULT hr = RemoveInlineHook();

  if (SUCCEEDED(hr)) {
    InterlockedExchange(&g_InterceptState.HooksInstalled, 0);
  }

  return hr;
}

WIN11MON_API BOOL Win11MonInterceptAreHooksInstalled(_In_ HWIN11MON Handle) {
  UNREFERENCED_PARAMETER(Handle);
  return InterlockedCompareExchange(&g_InterceptState.HooksInstalled, 0, 0) !=
         0;
}

WIN11MON_API HRESULT Win11MonInterceptValidate(
    _In_ HWIN11MON Handle, _In_ HANDLE IoRingHandle, _In_ DWORD OperationCount,
    _In_reads_bytes_(BufferSize) const VOID* SubmissionBuffer,
    _In_ DWORD BufferSize, _Out_ PWIN11MON_INTERCEPT_RESPONSE Response) {
  UNREFERENCED_PARAMETER(Handle);

  if (!g_InterceptState.Initialized) {
    return WIN11MON_E_INVALID_HANDLE;
  }

  if (Response == NULL) {
    return E_INVALIDARG;
  }

  return ValidateViaDriver(IoRingHandle, OperationCount, SubmissionBuffer,
                           BufferSize, Response);
}

WIN11MON_API HRESULT Win11MonInterceptBuildRequest(
    _In_ HANDLE IoRingHandle,
    _In_reads_(SqeCount) const WIN11MON_SERIALIZED_SQE* SqeArray,
    _In_ DWORD SqeCount,
    _Out_writes_bytes_to_(RequestBufferSize, *RequestSize)
        PWIN11MON_INTERCEPT_REQUEST Request,
    _In_ DWORD RequestBufferSize, _Out_ DWORD* RequestSize) {
  if (Request == NULL || RequestSize == NULL) {
    return E_INVALIDARG;
  }

  DWORD sqeBufferSize = SqeCount * sizeof(WIN11MON_SERIALIZED_SQE);

  return BuildValidationRequest(IoRingHandle, SqeCount, SqeArray, sqeBufferSize,
                                Request, RequestBufferSize, RequestSize);
}
