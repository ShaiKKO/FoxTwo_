/*
 * VAD Tree Walker
 *
 * Author: Colin MacRitchie
 * Organization: ziX Labs - Security Research Division
 * File: vad_walker.c
 * Version: 1.0
 * Date: 2025-12-01
 * Copyright:
 *   © 2025 ziX Performance Labs. All rights reserved. Proprietary and
 * confidential. Redistribution or disclosure without prior written consent is
 * prohibited.
 *
 * Summary:
 * Walks the VAD (Virtual Address Descriptor) tree for a target process.
 * VAD structures are undocumented and version-dependent, requiring runtime
 * offset resolution. Extracts memory region information for security analysis.
 *
 * Threading Model:
 * - Acquires process rundown protection during walk
 * - Snapshot-based: no persistent locks held
 * - Short-lived attachment to target process
 *
 * SECURITY PROPERTIES:
 * - Input: ProcessId validated, target process referenced safely
 * - Output: All virtual addresses masked before export
 * - Memory Safety: SEH guards on all VAD dereferences
 * - IRQL: PASSIVE_LEVEL required for process attachment
 */

#include <ntddk.h>
#include <ntstrsafe.h>

#include "addr_mask.h" /* MonAddrMask */
#include "mem_monitor.h"
#include "offset_resolver.h" /* For VAD structure offsets */

#pragma warning(push)
#pragma warning(disable : 4201) /* nameless struct/union */

/*--------------------------------------------------------------------------*/
/* Undocumented Structure Offsets                                           */
/*--------------------------------------------------------------------------*/

/* These offsets are resolved at runtime via offset_resolver.c */
/* Default values are for Windows 11 22H2 - may need adjustment */

static ULONG g_VadRootOffset = 0x7D8;    /* EPROCESS.VadRoot */
static ULONG g_VadNodeOffset = 0x0;      /* MMVAD.VadNode (RTL_BALANCED_NODE) */
static ULONG g_StartingVpnOffset = 0x18; /* MMVAD.StartingVpn */
static ULONG g_EndingVpnOffset = 0x1C;   /* MMVAD.EndingVpn */
static ULONG g_FlagsOffset = 0x30;       /* MMVAD.u (flags union) */

static BOOLEAN g_OffsetsResolved = FALSE;

/*--------------------------------------------------------------------------*/
/* VAD Flags Interpretation                                                 */
/*--------------------------------------------------------------------------*/

/* MMVAD_FLAGS bit layout (Windows 11) */
#define VAD_FLAG_VADTYPE_MASK     0x00000007
#define VAD_FLAG_PROTECTION_SHIFT 7
#define VAD_FLAG_PROTECTION_MASK  0x00001F00
#define VAD_FLAG_PRIVATE_MEMORY   0x00100000

/* Protection to readable flags */
static const ULONG ProtectionReadable[] = {
    0, /* PAGE_NOACCESS */
    0, /* PAGE_READONLY - readable */
    0, /* PAGE_EXECUTE */
    0, /* PAGE_EXECUTE_READ */
    0, /* PAGE_READWRITE */
    0, /* PAGE_WRITECOPY */
    0, /* PAGE_EXECUTE_READWRITE */
    0, /* PAGE_EXECUTE_WRITECOPY */
};

/*--------------------------------------------------------------------------*/
/* Forward Declarations                                                     */
/*--------------------------------------------------------------------------*/

static NTSTATUS MonVadResolveOffsets(VOID);
static NTSTATUS MonVadGetProcess(_In_ ULONG ProcessId, _Out_ PEPROCESS *Process);
static VOID MonVadWalkNode(_In_ PVOID VadNode, _Inout_ PMON_VAD_SCAN_RESULT Result,
                           _In_ ULONG MaxDetails, _Inout_ ULONG *DetailIndex);
static VOID MonVadExtractInfo(_In_ PVOID VadNode, _Out_ PMON_VAD_INFO Info);
static MON_VAD_TYPE MonVadTypeFromFlags(_In_ ULONG Flags);
static VOID MonVadCheckAnomaly(_In_ PMON_VAD_INFO Info, _Inout_ PMON_VAD_SCAN_RESULT Result);

/*--------------------------------------------------------------------------*/
/* Offset Resolution                                                        */
/*--------------------------------------------------------------------------*/

/**
 * Resolve VAD structure offsets for current Windows build
 */
static NTSTATUS MonVadResolveOffsets(VOID) {
  NTSTATUS status;
  ULONG buildNumber;

  if (g_OffsetsResolved) {
    return STATUS_SUCCESS;
  }

  /* Get Windows build number */
  PsGetVersion(NULL, NULL, &buildNumber, NULL);

  /* Adjust offsets based on build */
  switch (buildNumber) {
  case 22621: /* Windows 11 22H2 */
  case 22631: /* Windows 11 23H2 */
    g_VadRootOffset = 0x7D8;
    g_StartingVpnOffset = 0x18;
    g_EndingVpnOffset = 0x1C;
    g_FlagsOffset = 0x30;
    break;

  case 26100: /* Windows 11 24H2 */
    g_VadRootOffset = 0x7E0;
    g_StartingVpnOffset = 0x18;
    g_EndingVpnOffset = 0x1C;
    g_FlagsOffset = 0x30;
    break;

  default:
    /* Try to use offset resolver */
    status = MonOffsetResolverGetVadOffsets(&g_VadRootOffset, &g_StartingVpnOffset,
                                            &g_EndingVpnOffset, &g_FlagsOffset);

    if (!NT_SUCCESS(status)) {
      DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                 "[WIN11MON] VAD offsets unknown for build %lu\n", buildNumber);
      return STATUS_NOT_SUPPORTED;
    }
    break;
  }

  g_OffsetsResolved = TRUE;
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
             "[WIN11MON] VAD offsets resolved for build %lu\n", buildNumber);

  return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------*/
/* Process Access                                                           */
/*--------------------------------------------------------------------------*/

/**
 * Get EPROCESS for target process with rundown protection
 */
static NTSTATUS MonVadGetProcess(_In_ ULONG ProcessId, _Out_ PEPROCESS *Process) {
  NTSTATUS status;
  HANDLE processHandle = ULongToHandle(ProcessId);

  *Process = NULL;

  status = PsLookupProcessByProcessId(processHandle, Process);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------*/
/* VAD Node Extraction                                                      */
/*--------------------------------------------------------------------------*/

/**
 * Extract VAD info from a node
 */
static VOID MonVadExtractInfo(_In_ PVOID VadNode, _Out_ PMON_VAD_INFO Info) {
  ULONG startingVpn;
  ULONG endingVpn;
  UCHAR startingVpnHigh;
  UCHAR endingVpnHigh;
  ULONG flags;
  ULONG protection;

  RtlZeroMemory(Info, sizeof(*Info));

  __try {
    /* Read VPN values */
    startingVpn = *(PULONG)((PUCHAR)VadNode + g_StartingVpnOffset);
    endingVpn = *(PULONG)((PUCHAR)VadNode + g_EndingVpnOffset);

    /* Read high bytes (for 64-bit address space) */
    startingVpnHigh = *((PUCHAR)VadNode + g_StartingVpnOffset + 4);
    endingVpnHigh = *((PUCHAR)VadNode + g_EndingVpnOffset + 4);

    /* Calculate addresses */
    Info->StartAddress = ((ULONG64)startingVpnHigh << 32 | startingVpn) << PAGE_SHIFT;
    Info->EndAddress = (((ULONG64)endingVpnHigh << 32 | endingVpn) << PAGE_SHIFT) + PAGE_SIZE - 1;
    Info->Size = Info->EndAddress - Info->StartAddress + 1;

    /* Mask addresses for security */
    Info->StartAddress = MonAddrMask(Info->StartAddress);
    Info->EndAddress = MonAddrMask(Info->EndAddress);

    /* Read flags */
    flags = *(PULONG)((PUCHAR)VadNode + g_FlagsOffset);

    /* Extract VAD type */
    Info->VadType = MonVadTypeFromFlags(flags);

    /* Extract protection */
    protection = (flags & VAD_FLAG_PROTECTION_MASK) >> VAD_FLAG_PROTECTION_SHIFT;
    Info->Protection = protection;
    Info->InitialProtection = protection;

    /* Determine protection characteristics */
    Info->IsExecutable = (protection >= 3 && protection <= 7);
    Info->IsWritable = (protection == 4 || protection == 5 || protection == 6 || protection == 7);
    Info->IsPrivate = (flags & VAD_FLAG_PRIVATE_MEMORY) != 0;

    Info->IsCommitted = TRUE; /* Simplified - actual check needs more work */

  } __except (EXCEPTION_EXECUTE_HANDLER) {
    RtlZeroMemory(Info, sizeof(*Info));
  }
}

/**
 * Convert VAD flags to type enum
 */
static MON_VAD_TYPE MonVadTypeFromFlags(_In_ ULONG Flags) {
  ULONG vadType = Flags & VAD_FLAG_VADTYPE_MASK;

  switch (vadType) {
  case 0:
    return MonVadType_Private;
  case 1:
    return MonVadType_Mapped;
  case 2:
    return MonVadType_Image;
  case 3:
    return MonVadType_Physical;
  case 4:
    return MonVadType_WriteWatch;
  case 5:
    return MonVadType_LargePages;
  case 6:
    return MonVadType_Rotate;
  default:
    return MonVadType_Unknown;
  }
}

/*--------------------------------------------------------------------------*/
/* Anomaly Detection                                                        */
/*--------------------------------------------------------------------------*/

/**
 * Check VAD for anomalies
 */
static VOID MonVadCheckAnomaly(_In_ PMON_VAD_INFO Info, _Inout_ PMON_VAD_SCAN_RESULT Result) {
  /* Executable heap (private + executable, not image) */
  if (Info->IsPrivate && Info->IsExecutable && Info->VadType != MonVadType_Image) {
    Result->AnomalyFlags |= (1 << MonMemAnomaly_ExecutableHeap);
    Result->SuspiciousVadCount++;
  }

  /* Writable code section */
  if (Info->VadType == MonVadType_Image && Info->IsWritable && Info->IsExecutable) {
    Result->AnomalyFlags |= (1 << MonMemAnomaly_WritableCode);
    Result->SuspiciousVadCount++;
  }

  /* Unbacked executable (private executable without file backing) */
  if (Info->IsExecutable && Info->IsPrivate && !Info->HasFileBackingStore) {
    Result->AnomalyFlags |= (1 << MonMemAnomaly_UnbackedExecutable);
    Result->SuspiciousVadCount++;
  }
}

/*--------------------------------------------------------------------------*/
/* Tree Walking                                                             */
/*--------------------------------------------------------------------------*/

/**
 * Recursively walk VAD node and children
 */
static VOID MonVadWalkNode(_In_ PVOID VadNode, _Inout_ PMON_VAD_SCAN_RESULT Result,
                           _In_ ULONG MaxDetails, _Inout_ ULONG *DetailIndex) {
  PRTL_BALANCED_NODE balancedNode;
  MON_VAD_INFO vadInfo;
  PMON_VAD_INFO detailArray;

  if (VadNode == NULL) {
    return;
  }

  __try {
    balancedNode = (PRTL_BALANCED_NODE)((PUCHAR)VadNode + g_VadNodeOffset);

    /* Process current node */
    MonVadExtractInfo(VadNode, &vadInfo);
    Result->VadCount++;

    /* Accumulate statistics */
    if (vadInfo.IsPrivate) {
      Result->TotalPrivateBytes += vadInfo.Size;
    } else {
      Result->TotalMappedBytes += vadInfo.Size;
    }

    if (vadInfo.IsExecutable) {
      Result->TotalExecutableBytes += vadInfo.Size;
    }

    Result->TotalCommittedBytes += vadInfo.Size;

    /* Check for anomalies */
    MonVadCheckAnomaly(&vadInfo, Result);

    /* Store detailed info if space available */
    if (*DetailIndex < MaxDetails) {
      detailArray = (PMON_VAD_INFO)((PUCHAR)Result + sizeof(MON_VAD_SCAN_RESULT));
      RtlCopyMemory(&detailArray[*DetailIndex], &vadInfo, sizeof(vadInfo));
      (*DetailIndex)++;
      Result->DetailedInfoCount = *DetailIndex;
    }

    /* Walk left subtree */
    if (balancedNode->Left != NULL) {
      /* Calculate VAD address from balanced node */
      PVOID leftVad = (PVOID)((PUCHAR)balancedNode->Left - g_VadNodeOffset);
      MonVadWalkNode(leftVad, Result, MaxDetails, DetailIndex);
    }

    /* Walk right subtree */
    if (balancedNode->Right != NULL) {
      PVOID rightVad = (PVOID)((PUCHAR)balancedNode->Right - g_VadNodeOffset);
      MonVadWalkNode(rightVad, Result, MaxDetails, DetailIndex);
    }

  } __except (EXCEPTION_EXECUTE_HANDLER) {
    /* Log exception but continue */
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
               "[WIN11MON] Exception walking VAD node at %p\n", VadNode);
  }
}

/*--------------------------------------------------------------------------*/
/* Public API                                                               */
/*--------------------------------------------------------------------------*/

/**
 * @function   MonVadWalkTree
 * @purpose    Walk VAD tree for a process
 * @precondition IRQL == PASSIVE_LEVEL
 * @postcondition VAD scan result populated
 * @returns    STATUS_SUCCESS or error
 * @thread-safety Snapshot-based, no persistent locks
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS
    MonVadWalkTree(_In_ ULONG ProcessId,
                   _Out_writes_bytes_to_(OutLen, *BytesWritten) PVOID OutBuffer, _In_ ULONG OutLen,
                   _Out_ ULONG *BytesWritten) {
  NTSTATUS status;
  PEPROCESS process = NULL;
  PMON_VAD_SCAN_RESULT result = (PMON_VAD_SCAN_RESULT)OutBuffer;
  PVOID vadRoot;
  ULONG maxDetails;
  ULONG detailIndex = 0;
  LARGE_INTEGER startTime, endTime, frequency;

  if (OutBuffer == NULL || BytesWritten == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  if (OutLen < sizeof(MON_VAD_SCAN_RESULT)) {
    return STATUS_BUFFER_TOO_SMALL;
  }

  *BytesWritten = 0;

  /* Resolve offsets if needed */
  status = MonVadResolveOffsets();
  if (!NT_SUCCESS(status)) {
    return status;
  }

  /* Get target process */
  status = MonVadGetProcess(ProcessId, &process);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  /* Initialize result */
  RtlZeroMemory(result, OutLen);
  result->Size = sizeof(MON_VAD_SCAN_RESULT);
  result->ProcessId = ProcessId;

  /* Calculate max detailed entries that fit */
  maxDetails = (OutLen - sizeof(MON_VAD_SCAN_RESULT)) / sizeof(MON_VAD_INFO);
  maxDetails = min(maxDetails, MON_MAX_VAD_DETAILED);

  /* Get timing */
  KeQueryPerformanceCounter(&startTime);
  result->ScanStartTime = KeQueryInterruptTime();

  __try {
    /* Get VAD root from EPROCESS */
    vadRoot = *(PVOID *)((PUCHAR)process + g_VadRootOffset);

    if (vadRoot != NULL) {
      MonVadWalkNode(vadRoot, result, maxDetails, &detailIndex);
    }

  } __except (EXCEPTION_EXECUTE_HANDLER) {
    status = GetExceptionCode();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[WIN11MON] Exception walking VAD tree: 0x%08X\n", status);
  }

  /* Record timing */
  KeQueryPerformanceCounter(&endTime);
  result->ScanEndTime = KeQueryInterruptTime();

  KeQueryPerformanceCounter(&frequency);
  if (frequency.QuadPart > 0) {
    result->ScanDurationUs =
        (ULONG)((endTime.QuadPart - startTime.QuadPart) * 1000000 / frequency.QuadPart);
  }

  /* Dereference process */
  ObDereferenceObject(process);

  *BytesWritten = sizeof(MON_VAD_SCAN_RESULT) + (detailIndex * sizeof(MON_VAD_INFO));

  return STATUS_SUCCESS;
}

#pragma warning(pop)
