/*
 * Dynamic Offset Resolution Module - Public Header
 *
 * Author: Colin MacRitchie
 * Organization: ziX Performance Labs
 * File: offset_resolver.h
 * Version: 1.0
 * Date: 2025-12-01
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and
 * confidential. Redistribution or disclosure without prior written consent is
 * prohibited.
 *
 * Summary
 * -------
 * Provides dynamic structure offset resolution for cross-version Windows
 * compatibility. Implements a three-tier resolution strategy:
 *
 * 1. Embedded Tables (Primary)
 *    - Hardcoded offsets for known Windows builds
 *    - Fastest, most reliable for supported builds
 *
 * 2. Signature-Based Resolution (Fallback)
 *    - Memory pattern scanning for unknown builds
 *    - Uses structural invariants to derive offsets
 *
 * 3. Manual Override (Admin)
 *    - Registry or IOCTL-provided offsets
 *    - For testing or emergency patches
 *
 * Design Principles:
 * - Safety first: All resolved offsets validated before use
 * - Graceful degradation: Unknown build -> nearest known -> disabled
 * - Audit trail: All resolution attempts logged via ETW
 * - IRQL-safe: Query functions safe up to DISPATCH_LEVEL
 *
 * References:
 * - KPDB: https://github.com/GetRektBoy724/KPDB
 * - Offset-Free DSE:
 * https://blog.cryptoplague.net/main/research/windows-research/
 */

#ifndef _ZIX_LABS_OFFSET_RESOLVER_H_
#define _ZIX_LABS_OFFSET_RESOLVER_H_

#ifndef _KERNEL_MODE
#error "This header is for kernel-mode only."
#endif

#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------
 * Configuration Constants
 *-------------------------------------------------------------------------*/

/* Maximum structures tracked by resolver */
#define MON_OFFSET_MAX_STRUCTURES 8

/* Maximum fields per structure */
#define MON_OFFSET_MAX_FIELDS 16

/* Maximum structure/field name length */
#define MON_OFFSET_MAX_NAME_LEN 64

/* Build number tolerance for nearest-match fallback */
#define MON_OFFSET_BUILD_TOLERANCE 500

/* Signature scan memory limit (16MB) */
#define MON_OFFSET_SIGNATURE_SCAN_LIMIT (16 * 1024 * 1024)

/*--------------------------------------------------------------------------
 * Resolution Source Enumeration
 *
 * Indicates how an offset was determined.
 *-------------------------------------------------------------------------*/
typedef enum _MON_OFFSET_SOURCE {
  MonOffsetSource_Unknown = 0,   /* Not yet resolved */
  MonOffsetSource_Embedded = 1,  /* From compiled-in table */
  MonOffsetSource_Signature = 2, /* From memory signature scan */
  MonOffsetSource_Override = 3,  /* From admin override */
  MonOffsetSource_Inferred = 4   /* From nearest known build */
} MON_OFFSET_SOURCE;

/*--------------------------------------------------------------------------
 * Validation Status Enumeration
 *-------------------------------------------------------------------------*/
typedef enum _MON_OFFSET_VALIDATION {
  MonOffsetValidation_NotTested = 0, /* Not yet validated */
  MonOffsetValidation_Passed = 1,    /* Runtime validation passed */
  MonOffsetValidation_Failed = 2,    /* Runtime validation failed */
  MonOffsetValidation_Skipped = 3    /* Validation skipped (no test object) */
} MON_OFFSET_VALIDATION;

/*--------------------------------------------------------------------------
 * Resolved Offset Entry
 *
 * Represents a single field offset within a structure.
 *-------------------------------------------------------------------------*/
typedef struct _MON_RESOLVED_OFFSET {
  CHAR FieldName[MON_OFFSET_MAX_NAME_LEN];
  ULONG Offset;                     /* Byte offset from structure start */
  ULONG Size;                       /* Field size in bytes (0 if unknown) */
  MON_OFFSET_SOURCE Source;         /* How this offset was determined */
  MON_OFFSET_VALIDATION Validation; /* Runtime validation status */
} MON_RESOLVED_OFFSET, *PMON_RESOLVED_OFFSET;

/*--------------------------------------------------------------------------
 * Structure Offset Table
 *
 * Contains all resolved offsets for a single structure type.
 *-------------------------------------------------------------------------*/
typedef struct _MON_STRUCTURE_OFFSETS {
  CHAR StructureName[MON_OFFSET_MAX_NAME_LEN];
  ULONG StructureSize;             /* Total structure size (0 if unknown) */
  ULONG TargetBuild;               /* Windows build this was resolved for */
  ULONG SourceBuild;               /* Build the offsets came from */
  MON_OFFSET_SOURCE OverallSource; /* Primary resolution method used */
  MON_OFFSET_VALIDATION OverallValidation;
  ULONG FieldCount; /* Number of fields resolved */
  MON_RESOLVED_OFFSET Fields[MON_OFFSET_MAX_FIELDS];
} MON_STRUCTURE_OFFSETS, *PMON_STRUCTURE_OFFSETS;

/*--------------------------------------------------------------------------
 * Resolver Configuration
 *
 * Passed to MonOffsetResolverInitialize to configure behavior.
 *-------------------------------------------------------------------------*/
typedef struct _MON_OFFSET_RESOLVER_CONFIG {
  ULONG Size;                  /* Must be sizeof(MON_OFFSET_RESOLVER_CONFIG) */
  BOOLEAN EnableSignatureScan; /* Allow signature-based fallback */
  BOOLEAN EnableInference;     /* Allow nearest-build inference */
  BOOLEAN RequireValidation;   /* Fail if validation cannot pass */
  ULONG BuildTolerance;        /* Max build number delta for inference */
} MON_OFFSET_RESOLVER_CONFIG, *PMON_OFFSET_RESOLVER_CONFIG;

/*--------------------------------------------------------------------------
 * Resolver Statistics
 *
 * Runtime statistics about offset resolution.
 *-------------------------------------------------------------------------*/
typedef struct _MON_OFFSET_RESOLVER_STATS {
  ULONG Size;                 /* sizeof(MON_OFFSET_RESOLVER_STATS) */
  ULONG CurrentBuild;         /* Running Windows build */
  ULONG StructuresRegistered; /* Structures with offsets */
  ULONG StructuresValidated;  /* Structures validated */
  ULONG EmbeddedHits;         /* Resolutions from embedded */
  ULONG SignatureHits;        /* Resolutions from signature */
  ULONG InferenceHits;        /* Resolutions from inference */
  ULONG ValidationFailures;   /* Validation test failures */
  BOOLEAN Initialized;        /* Resolver initialized */
  BOOLEAN Degraded;           /* Operating in degraded mode */
} MON_OFFSET_RESOLVER_STATS, *PMON_OFFSET_RESOLVER_STATS;

/*--------------------------------------------------------------------------
 * Well-Known Structure Names
 *
 * String constants for common structures resolved by this module.
 *-------------------------------------------------------------------------*/
#define MON_STRUCT_IORING_OBJECT       "_IORING_OBJECT"
#define MON_STRUCT_IOP_MC_BUFFER_ENTRY "_IOP_MC_BUFFER_ENTRY"

/*--------------------------------------------------------------------------
 * Well-Known Field Names
 *-------------------------------------------------------------------------*/
#define MON_FIELD_REGBUFFERS_COUNT "RegBuffersCount"
#define MON_FIELD_REGBUFFERS       "RegBuffers"
#define MON_FIELD_REGFILES_COUNT   "RegFilesCount"
#define MON_FIELD_REGFILES         "RegFiles"

/*--------------------------------------------------------------------------
 * Public Function Prototypes
 *-------------------------------------------------------------------------*/

/**
 * @function   MonOffsetResolverInitialize
 * @purpose    Initialize the offset resolver subsystem
 * @precondition IRQL == PASSIVE_LEVEL; Called from DriverEntry
 * @postcondition Resolver ready for offset queries
 * @thread-safety Single-threaded initialization
 * @side-effects Populates internal offset tables
 *
 * @param[in] Config - Optional configuration (NULL for defaults)
 * @returns   STATUS_SUCCESS on success
 *            STATUS_INSUFFICIENT_RESOURCES on allocation failure
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS
    MonOffsetResolverInitialize(_In_opt_ const MON_OFFSET_RESOLVER_CONFIG *Config);

/**
 * @function   MonOffsetResolverShutdown
 * @purpose    Shut down the offset resolver and free resources
 * @precondition IRQL == PASSIVE_LEVEL; Called from DriverUnload
 * @postcondition All resolver state cleared
 * @thread-safety Single-threaded shutdown
 * @side-effects Frees internal tables
 */
_IRQL_requires_(PASSIVE_LEVEL) VOID MonOffsetResolverShutdown(VOID);

/**
 * @function   MonOffsetResolverIsInitialized
 * @purpose    Check if resolver is operational
 * @precondition IRQL <= DISPATCH_LEVEL
 * @postcondition Returns TRUE if resolver is ready
 * @thread-safety Thread-safe read-only
 * @side-effects None
 */
_IRQL_requires_max_(DISPATCH_LEVEL) BOOLEAN MonOffsetResolverIsInitialized(VOID);

/**
 * @function   MonGetStructureOffsets
 * @purpose    Retrieve all resolved offsets for a structure
 * @precondition IRQL <= DISPATCH_LEVEL; Resolver initialized
 * @postcondition Offsets structure populated
 * @thread-safety Thread-safe read-only
 * @side-effects None
 *
 * @param[in] StructureName - Name of structure (e.g., "_IORING_OBJECT")
 * @param[out] Offsets - Structure to receive offset data
 * @returns   STATUS_SUCCESS if found
 *            STATUS_NOT_FOUND if structure not registered
 *            STATUS_NOT_SUPPORTED if resolver not initialized
 */
_IRQL_requires_max_(DISPATCH_LEVEL) NTSTATUS
    MonGetStructureOffsets(_In_z_ const CHAR *StructureName, _Out_ PMON_STRUCTURE_OFFSETS Offsets);

/**
 * @function   MonGetFieldOffset
 * @purpose    Retrieve a single field's offset
 * @precondition IRQL <= DISPATCH_LEVEL; Resolver initialized
 * @postcondition Offset written if field found
 * @thread-safety Thread-safe read-only
 * @side-effects None
 *
 * @param[in] StructureName - Name of containing structure
 * @param[in] FieldName - Name of field
 * @param[out] Offset - Receives the byte offset
 * @returns   STATUS_SUCCESS if found
 *            STATUS_NOT_FOUND if structure or field not found
 */
_IRQL_requires_max_(DISPATCH_LEVEL) NTSTATUS
    MonGetFieldOffset(_In_z_ const CHAR *StructureName, _In_z_ const CHAR *FieldName,
                      _Out_ PULONG Offset);

/**
 * @function   MonGetFieldOffsetWithSize
 * @purpose    Retrieve a field's offset and size
 * @precondition IRQL <= DISPATCH_LEVEL
 * @postcondition Offset and size written if found
 * @thread-safety Thread-safe read-only
 * @side-effects None
 */
_IRQL_requires_max_(DISPATCH_LEVEL) NTSTATUS
    MonGetFieldOffsetWithSize(_In_z_ const CHAR *StructureName, _In_z_ const CHAR *FieldName,
                              _Out_ PULONG Offset, _Out_ PULONG Size);

/**
 * @function   MonGetOffsetSource
 * @purpose    Determine how a structure's offsets were resolved
 * @precondition IRQL <= DISPATCH_LEVEL
 * @postcondition Returns resolution source
 * @thread-safety Thread-safe read-only
 * @side-effects None
 */
_IRQL_requires_max_(DISPATCH_LEVEL) MON_OFFSET_SOURCE
    MonGetOffsetSource(_In_z_ const CHAR *StructureName);

/**
 * @function   MonAreOffsetsValidated
 * @purpose    Check if a structure's offsets passed runtime validation
 * @precondition IRQL <= DISPATCH_LEVEL
 * @postcondition Returns TRUE if validated
 * @thread-safety Thread-safe read-only
 * @side-effects None
 */
_IRQL_requires_max_(DISPATCH_LEVEL) BOOLEAN
    MonAreOffsetsValidated(_In_z_ const CHAR *StructureName);

/**
 * @function   MonValidateStructureOffsets
 * @purpose    Validate resolved offsets against a live object
 * @precondition IRQL == PASSIVE_LEVEL
 * @postcondition Validation status updated internally
 * @thread-safety May acquire internal lock
 * @side-effects Updates validation status; may emit ETW event
 *
 * @param[in] StructureName - Name of structure to validate
 * @param[in] TestObject - Live object to validate against (SEH guarded)
 * @returns   STATUS_SUCCESS if validation passed
 *            STATUS_UNSUCCESSFUL if validation failed
 *            STATUS_NOT_FOUND if structure not registered
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS
    MonValidateStructureOffsets(_In_z_ const CHAR *StructureName, _In_ PVOID TestObject);

/**
 * @function   MonOffsetResolverGetStats
 * @purpose    Retrieve resolver statistics
 * @precondition IRQL <= DISPATCH_LEVEL
 * @postcondition Stats structure populated
 * @thread-safety Thread-safe snapshot
 * @side-effects None
 */
_IRQL_requires_max_(DISPATCH_LEVEL) VOID
    MonOffsetResolverGetStats(_Out_ PMON_OFFSET_RESOLVER_STATS Stats);

/**
 * @function   MonRegisterStructureOffsets
 * @purpose    Register offsets for a structure (typically from embedded table)
 * @precondition IRQL == PASSIVE_LEVEL
 * @postcondition Structure offsets registered for queries
 * @thread-safety Not thread-safe; call during init only
 * @side-effects Modifies internal offset tables
 *
 * @param[in] Offsets - Structure offset table to register
 * @returns   STATUS_SUCCESS on success
 *            STATUS_QUOTA_EXCEEDED if too many structures registered
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS
    MonRegisterStructureOffsets(_In_ const MON_STRUCTURE_OFFSETS *Offsets);

/**
 * @function   MonOffsetResolverSetDegraded
 * @purpose    Force resolver into degraded mode (disables dynamic resolution)
 * @precondition IRQL == PASSIVE_LEVEL
 * @postcondition Resolver will only use embedded tables
 * @thread-safety Thread-safe
 * @side-effects Emits ETW event
 */
_IRQL_requires_(PASSIVE_LEVEL) VOID MonOffsetResolverSetDegraded(_In_ BOOLEAN Degraded);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _ZIX_LABS_OFFSET_RESOLVER_H_ */
