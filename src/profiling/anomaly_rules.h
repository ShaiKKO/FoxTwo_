/*
 * Anomaly Rules Engine - Public Header
 *
 * Author: Colin MacRitchie | ziX Labs
 * Organization: ziX Labs - Security Research Division
 * File: anomaly_rules.h
 * Version: 1.0
 * Date: 2025-11-30
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved. Proprietary and
 * confidential. Redistribution or disclosure without prior written consent is
 * prohibited.
 *
 * Summary
 * -------
 * Extensible rule evaluation engine for process behavior anomaly detection.
 * Provides rule management, threshold configuration, and evaluation APIs.
 *
 * SECURITY PROPERTIES:
 * - Input: All rule parameters validated
 * - Output: No kernel pointers disclosed
 * - Thread Safety: FAST_MUTEX for modifications; lock-free evaluation
 *
 * Architecture:
 * - Built-in rules with default thresholds
 * - Custom rule registration
 * - Per-rule enable/disable
 * - MITRE ATT&CK technique mapping
 */

#ifndef _ZIX_LABS_ANOMALY_RULES_H_
#define _ZIX_LABS_ANOMALY_RULES_H_

#ifndef _KERNEL_MODE
#error "This header is for kernel-mode only."
#endif

#include <ntddk.h>

#include "process_profile.h"

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------
 * Configuration Constants
 *-------------------------------------------------------------------------*/
#define MON_ANOMALY_MAX_RULES   32 /* Maximum simultaneous rules */
#define MON_ANOMALY_MAX_RESULTS 16 /* Max results per evaluation */

/*--------------------------------------------------------------------------
 * Extended Anomaly Rule Structure (with score impact)
 *
 * Extends MON_ANOMALY_RULE from process_profile.h with evaluation details.
 *-------------------------------------------------------------------------*/

/* Use MON_ANOMALY_RULE from process_profile.h, but add ScoreImpact field */
#ifndef MON_ANOMALY_RULE_EXTENDED
#define MON_ANOMALY_RULE_EXTENDED

/* Re-define with ScoreImpact for internal use */
typedef struct _MON_ANOMALY_RULE {
  MON_ANOMALY_RULE_ID RuleId;
  WCHAR RuleName[32];
  ULONG Threshold;     /* Rule-specific threshold */
  ULONG WindowSeconds; /* Evaluation window */
  MON_ANOMALY_SEVERITY Severity;
  ULONG ScoreImpact; /* Anomaly score increase */
  BOOLEAN Enabled;
  BOOLEAN Reserved[3];
  CHAR MitreTechnique[16]; /* e.g., "T1055" */
} MON_ANOMALY_RULE, *PMON_ANOMALY_RULE;

#endif /* MON_ANOMALY_RULE_EXTENDED */

/*--------------------------------------------------------------------------
 * Anomaly Evaluation Result
 *-------------------------------------------------------------------------*/
typedef struct _MON_ANOMALY_RESULT {
  MON_ANOMALY_RULE_ID RuleId;
  ULONG Threshold;
  ULONG ActualValue;
  MON_ANOMALY_SEVERITY Severity;
  ULONG ScoreImpact;
} MON_ANOMALY_RESULT, *PMON_ANOMALY_RESULT;

C_ASSERT(sizeof(MON_ANOMALY_RESULT) == 20);

/*--------------------------------------------------------------------------
 * Anomaly Statistics
 *-------------------------------------------------------------------------*/
typedef struct _MON_ANOMALY_STATS {
  ULONG Size;
  ULONG TotalRules;
  ULONG EnabledRules;
  ULONG TotalEvaluations;
  ULONG TotalMatches;
  ULONG Reserved;
} MON_ANOMALY_STATS, *PMON_ANOMALY_STATS;

C_ASSERT(sizeof(MON_ANOMALY_STATS) == 24);

/*==========================================================================
 * Public API Function Prototypes
 *=========================================================================*/

/**
 * @function   MonAnomalyInitialize
 * @purpose    Initialize the anomaly rules engine
 * @precondition IRQL == PASSIVE_LEVEL; Called from DriverEntry
 * @postcondition Rules engine initialized with built-in rules
 * @returns    STATUS_SUCCESS on success
 * @thread-safety Single-threaded init
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS MonAnomalyInitialize(VOID);

/**
 * @function   MonAnomalyShutdown
 * @purpose    Shutdown the rules engine
 * @precondition IRQL == PASSIVE_LEVEL; Called from DriverUnload
 * @postcondition Engine unavailable
 * @thread-safety Single-threaded shutdown
 */
_IRQL_requires_(PASSIVE_LEVEL) VOID MonAnomalyShutdown(VOID);

/**
 * @function   MonAnomalyIsInitialized
 * @purpose    Check if rules engine is ready
 * @precondition IRQL <= DISPATCH_LEVEL
 * @returns    TRUE if initialized
 * @thread-safety Lock-free read
 */
_IRQL_requires_max_(DISPATCH_LEVEL) BOOLEAN MonAnomalyIsInitialized(VOID);

/**
 * @function   MonAnomalyEvaluate
 * @purpose    Evaluate all rules against a process profile
 * @precondition IRQL == PASSIVE_LEVEL
 *
 * @param[in]  Profile - Process profile to evaluate
 * @param[in]  OpsPerSecond - Current operations per second
 * @param[out] TriggeredRules - Bitmask of triggered rule IDs (optional)
 * @param[out] Results - Array of evaluation results (optional)
 * @param[in]  MaxResults - Capacity of Results array
 * @returns    Number of rules that matched
 *
 * @thread-safety Lock-free evaluation
 */
_IRQL_requires_(PASSIVE_LEVEL) ULONG
    MonAnomalyEvaluate(_In_ const MON_PROCESS_PROFILE *Profile, _In_ ULONG OpsPerSecond,
                       _Out_opt_ ULONG *TriggeredRules,
                       _Out_writes_opt_(MaxResults) MON_ANOMALY_RESULT *Results,
                       _In_ ULONG MaxResults);

/**
 * @function   MonAnomalyGetRule
 * @purpose    Get rule details by ID
 * @precondition IRQL == PASSIVE_LEVEL
 *
 * @param[in]  RuleId - Rule ID to retrieve
 * @param[out] Rule - Output buffer
 * @returns    STATUS_SUCCESS if found
 *             STATUS_NOT_FOUND if rule doesn't exist
 *
 * @thread-safety FAST_MUTEX protected
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS
    MonAnomalyGetRule(_In_ MON_ANOMALY_RULE_ID RuleId, _Out_ PMON_ANOMALY_RULE Rule);

/**
 * @function   MonAnomalySetThreshold
 * @purpose    Configure threshold for a rule
 * @precondition IRQL == PASSIVE_LEVEL
 *
 * @param[in]  RuleId - Rule to modify
 * @param[in]  Threshold - New threshold value
 * @returns    STATUS_SUCCESS on success
 *             STATUS_NOT_FOUND if rule doesn't exist
 *
 * @thread-safety FAST_MUTEX protected
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS
    MonAnomalySetThreshold(_In_ MON_ANOMALY_RULE_ID RuleId, _In_ ULONG Threshold);

/**
 * @function   MonAnomalyEnableRule
 * @purpose    Enable or disable a rule
 * @precondition IRQL == PASSIVE_LEVEL
 *
 * @param[in]  RuleId - Rule to modify
 * @param[in]  Enable - TRUE to enable, FALSE to disable
 * @returns    STATUS_SUCCESS on success
 *             STATUS_NOT_FOUND if rule doesn't exist
 *
 * @thread-safety FAST_MUTEX protected
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS
    MonAnomalyEnableRule(_In_ MON_ANOMALY_RULE_ID RuleId, _In_ BOOLEAN Enable);

/**
 * @function   MonAnomalyAddRule
 * @purpose    Register a custom anomaly rule
 * @precondition IRQL == PASSIVE_LEVEL
 *
 * @param[in]  NewRule - Rule to add
 * @returns    STATUS_SUCCESS if added
 *             STATUS_DUPLICATE_OBJECTID if RuleId exists
 *             STATUS_INSUFFICIENT_RESOURCES if at capacity
 *
 * @thread-safety FAST_MUTEX protected
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS MonAnomalyAddRule(_In_ const MON_ANOMALY_RULE *NewRule);

/**
 * @function   MonAnomalyEnumerateRules
 * @purpose    Enumerate all registered rules
 * @precondition IRQL == PASSIVE_LEVEL
 *
 * @param[out] Buffer - Array of rules
 * @param[in]  MaxCount - Buffer capacity
 * @param[out] ActualCount - Number of rules returned
 * @returns    STATUS_SUCCESS on success
 *
 * @thread-safety FAST_MUTEX protected
 */
_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS
    MonAnomalyEnumerateRules(_Out_writes_to_(MaxCount, *ActualCount) PMON_ANOMALY_RULE Buffer,
                             _In_ ULONG MaxCount, _Out_ ULONG *ActualCount);

/**
 * @function   MonAnomalyGetRuleCount
 * @purpose    Get total number of registered rules
 * @precondition IRQL <= DISPATCH_LEVEL
 * @returns    Number of rules
 * @thread-safety Lock-free read
 */
_IRQL_requires_max_(DISPATCH_LEVEL) ULONG MonAnomalyGetRuleCount(VOID);

/**
 * @function   MonAnomalyGetStats
 * @purpose    Get rules engine statistics
 * @precondition IRQL <= DISPATCH_LEVEL
 *
 * @param[out] Stats - Output buffer
 * @thread-safety Lock-free counter reads
 */
_IRQL_requires_max_(DISPATCH_LEVEL) VOID MonAnomalyGetStats(_Out_ PMON_ANOMALY_STATS Stats);

/**
 * @function   MonAnomalyResetStats
 * @purpose    Reset evaluation statistics
 * @precondition IRQL == PASSIVE_LEVEL
 * @thread-safety Interlocked operations
 */
_IRQL_requires_(PASSIVE_LEVEL) VOID MonAnomalyResetStats(VOID);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _ZIX_LABS_ANOMALY_RULES_H_ */
