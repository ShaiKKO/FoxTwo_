# ziX Labs C Coding Style Guide
## Version 1.0 | Kernel-Mode Driver Development

Based on CERT C Secure Coding Standard with security-critical emphasis for Windows I/O Ring introspection utilities.

---

## 1. Philosophy

Our code prioritizes **security first, then elegance, then performance**. Every decision follows this hierarchy:
- No untrusted pointer dereference without validation
- Code must be immediately understandable to security reviewers
- Optimize only when profiling confirms the bottleneck

We are writing **security-critical introspection utilities** for Windows kernel mode. Assume all inputs are hostile until proven safe.

---

## 2. File Organization

### Header Files

```c
/*
 * Author: [Your Name]
 * Organization: ziX Labs
 * File: [module_name].h
 * Version: [X.X]
 * Date: [YYYY-MM-DD]
 *
 * [One-line purpose]
 *
 * [Detailed rationale explaining security properties and threat model]
 *
 * SECURITY PROPERTIES:
 * - Input: All pointers treated as hostile until validated
 * - Output: No kernel pointers disclosed across trust boundaries
 * - Memory Safety: SEH guards all dereferences
 * - IRQL: [Required IRQL level]
 *
 * Preconditions / Requirements:
 * - [List all assumptions]
 * - [Compiler/platform requirements]
 * - [Memory model requirements]
 */

#ifndef ZIX_LABS_[MODULE_NAME]_H_
#define ZIX_LABS_[MODULE_NAME]_H_

#include <ntdef.h>
// ... other includes

/*
 * Section Comment Block
 * =====================
 * Use this pattern for major sections
 */

// Forward declarations before struct definitions

typedef struct _MY_STRUCT {
    // fields with inline comments for non-obvious purposes
    PVOID Pointer;      // Untrusted; validate before dereference
    SIZE_T ValidatedLength;  // Cross-validated against MDL
} MY_STRUCT, *PMY_STRUCT;

/*
 * Function Declarations with Complete Documentation
 */

/**
 * @function   Iop_ValidatePointer
 * @purpose    Validates kernel pointer address space and optionally deferences it
 * @precondition IRQL <= DISPATCH_LEVEL; Address may be in any pool type
 * @postcondition Returns TRUE only if pointer is valid and safe to dereference
 * @param[in]  Pointer - Untrusted pointer to validate
 * @param[in]  Size - Expected size of structure at pointer
 * @param[out] SafeSnapshot - Output structure (optional; NULL allowed)
 * @returns    TRUE if validation succeeded; FALSE otherwise
 * @thread-safety Exception-guarded; idempotent
 * @side-effects None (read-only operation)
 */
BOOLEAN
Iop_ValidatePointer(
    _In_ PVOID Pointer,
    _In_ SIZE_T Size,
    _Out_opt_ PVOID SafeSnapshot
);

#endif // ZIX_LABS_[MODULE_NAME]_H_
```

### Include Guards

Use PROJECT_PATH_FILENAME format in ALL CAPS:

```c
#ifndef ZIX_LABS_IOP_MC_H_
#define ZIX_LABS_IOP_MC_H_
// ... content
#endif // ZIX_LABS_IOP_MC_H_
```

---

## 3. Naming Conventions

### Constants and Macros

```c
// Constants in UPPER_CASE
#define ZIX_MAX_BUFFER_SIZE (4096)
#define ZIX_MAGIC_COOKIE    (0xDEADBEEF)

// Prefix with module name: ZIX_
// Suffix with _MAX, _MIN, _SIZE, _COUNT when appropriate
#define ZIX_IOP_MAX_VALIDATION_FLAGS (16)
```

### Types

```c
// Use _t suffix for primitive-based types
typedef ULONG   zix_status_t;

// Use STRUCT format for complex types, with leading underscore + uppercase
typedef struct _ZIX_BUFFER_ENTRY {
    PVOID Buffer;
    SIZE_T Size;
} ZIX_BUFFER_ENTRY, *PZIX_BUFFER_ENTRY;

// Pointer types mirror struct naming
// Good: struct _FOO -> FOO, *PFOO
// Bad: FOOPTR, FOOPT
```

### Functions

```c
// Function naming: Prefix + Verb + Noun + OptionalQualifier
// Prefix: Iop (I/O Ring), Mc (Memory Context), Etc.
// Verb: Validate, Query, Create, Destroy, Get, Set
// Noun: BufferEntry, MdlList, Pointer, etc.

// Public functions (exported from module):
NTSTATUS
Iop_ValidateMcBufferEntry(
    _In_ PVOID Entry
);

// Private/static functions use lowercase prefix + underscore:
static BOOLEAN
_Iop_IsAddressValid(
    _In_ PVOID Address
);
```

### Variables

```c
// Local variables: lowercase_with_underscores
// Global variables: g_ZixModuleName_VariableName (rare; avoid globals)
// Parameters: UpperCase (Windows convention for function parameters)

static ULONG g_Iop_ValidationFlags = 0;

NTSTATUS
Iop_ProcessEntry(
    _In_ PVOID Entry,       // UpperCase for parameters
    _In_ SIZE_T EntrySize
)
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN is_valid = FALSE;
    // ...
}
```

---

## 4. Formatting and Layout

### Indentation

- **Use spaces only; 4 spaces per indent level** (enforced by clang-format)
- Tabs allowed ONLY in Makefiles/build scripts
- Configure your editor: `.editorconfig`:

```ini
[*.{c,h}]
indent_style = space
indent_size = 4
end_of_line = crlf
insert_final_newline = true
trim_trailing_whitespace = true
```

### Brace Placement

Use **Linux Kernel Style** (opening brace on same line for control structures):

```c
// CORRECT - Linux/Kernel style
if (condition) {
    DoSomething();
    DoSomethingElse();
}

// CORRECT - Function definition brace on next line
NTSTATUS
Iop_MyFunction(VOID)
{
    return STATUS_SUCCESS;
}

// WRONG - Opening brace on next line for if
if (condition)
{
    DoSomething();
}
```

### Line Length

- **Maximum 100 characters** for readability
- Break long lines at logical operators or after commas
- Align continuation lines for clarity

```c
// CORRECT - Long line broken at logical operator
if (pointer_is_valid && address_is_in_kernel_space && 
    size_exceeds_minimum) {
    ProcessEntry(pointer);
}

// CORRECT - Function call with many arguments
status = Iop_ValidateMcBufferEntryEx(
    Entry,
    TRUE,  // StrictMode
    IOP_VALIDATION_FLAG_CHECK_MDL | IOP_VALIDATION_FLAG_CHECK_BOUNDS,
    &ViolationCode
);
```

### Spacing

```c
// No space after keywords
if (x == y) { ... }      // CORRECT
if(x == y) { ... }       // WRONG

// Spaces around binary operators
result = a + b;          // CORRECT
result = a+b;            // WRONG

// No space before semicolon
status = DoSomething();  // CORRECT
status = DoSomething() ; // WRONG

// Space after comma in parameter lists
func(a, b, c);           // CORRECT
func(a,b,c);             // WRONG

// Function pointers: no space before asterisk
typedef NTSTATUS (*Callback_t)(PVOID);  // CORRECT
typedef NTSTATUS (*Callback_t )(PVOID); // WRONG
```

---

## 5. Security Guidelines (CERT C Focused)

### Input Validation

**Every external input is hostile by default:**

```c
/**
 * All inputs from user-mode, kernel pointers, or MDLs require validation
 */

// BAD - Direct dereference without validation
PVOID user_pointer = (PVOID)ioctl_input;
ULONG value = *(PULONG)user_pointer;  // CRASH if invalid!

// GOOD - Validate first, capture second
__try {
    // Validate address range
    if (!Iop_IsAddressValidKernelMode(UserPointer)) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Probe memory
    ProbeForRead(UserPointer, sizeof(ULONG), sizeof(ULONG));
    
    // Safe capture
    ULONG captured_value = *(PULONG)UserPointer;
    
    // Proceed with validated data
} __except (EXCEPTION_EXECUTE_HANDLER) {
    return STATUS_ACCESS_VIOLATION;
}
```

### Exception Handling (SEH)

Use Structured Exception Handling for all risky operations:

```c
// CORRECT - SEH wraps risky operations
__try {
    // All dereferences must be guarded
    PVOID snapshot = MmGetSystemAddressForMdlSafe(mdl, HighPagePriority);
    if (snapshot == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Dereference inside try block
    value = *(PULONG)snapshot;
} __except (EXCEPTION_EXECUTE_HANDLER) {
    // Log violation
    IOP_MC_LOG_ERROR("Exception during dereference: 0x%x", GetExceptionCode());
    return STATUS_INVALID_PARAMETER;
}
```

### SAL Annotations & Tooling Compatibility

- Use SAL consistently on all public and cross-module prototypes. Prefer `_Use_decl_annotations_` and annotate each parameter with `_In_`, `_Out_`, `_Inout_`, and buffer-size contracts (e.g., `_Out_writes_bytes_(n)`).
- Keep SAL and header guards deterministic to avoid environment-specific failures.
- Cppcheck note: SAL macros are not understood by default. Maintain a local suppressions list to avoid false positives:

```text
unknownMacro:_In_
unknownMacro:_Out_*
unknownMacro:_Inout_*
unknownMacro:_IRQL_requires_max_*
```

Example invocation:

```powershell
& "C:\\Program Files\\Cppcheck\\cppcheck.exe" --enable=warning,performance,portability --inconclusive --language=c --suppressions-list=cppcheck-suppressions.txt .
```

### IRQL & Concurrency Tags

- Always document IRQL requirements using both SAL and comment tags.
- Map SAL to documentation explicitly:
  - `_IRQL_requires_max_(DISPATCH_LEVEL)` → `@precondition IRQL <= DISPATCH_LEVEL`
  - `_IRQL_requires_max_(APC_LEVEL)` → `@precondition IRQL <= APC_LEVEL`
- Use `@thread-safety` to state reentrancy, locking, and interlocked semantics.

### SEH Scoping Pattern (Kernel)

- Keep `__try/__except` blocks as narrow as possible—wrap only the specific risky dereferences or MDL traversals.
- On exception: log once at ERROR level and return a precise NTSTATUS (`STATUS_ACCESS_VIOLATION` or mapped code). Do not swallow logic errors.

### Kernel Logging Levels

- Define and use consistent severities. Debug-only logging should be compiled out in retail builds.

```c
#if DBG
#define LOG_ERROR(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, __VA_ARGS__)
#define LOG_WARN(fmt,  ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, fmt, __VA_ARGS__)
#define LOG_INFO(fmt,  ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, fmt, __VA_ARGS__)
#else
#define LOG_ERROR(...) do { __pragma(warning(suppress:4127)) } while(0)
#define LOG_WARN(...)  do { __pragma(warning(suppress:4127)) } while(0)
#define LOG_INFO(...)  do { __pragma(warning(suppress:4127)) } while(0)
#endif
```

### Pointer Arithmetic Restrictions

Avoid raw pointer arithmetic; use typed accessors:

```c
// BAD - Raw pointer arithmetic (error-prone)
ULONG offset = sizeof(HEADER) + (index * sizeof(ENTRY));
PENTRY entry = (PENTRY)((PUCHAR)buffer + offset);

// GOOD - Bounds-checked accessor functions
BOOLEAN
_Iop_GetBufferEntry(
    _In_ PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _In_ ULONG Index,
    _Out_ PENTRY Entry
)
{
    // Bounds check first
    SIZE_T required_size = sizeof(HEADER) + ((Index + 1) * sizeof(ENTRY));
    if (required_size > BufferSize) {
        return FALSE;  // Out of bounds
    }
    
    // Safe offset calculation
    PHEADER header = (PHEADER)Buffer;
    PENTRY entry = &header->Entries[Index];
    
    __try {
        *Entry = *entry;  // Capture
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}
```

### Avoid Dynamic Memory Allocation

Your code should never call `ExAllocatePoolWithTag()` in hot paths. Stack-based or pre-allocated memory only:

```c
// GOOD - Stack allocation for temporary data
UCHAR snapshot_buffer[sizeof(IOP_MC_BUFFER_ENTRY)];

// GOOD - Pre-allocated from DriverEntry
static PVOID g_validation_workspace = NULL;  // Allocated once at startup

// BAD - Runtime allocation in validation path
PVOID temp = ExAllocatePoolWithTag(NonPagedPool, size, 'tag');
```

---

## 6. Function Requirements

### Function Length

- **Maximum 60 lines per function** (including comments and blank lines)
- If exceeding 60 lines, split into smaller functions
- Exception: Large switch statements or initialization may be longer

### Function Parameters

- **Maximum 6 parameters** (use structures for more)
- Use `_In_`, `_Out_`, `_Inout_` SAL annotations on all parameters
- Document each parameter in the function's header comment

```c
/**
 * @function   Iop_ProcessRequest
 * @param[in]  Request - Caller-provided request structure
 * @param[in]  RequestSize - Size of Request buffer
 * @param[out] Response - Output response (caller-allocated)
 * @param[in]  MaxResponseSize - Max bytes for Response
 * @param[out] ResponseSize - Actual bytes written to Response
 * @param[in]  Flags - Processing flags (see IOP_PROCESS_*)
 */
NTSTATUS
Iop_ProcessRequest(
    _In_ PVOID Request,
    _In_ SIZE_T RequestSize,
    _Out_writes_bytes_(*ResponseSize) PVOID Response,
    _In_ SIZE_T MaxResponseSize,
    _Out_ PSIZE_T ResponseSize,
    _In_ ULONG Flags
);
```

### Return Values

All functions must document return values:

```c
/**
 * @returns    STATUS_SUCCESS if validation passed
 *             STATUS_INVALID_PARAMETER if pointer invalid
 *             STATUS_ACCESS_VIOLATION if address not accessible
 */
NTSTATUS
Iop_Validate(...);
```

---

## 7. Comments and Documentation

### When to Comment

- **Security-critical logic**: Why we chose this approach
- **Non-obvious intent**: Algorithm explanation
- **Assumptions**: Dependencies on callers or environment
- **Workarounds**: Why we can't use the obvious approach

### When NOT to Comment

- Self-documenting code (obvious from reading)
- Redundant paraphrasing of code
- Comments that lie or become stale

### Comment Format

```c
// Single-line comments for brief explanations
if (size_is_suspiciously_large) {
    // Reject sizes > 1MB as likely attack vectors
    return STATUS_INVALID_PARAMETER;
}

/*
 * Multi-line comments for detailed explanations
 * Explain the "why", not the "what"
 * Reference specifications or security concerns
 */
for (index = 0; index < entry_count; index++) {
    // Process each entry...
}

/**
 * @function   Name
 * @purpose    What it does
 * @security   Security implications if non-obvious
 * @reference  RFC/Spec reference if applicable
 */
```

---

## 8. Logging and Debugging

### Logging Levels

```c
// ERROR: Security violations or unrecoverable failures
IOP_MC_LOG_ERROR("Invalid pointer: 0x%p (violation code: 0x%x)", 
                 Pointer, ViolationCode);

// WARN: Lenient-mode acceptances of questionable inputs
IOP_MC_LOG_WARN("Lenient mode: accepting input despite flag mismatch");

// INFO: Diagnostic information (disabled in release builds)
IOP_MC_LOG_INFO("Validated entry at 0x%p, length %zu bytes", 
                Entry, EntryLength);
```

### Log Message Format

```c
// GOOD - Specific, quantitative
IOP_MC_LOG_ERROR("Validation failed: MDL byte count (0x%x) exceeds entry length (0x%x)",
                 MdlByteCount, EntryLength);

// BAD - Vague
IOP_MC_LOG_ERROR("Something went wrong");
```

---

## 9. Assertion and Contract Enforcement

### Use C_ASSERT for Compile-Time Verification

```c
// Catch structure layout issues at compile time
C_ASSERT(sizeof(IOP_MC_BUFFER_ENTRY) == 0x50);
C_ASSERT(FIELD_OFFSET(IOP_MC_BUFFER_ENTRY, Flags) == 0x0C);
```

### Use Runtime Assertions for Preconditions

```c
// Verify assumptions at runtime (debug builds)
ASSERT(Entry != NULL);
ASSERT(EntrySize >= sizeof(IOP_MC_BUFFER_ENTRY));
```

---

## 10. Automated Enforcement

### Use clang-format

Place `.clang-format` in project root:

```yaml
Language: C
Standard: c11
BasedOnStyle: LLVM
IndentWidth: 4
UseTab: Never
TabWidth: 4
ColumnLimit: 100
BreakBeforeBraces: Linux
AlwaysBreakAfterReturnType: TopLevel
AllowShortFunctionsOnASingleLine: None
AlignTrailingComments: true
SortIncludes: true
```

Run before commit:
```bash
clang-format -i src/*.c src/*.h
```

### Use cppcheck

```bash
cppcheck --enable=all --std=c11 src/
```

### Pre-Commit Hook

Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash
set -e

# Format check
echo "Checking formatting..."
clang-format --dry-run -Werror src/*.c src/*.h || {
    echo "Run: clang-format -i src/*.c src/*.h"
    exit 1
}

# CERT C static analysis
echo "Running static analysis..."
cppcheck --enable=all --std=c11 src/ || exit 1

echo "All checks passed!"
exit 0
```

Make executable: `chmod +x .git/hooks/pre-commit`

---

## 11. Security Review Checklist

Before committing, verify:

- [ ] All external inputs validated before use
- [ ] All dereferences guarded by SEH `__try/__except`
- [ ] No dynamic memory allocation in hot paths
- [ ] MDL operations cross-validated
- [ ] Function under 60 lines
- [ ] No recursion
- [ ] All parameters documented with SAL annotations
- [ ] Return values and error conditions documented
- [ ] clang-format compliant
- [ ] cppcheck passes with no warnings
- [ ] Security implications explained in comments

---

## 12. Examples

### Good Example: Validated Buffer Query

```c
/**
 * Safely retrieves buffer entry metadata after rigorous validation.
 * All inputs treated as hostile until proven safe.
 * 
 * @precondition IRQL <= DISPATCH_LEVEL
 * @postcondition Returns TRUE and populates Result only if entry is valid
 */
BOOLEAN
Iop_QueryMcBufferEntryMetadata(
    _In_ PVOID EntryPointer,
    _In_ SIZE_T EntrySize,
    _Out_ PIOP_ENTRY_METADATA Result
)
{
    // Validate inputs
    if (EntryPointer == NULL || EntrySize == 0 || Result == NULL) {
        IOP_MC_LOG_ERROR("NULL parameter: pointer=0x%p, size=%zu, result=0x%p",
                        EntryPointer, EntrySize, Result);
        return FALSE;
    }

    if (EntrySize < sizeof(IOP_MC_BUFFER_ENTRY)) {
        IOP_MC_LOG_ERROR("Buffer too small: %zu < %zu",
                        EntrySize, sizeof(IOP_MC_BUFFER_ENTRY));
        return FALSE;
    }

    // SEH guards all dereferences
    __try {
        // Probe memory before access
        ProbeForRead(EntryPointer, EntrySize, sizeof(ULONG));

        // Capture structure snapshot
        IOP_MC_BUFFER_ENTRY snapshot;
        RtlCopyMemory(&snapshot, EntryPointer, sizeof(snapshot));

        // Validate captured data
        if (snapshot.Magic != IOP_MAGIC_COOKIE) {
            IOP_MC_LOG_WARN("Invalid magic: 0x%x (expected 0x%x)",
                           snapshot.Magic, IOP_MAGIC_COOKIE);
            return FALSE;
        }

        // Cross-validate length fields
        if (snapshot.ByteCount > MAXIMUM_ALLOWED_SIZE) {
            IOP_MC_LOG_ERROR("Size overflow: 0x%x > 0x%x",
                           snapshot.ByteCount, MAXIMUM_ALLOWED_SIZE);
            return FALSE;
        }

        // Populate output
        Result->EntrySize = snapshot.ByteCount;
        Result->Flags = snapshot.Flags;
        Result->HasMdl = (snapshot.MdlPointer != NULL);

        return TRUE;

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        IOP_MC_LOG_ERROR("Exception during validation: 0x%lx",
                        GetExceptionCode());
        return FALSE;
    }
}
```

---

## 13. References

- **CERT C Secure Coding Standard**: https://www.sei.cmu.edu/cert-coding-standard/
- **Linux Kernel Coding Style**: https://www.kernel.org/doc/html/latest/process/coding-style.html
- **Windows WDK Documentation**: https://docs.microsoft.com/en-us/windows-hardware/drivers/
- **SEH (Structured Exception Handling)**: https://docs.microsoft.com/en-us/cpp/cpp/structured-exception-handling-c-cpp
- **SAL Annotations**: https://docs.microsoft.com/en-us/cpp/code-quality/understanding-sal

---

**Last Updated**: November 19, 2025
**Owner**: ziX Labs Security Engineering
**Status**: v1.0 - Ready for Team Adoption
