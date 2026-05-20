---
layout: post
title: "PEB Internals: What the Process Environment Block Reveals and Why Defenders Care"
date: 2026-05-15
tags: [windows, internals, defense, malware-analysis, low-level]
---

Every process on Windows has a Process Environment Block (PEB). Most developers never interact with it directly - the Win32 API abstracts everything away. But if you're doing malware analysis, EDR engineering, or any kind of defensive work, the PEB comes up constantly.

---

## 1. What Is the PEB?

The PEB is a user-mode structure that the Windows kernel creates for every process. It lives in the process's own address space, readable from user mode without any system calls. This is by design - many common operations (checking if the debugger is attached, enumerating loaded modules, reading environment variables) need this data without the overhead of a syscall.

The PEB is accessible through the TEB (Thread Environment Block), which itself is pointed to by the `GS` segment register on x64:

```c
// x64: TEB is at GS:[0x30], PEB is at TEB+0x60
PEB* peb = (PEB*)__readgsqword(0x60);
```

On x86:

```c
// x86: TEB is at FS:[0x18], PEB is at TEB+0x30
PEB* peb = (PEB*)__readfsdword(0x30);
```

### Why This Matters for Defense

Because the PEB is in user-mode memory, any code running in the process can read *and modify* it. This is both a feature and a security concern. Legitimate code reads the PEB for process information. Malware modifies the PEB to hide its tracks.

---

## 2. Key PEB Fields

The PEB is large and version-dependent. These are the fields that matter most for security analysis:

### `BeingDebugged` (offset 0x02)

A single byte. Set to 1 when a debugger is attached via `DebugActiveProcess` or when the process is started under a debugger.

```c
if (peb->BeingDebugged) {
    // debugger is attached
}
```

This is equivalent to calling `IsDebuggerPresent()`, which literally just reads this byte. Malware commonly checks this field and alters its behavior. Anti-analysis code typically modifies this field to 0 to hide the debugger.

If your EDR sees a process where `BeingDebugged` is 0 but debug events are active on the process, something is manipulating the PEB.

### `Ldr` (offset 0x18) - PEB_LDR_DATA

Pointer to the loader data structure, which contains three linked lists of loaded modules:

- `InLoadOrderModuleList` - modules in load order
- `InMemoryOrderModuleList` - modules in memory address order
- `InInitializationOrderModuleList` - modules in initialization order

Each entry is an `LDR_DATA_TABLE_ENTRY` containing:

```c
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;               // base address of the module
    PVOID EntryPoint;            // entry point
    ULONG SizeOfImage;           // size in memory
    UNICODE_STRING FullDllName;  // full path
    UNICODE_STRING BaseDllName;  // just the filename
    // ... more fields
} LDR_DATA_TABLE_ENTRY;
```

Walking these lists is how tools like Process Explorer enumerate loaded DLLs. But malware can unlink entries from these lists to hide injected DLLs. The module is still loaded in memory, but PEB-based enumeration won't find it.

### `ProcessParameters` (offset 0x20) - RTL_USER_PROCESS_PARAMETERS

Contains the command line, current directory, environment variables, image path, and window information:

```c
RTL_USER_PROCESS_PARAMETERS* params = peb->ProcessParameters;
// params->CommandLine      - full command line
// params->ImagePathName    - path to the executable
// params->Environment      - environment variable block
// params->CurrentDirectory - working directory
```

Malware can modify `ImagePathName` to make the process appear to be running from a different location. Comparing PEB `ImagePathName` with the actual executable path (from kernel structures) reveals this tampering.

### `NtGlobalFlag` (offset 0x68 on x86, 0xBC on x64)

Debug-related flags set by the OS. When a debugger creates a process, certain flags are set:

- `FLG_HEAP_ENABLE_TAIL_CHECK` (0x10)
- `FLG_HEAP_ENABLE_FREE_CHECK` (0x20)
- `FLG_HEAP_VALIDATE_PARAMETERS` (0x40)

Combined value when debugging: `0x70`.

Malware checks this: if `NtGlobalFlag` contains `0x70`, a debugger likely started the process. This is a more subtle check than `BeingDebugged` and is missed by naive anti-anti-debug tools.

---

## 3. PEB-Based Module Enumeration

Walking the PEB loader lists is the standard way to enumerate modules from user mode without calling `EnumProcessModules` or `CreateToolhelp32Snapshot` - API calls that security tools monitor.

### The Walk

```c
PEB* peb = get_peb();
PEB_LDR_DATA* ldr = peb->Ldr;
LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
LIST_ENTRY* current = head->Flink;

while (current != head) {
    LDR_DATA_TABLE_ENTRY* entry =
        CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

    // entry->BaseDllName.Buffer - module name
    // entry->DllBase            - base address
    // entry->SizeOfImage        - size

    current = current->Flink;
}
```

### Why Malware Does This

Calling `GetModuleHandle` or `LoadLibrary` goes through the Windows API, which EDR products hook. PEB walking achieves the same result (finding a module base address) without touching any hooked functions.

This is a common pattern in malware:

1. Walk PEB to find `kernel32.dll` base address
2. Parse its export table to find `GetProcAddress`
3. Use `GetProcAddress` to resolve everything else

No API calls that an EDR can intercept in the traditional sense.

### How to Catch It

Even if malware avoids API hooks, ETW providers at the kernel level still see module loads. Comparing ETW module load events with PEB module lists reveals unlinking.

You can also scan process memory for PE headers (`MZ` / `PE` signatures) and compare against the PEB module list. If there's a PE header in memory that doesn't appear in the loader lists, something was unlinked.

Periodically comparing PEB module lists against kernel-side structures (`EPROCESS.VadRoot`, kernel module lists) works too. The kernel still tracks the memory regions even after PEB unlinking.

---

## 4. PEB Manipulation Techniques and Detection

### Module Unlinking

The most common PEB manipulation: removing a `LDR_DATA_TABLE_ENTRY` from the three loader lists. After unlinking, the module is still loaded and functional, but will not appear when enumerating modules via the PEB.

```c
void unlink_module(LDR_DATA_TABLE_ENTRY* entry) {
    entry->InLoadOrderLinks.Blink->Flink = entry->InLoadOrderLinks.Flink;
    entry->InLoadOrderLinks.Flink->Blink = entry->InLoadOrderLinks.Blink;
    // ... same for the other two lists
}
```

To catch this, compare the PEB module list against:
- VAD (Virtual Address Descriptor) tree from kernel mode - memory regions are still tracked
- PE header scanning in the process address space
- ETW module load events (the load was logged before unlinking happened)

### ImagePathName Spoofing

Overwriting `ProcessParameters->ImagePathName` to a different path. Some security tools trust this field to identify what binary is running.

Compare with `EPROCESS.ImageFileName` in kernel mode, or with the `QueryFullProcessImageName` result, which reads from kernel structures.

### BeingDebugged / NtGlobalFlag Clearing

Malware zeroes these fields to evade anti-debug checks by analysis tools or its own anti-analysis routines.

From a debugger, compare expected debug state with PEB values. Tools like ScyllaHide do the reverse (clear these fields to help analysts), which is useful during malware analysis.

### CommandLine Modification

Overwriting `ProcessParameters->CommandLine` after process creation. Process creation events capture the original command line, but tools querying the PEB later see the modified version.

Process creation events (Sysmon Event ID 1, ETW) capture the original command line. Comparing with the PEB reveals tampering.

---

## 5. PEB and the Heap

The PEB contains pointers to process heaps:

```c
PVOID  ProcessHeap;              // default process heap
ULONG  NumberOfHeaps;            // total heap count
ULONG  MaximumNumberOfHeaps;     // maximum heap count
PVOID* ProcessHeaps;             // array of heap pointers
```

### Heap-Based Debug Detection

The process heap (from `GetProcessHeap()` or `PEB->ProcessHeap`) has debug-specific flags when a debugger creates the process:

- `Heap->Flags` should be `HEAP_GROWABLE` (0x02) normally
- Under a debugger: additional flags like `HEAP_TAIL_CHECKING_ENABLED`, `HEAP_FREE_CHECKING_ENABLED`
- `Heap->ForceFlags` should be 0 normally, non-zero under debugger

This is a more reliable anti-debug check than `BeingDebugged` because many anti-anti-debug tools forget to patch heap flags.

This one has bitten me during analysis. You patch `BeingDebugged` thinking you're clean, and the malware still detects you because you forgot about the heap flags. A lot of anti-anti-debug tools miss this.

---

## 6. PEB Across Windows Versions

The PEB grows with each Windows version. Microsoft adds fields but does not remove them, maintaining backward compatibility. Key additions over time:

- **Windows Vista:** Added `AppCompatFlags`, `AppCompatFlagsUser`
- **Windows 8:** Added `AppModelPolicy`
- **Windows 10:** Added `LeapSecondData`, `ActiveCodePage`
- **Windows 11:** Various additions for security mitigations

### Practical Implication

When writing tools that read the PEB, always verify the Windows version and use the correct structure layout. Using the wrong offsets causes silent reads of wrong fields. I've seen tools read garbage for months because of this.

The best approach: use `NtQueryInformationProcess(ProcessBasicInformation)` to get the PEB address, then read fields at known offsets rather than relying on a compiled structure definition that might not match the running OS version.

---

## 7. Defensive Tooling Using PEB Analysis

### Integrity Monitoring

A lightweight detection approach: periodically snapshot PEB state and compare:

1. Module list: any entries added or removed since last check?
2. `ImagePathName`: still matches the real binary path?
3. `BeingDebugged` / `NtGlobalFlag`: consistent with actual debug state?
4. `CommandLine`: matches process creation event?

Changes to any of these fields outside of expected operations are strong indicators of compromise or tampering.

### EDR Integration

Modern EDRs combine PEB inspection with other telemetry:

- PEB module list + VAD scan + ETW events = comprehensive module visibility
- PEB `CommandLine` + Sysmon creation event = tamper detection
- PEB heap analysis + debug state = environment fingerprinting detection

### Forensic Analysis

During incident response, dumping the PEB provides immediate context:

- What modules are loaded (and what's hiding)?
- What was the real command line?
- Is the process environment modified?
- Are there signs of debugger evasion?

Tools like Volatility can extract PEB data from memory dumps, making this analysis possible even on dead systems.

---

## Conclusion

The PEB is small but it comes up everywhere. Attackers read it to avoid API hooks. They modify it to hide their presence. Defenders read it to catch that modification.

The big points: the PEB is user-mode writable, so always assume it can be tampered with. Module enumeration via PEB is a malware staple because it avoids hooked APIs. Defensive detection works by comparing PEB state against kernel-side ground truth. And debug detection through PEB goes well beyond `IsDebuggerPresent` - heap flags and `NtGlobalFlag` catch a lot of analysts off guard.

Every detection rule for PEB tampering starts with knowing how the tampering actually works.
