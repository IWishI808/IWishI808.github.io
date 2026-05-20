---
layout: post
title: "CRT vs NoCRT: How the C Runtime Helps Defenders Catch Injected DLLs"
date: 2026-05-10
tags: [windows, detection, defense, malware-analysis, dll, crt]
---

When an attacker injects a DLL into a process, one of the first decisions they make - whether they realize it or not - is whether to link the C Runtime Library (CRT). That decision leaves distinct forensic traces that defenders can use to detect the injection.

---

## 1. What the CRT Actually Does

When you compile a DLL with Visual Studio using the default settings, the C Runtime Library is linked in. The CRT is not just `printf` and `malloc` - it's a significant initialization framework that runs before your code.

When a CRT-linked DLL is loaded, this happens before `DllMain` executes:

1. **Security cookie initialization** (`__security_init_cookie`) - generates a random stack canary value
2. **CRT heap initialization** - sets up the CRT's internal heap
3. **Thread-local storage initialization** - initializes TLS slots
4. **Atexit/onexit registration** - prepares cleanup handlers
5. **Floating-point initialization** - configures FPU state
6. **Global C++ constructor calls** - runs static object constructors (`_initterm`)

The actual entry point of a CRT-linked DLL is not `DllMain` - it is `_DllMainCRTStartup`, which does all of the above and then calls your `DllMain`.

### The Security Cookie

The security cookie (`/GS` flag, enabled by default) is the most visible CRT artifact. The function `__security_init_cookie` generates a random value at DLL load time and stores it in `__security_cookie`. Every function that uses stack buffers places this value on the stack and validates it before returning.

The initialization is easy to spot in a disassembler:

```
_DllMainCRTStartup:
    call    __security_init_cookie    ; ← distinctive CRT artifact
    jmp     dllmain_dispatch
```

This single call is one of the most reliable indicators that a DLL was compiled with the CRT.

---

## 2. CRT-Linked DLLs: What Defenders See

A DLL compiled with the CRT has a recognizable fingerprint. Here's what to look for.

### Import Table

CRT-linked DLLs import from CRT libraries. The specific imports depend on the linking mode:

**Dynamic CRT (`/MD`):**
- `vcruntime140.dll`
- `ucrtbase.dll` (or `api-ms-win-crt-*.dll` on newer Windows)
- Possibly `msvcp140.dll` for C++ standard library

**Static CRT (`/MT`):**
- No CRT DLL imports (everything is compiled into the binary)
- But the code patterns are still present in the `.text` section

### Entry Point Pattern

The entry point follows a predictable pattern:

```asm
; _DllMainCRTStartup
push    rbp
mov     rbp, rsp
sub     rsp, 0x20
call    __security_init_cookie
; ... CRT initialization ...
call    dllmain_dispatch
; ... CRT cleanup ...
```

The call to `__security_init_cookie` near the entry point is a strong CRT indicator. This function reads `RDTSC`, `GetCurrentProcessId`, `GetCurrentThreadId`, `GetSystemTimeAsFileTime`, and `QueryPerformanceCounter` to generate entropy for the cookie. Those API calls or their patterns are detectable.

### .rdata and .data Sections

CRT-linked DLLs contain specific global variables:

- `__security_cookie` - the canary value (in `.data` or `.rdata`)
- `_onexit_table` - atexit cleanup handlers
- `__acrt_iob_func` references for stdio
- CRT error messages as strings ("runtime error", "assertion failed")

### Section Layout

A typical CRT DLL has well-structured sections:

```
.text    - code (substantial, includes CRT runtime code)
.rdata   - read-only data, vtables, CRT strings
.data    - writable data, security cookie, global state
.pdata   - exception handling unwind data
.rsrc    - resources (optional)
.reloc   - relocation table
```

The `.pdata` section (exception unwind information) is almost always present in CRT DLLs because the CRT uses structured exception handling.

---

## 3. Why Attackers Avoid the CRT

Sophisticated attackers compile DLLs without the CRT for several reasons.

A minimal NoCRT DLL can be 4-8 KB. A CRT-linked DLL starts at 50-100 KB. Smaller files are easier to inject, less likely to trigger size-based heuristics, and faster to write into remote process memory.

The CRT also pulls in dozens of API imports, and each import is a potential detection point. A NoCRT DLL can operate with just a handful of functions from `ntdll.dll` or `kernel32.dll`.

CRT initialization calls multiple API functions that EDR products monitor. Skipping it means the DLL's entry point runs directly - less telemetry generated. The CRT also brings code the attacker doesn't need, with its own behavior (heap allocations, TLS operations, exception handlers) that creates noise.

And many detection rules are tuned to CRT-compiled binaries because that's what most software produces. A NoCRT binary doesn't match those patterns - which is itself a signal, as we'll see.

### How NoCRT DLLs Are Built

```c
// NoCRT entry point - no _DllMainCRTStartup wrapper
BOOL WINAPI _DllMainCRTStartup(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // attacker code runs directly here
    }
    return TRUE;
}
```

Compiled with:
- `/NODEFAULTLIB` - no CRT libraries
- `/ENTRY:_DllMainCRTStartup` - custom entry point
- `/GS-` - no security cookie (requires CRT)
- No `printf`, `malloc`, `new` - only direct Win32 or NT API calls

---

## 4. NoCRT DLLs: What Defenders See

The absence of CRT artifacts is just as distinctive as their presence.

### Missing Security Cookie

No `__security_init_cookie` call at the entry point. No `__security_cookie` global. No `__GSHandlerCheck` exception handlers. For a DLL that does anything non-trivial, this is unusual.

A DLL with a `.text` section larger than 4 KB but no security cookie initialization is suspicious. Legitimate developers almost never disable `/GS` because it's the default and has negligible performance cost.

### Minimal Import Table

A NoCRT DLL often imports only from `kernel32.dll` or `ntdll.dll`, with a handful of functions:

```
kernel32.dll:
    VirtualAlloc
    VirtualProtect
    CreateThread
    LoadLibraryA
    GetProcAddress
```

Or even more minimal, using only `ntdll.dll` native API:

```
ntdll.dll:
    NtAllocateVirtualMemory
    NtProtectVirtualMemory
    NtCreateThreadEx
    LdrLoadDll
```

A DLL that imports exclusively from `ntdll.dll` with no CRT imports is highly unusual for legitimate software. Most legitimate DLLs use the Win32 API layer.

### Tiny File Size

A NoCRT DLL doing real work can be 4-15 KB. Legitimate DLLs with business logic are almost always larger. The distribution of DLL sizes in a normal process is skewed toward larger files.

Flag unsigned DLLs under 20 KB loaded into processes where the typical module size is much larger.

### Flat Entry Point

NoCRT DLLs have a simple entry point that goes directly to attacker logic:

```asm
_DllMainCRTStartup:
    cmp     edx, 1          ; DLL_PROCESS_ATTACH
    jne     short return_true
    ; ... immediately does attacker work ...
return_true:
    mov     eax, 1
    ret
```

Compare this with a CRT entry point that has initialization calls, exception handling setup, and a structured dispatch to `DllMain`. The difference is visible in static analysis.

### Missing .pdata Section

NoCRT DLLs compiled without exception handling often lack a `.pdata` section entirely. On x64 Windows, the `.pdata` section contains unwind information for structured exception handling. Its absence means the DLL has no SEH support.

A x64 DLL without `.pdata` is unusual. Not definitive on its own, but combined with other NoCRT indicators it strengthens the signal.

---

## 5. The Signature Gap

This is the most straightforward detection opportunity.

Legitimate CRT-linked DLLs are almost always signed. Microsoft, Adobe, Google, game studios - every major software vendor signs their DLLs. The CRT itself (`vcruntime140.dll`, `ucrtbase.dll`) is Microsoft-signed.

An unsigned DLL that uses the CRT is suspicious because:
1. If the developer was professional enough to use the CRT (standard build process), they would typically also sign their binaries
2. Legitimate unsigned DLLs exist (open-source plugins, internal tools) but they are a small population
3. An injected DLL is, by definition, not part of the original application - it will not be signed by the application vendor

An unsigned DLL loaded into a process where all other DLLs are signed is a strong anomaly signal. If it also uses the CRT, it was compiled with standard tooling but not through a standard release process.

### Why CRT Makes Unsigned DLLs Easier to Catch

Here's the thing: `__security_init_cookie` calls **4 external functions** to gather entropy:

1. `GetSystemTimeAsFileTime`
2. `QueryPerformanceCounter`
3. `GetCurrentProcessId`
4. `GetCurrentThreadId`

Every one of these can be hooked by a security product. When the hook fires, the defender inspects the **return address** on the call stack. That return address points back into the calling module - the injected DLL. Walking the call stack reveals the full chain:

```
GetSystemTimeAsFileTime          ← hooked, EDR gets control
  ← __security_init_cookie       ← return address is inside injected DLL
    ← _DllMainCRTStartup         ← CRT entry point
      ← LdrpCallInitRoutine      ← ntdll loader
```

The return address lands in a memory region. The defender checks: does this region belong to a signed, known module? If the return address resolves to an unsigned image, or to memory that is not backed by any loaded image at all, it is a strong injection indicator.

This is not a problem for legitimate DLLs. A signed module from a known vendor calling these same functions during normal CRT initialization will pass the return address check - the address resolves cleanly to a signed image with a valid certificate chain. The detection specifically targets the gap between "uses standard CRT tooling" and "did not go through a standard signing and distribution process."

Beyond the security cookie, the CRT generates additional telemetry:

- CRT heap initialization calls `HeapCreate` or `RtlCreateHeap` - same return address analysis applies
- TLS callbacks are registered and executed - monitored by ETW
- If dynamic CRT (`/MD`), loading the DLL triggers loads of `vcruntime140.dll` and `ucrtbase.dll` - module load events that EDR monitors

An attacker using a NoCRT DLL avoids all of these hook trigger points - but as covered in section 4, the *absence* of these patterns is also detectable through structural analysis.

---

## 6. Building a Detection Matrix

Combining these signals into a scoring system:

| Signal | CRT DLL (suspicious) | NoCRT DLL (suspicious) | Weight |
|--------|---------------------|----------------------|--------|
| Unsigned | Strong indicator | Strong indicator | High |
| No security cookie | N/A | Present | Medium |
| Minimal imports | Unlikely | Likely | Medium |
| Small file size (<20 KB) | Unlikely | Likely | Medium |
| No `.pdata` section | Unlikely | Likely | Low |
| ntdll-only imports | Very unlikely | Possible | High |
| Not in application manifest | Strong indicator | Strong indicator | High |
| Loaded after process init | Moderate indicator | Moderate indicator | Medium |
| No version info resource | Moderate indicator | Likely | Low |

### Detection Algorithm

```
score = 0

if dll.is_unsigned:
    score += 30

if dll.loaded_after_process_init:
    score += 15

if not dll.has_security_cookie and dll.text_size > 0x1000:
    score += 20  # NoCRT indicator

if dll.import_count < 5:
    score += 15

if dll.file_size < 0x5000:  # 20 KB
    score += 10

if dll.imports_only_ntdll:
    score += 25

if not dll.has_pdata_section:
    score += 5

if not dll.has_version_info:
    score += 5

if score >= 50:
    alert("suspicious DLL injection detected")
```

This is a simplified example. Production EDR systems use more sophisticated scoring with machine learning and behavioral context. But the core signals are the same.

---

## 7. ETW and Kernel-Level Detection

### Module Load Events

ETW provides `IMAGE_LOAD` events whenever a DLL is loaded. Each event includes:

- Image file path
- Image base address
- Image size
- Process ID
- Signing level and signature status

Monitoring these events for unsigned images loaded after process initialization is the foundation of DLL injection detection.

### Thread Creation Events

DLL injection typically involves creating a remote thread (via `CreateRemoteThread`, `NtCreateThreadEx`, or APC injection). ETW `THREAD_START` events capture:

- Start address - does it point into a known module?
- Thread creation time relative to process creation
- Calling process (for remote thread creation)

A thread starting at an address that does not belong to any known signed module is a strong injection indicator.

### Combining Telemetry

The strongest detection comes from correlating events:

1. `IMAGE_LOAD` for an unsigned DLL → timestamp T1
2. `THREAD_START` with start address in that DLL → timestamp T2
3. T2 shortly after T1 → high confidence injection

If the DLL also matches NoCRT patterns (small, minimal imports, no security cookie), the confidence increases further.

---

## 8. Practical Recommendations for Defenders

### For EDR Engineers

Don't just check signatures - also look for DLLs signed with revoked or untrusted certificates. Build a baseline of expected DLLs per application; any new DLL that appears in a stable application is worth investigating. Detect CRT absence, not just CRT presence - a DLL with no CRT artifacts doing complex work is more suspicious than one with the CRT. And watch for unexpected `vcruntime140.dll` or `ucrtbase.dll` loads, which signal something new was injected with CRT linkage.

### For Malware Analysts

Check the entry point first. CRT vs NoCRT is immediately visible from the entry point structure. Examine import table density - NoCRT malware often resolves APIs dynamically after load, so look for `GetProcAddress` chains or manual export table walking. And don't forget about statically linked CRT (`/MT`): no CRT imports show up, but the code is still there in the binary.

### For Blue Teams

Sysmon Event ID 7 (Image Loaded) with signature status filtering catches unsigned DLLs immediately. WDAC or AppLocker can block unsigned DLLs from loading entirely in high-security environments. Module load auditing with baseline comparison detects any new DLL in monitored processes.

---

## Conclusion

The CRT is not a security feature - it is a development convenience. But its presence or absence creates a distinctive forensic fingerprint that defenders can use.

An unsigned CRT-linked DLL is easy to catch because the CRT generates initialization telemetry, imports from known CRT libraries, and follows a recognizable structure. Attackers who avoid the CRT to reduce this footprint create a different but equally detectable pattern: minimal imports, no security cookie, tiny file size, and missing standard sections.

For defenders, the lesson is to detect in both directions:
- **CRT present + unsigned** = amateur or careless injection, catch on telemetry and signature
- **CRT absent + unusual characteristics** = deliberate evasion, catch on structural anomalies

Neither choice is invisible to a well-instrumented environment.
