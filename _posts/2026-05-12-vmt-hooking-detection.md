---
layout: post
title: "VMT Hooking: How It Works and How to Detect It"
date: 2026-05-12
tags: [windows, hooking, detection, cpp, defense]
---

Virtual Method Table (VMT) hooking is one of the oldest and most reliable hooking techniques on Windows. It exploits a fundamental C++ runtime mechanism - the vtable - to redirect virtual function calls without patching any code bytes. No code modification means most integrity scanners miss it entirely.

---

## 1. C++ Virtual Method Tables

Every C++ class with at least one virtual function has a vtable: a static array of function pointers, one per virtual method, in declaration order.

```cpp
class IRenderer {
public:
    virtual void Initialize() = 0;  // vtable[0]
    virtual void BeginFrame() = 0;  // vtable[1]
    virtual void EndFrame() = 0;    // vtable[2]
    virtual void Present() = 0;     // vtable[3]
};
```

When an object is instantiated, its first 8 bytes (on x64) are a pointer to the class vtable:

```
Object in memory:
  +0x00: vtable pointer → [Initialize, BeginFrame, EndFrame, Present]
  +0x08: member data...
```

A virtual call like `renderer->Present()` compiles to:

```asm
mov  rax, [rcx]          ; load vtable pointer from object
call [rax + 0x18]        ; call vtable[3] (Present)
```

The CPU reads the vtable pointer, indexes into the table, and calls whatever address it finds. There is no validation that the address is legitimate.

---

## 2. How VMT Hooking Works

VMT hooking replaces an entry in the vtable with a pointer to a different function. After the hook, every virtual call to that method on *any object using that vtable* is redirected.

### Method 1: Direct Vtable Patch

Overwrite a single entry in the vtable:

```c
void** vtable = *(void***)target_object;

// Save original
original_Present = vtable[3];

// The vtable is typically in .rdata (read-only), so change protection first
DWORD old_protect;
VirtualProtect(&vtable[3], sizeof(void*), PAGE_READWRITE, &old_protect);

// Replace entry
vtable[3] = hooked_Present;

// Restore protection
VirtualProtect(&vtable[3], sizeof(void*), old_protect, &old_protect);
```

**Pros:** Simple, affects all objects sharing this vtable.
**Cons:** Modifies the original vtable in `.rdata`, which can be detected by integrity checks.

### Method 2: Vtable Replacement

Allocate a new vtable, copy all entries, modify the target entry, then point the object's vtable pointer to the new table:

```c
void** original_vtable = *(void***)target_object;
int vtable_size = count_vtable_entries(original_vtable);

// Allocate new vtable
void** new_vtable = (void**)malloc(vtable_size * sizeof(void*));
memcpy(new_vtable, original_vtable, vtable_size * sizeof(void*));

// Hook one entry in the copy
new_vtable[3] = hooked_Present;

// Point object to new vtable
*(void***)target_object = new_vtable;
```

**Pros:** Original vtable is untouched. Only one object is affected.
**Cons:** The new vtable is in heap memory, which is unusual. Only affects the specific object instance.

---

## 3. Why VMT Hooks Are Hard to Detect

Inline hooks (patching the first bytes of a function with a `JMP`) are well-understood and widely detected:

- Code integrity scanners compare function prologues against known-good copies
- `JMP` or `INT3` instructions at function entry are obvious indicators
- ETW and kernel callbacks can detect code modification in certain scenarios

VMT hooks avoid all of this:

- **No code modification.** The function code is untouched. Only a data pointer changes.
- **No executable memory changes.** The modification is in a data section or on the heap.
- **Legitimate-looking calls.** The CPU's virtual dispatch mechanism works normally. The call instruction hasn't changed.
- **No unusual instructions.** There is no `JMP` to a trampoline, no `INT3`, no detour.

This is why traditional code integrity scanning doesn't catch VMT hooks.

---

## 4. Real-World Attack Patterns

Here's where VMT hooks actually show up in practice.

### COM Object Hooking

Windows COM (Component Object Model) is built on vtables. Every COM interface is a vtable. Hooking a COM object's vtable redirects interface method calls:

```
IUnknown vtable:
  [0] QueryInterface
  [1] AddRef
  [2] Release

IDXGISwapChain vtable:
  [0] QueryInterface
  [1] AddRef
  [2] Release
  ...
  [8] Present        ← commonly hooked
```

DXGI hooking via `Present` is used by game overlays (Steam, Discord), screen recorders, and performance tools. But the same technique can be used by malware to intercept graphics output or inject visual elements.

### Browser COM Hooking

Browsers expose COM interfaces for automation. Hooking these interfaces allows intercepting web traffic, modifying page content, or stealing credentials - all through vtable manipulation that won't trigger code integrity alerts.

### Security Product Bypass

Some security products expose COM or C++ interfaces that can be hooked via VMT. If a security scanning function is virtual, replacing its vtable entry effectively disables that scan while the product continues to report as healthy.

---

## 5. Detection Strategies

### Strategy 1: Vtable Pointer Validation

For known objects, verify that the vtable pointer points to the expected `.rdata` section of the correct module:

```c
bool validate_vtable(void* object, HMODULE expected_module) {
    void** vtable = *(void***)object;

    MODULEINFO module_info;
    GetModuleInformation(GetCurrentProcess(), expected_module,
                         &module_info, sizeof(module_info));

    uintptr_t vtable_addr = (uintptr_t)vtable;
    uintptr_t module_start = (uintptr_t)module_info.lpBaseOfDll;
    uintptr_t module_end = module_start + module_info.SizeOfImage;

    // Vtable should be within the module's image
    return (vtable_addr >= module_start && vtable_addr < module_end);
}
```

If the vtable pointer points to heap memory or an unknown module, the object's vtable has likely been replaced.

### Strategy 2: Vtable Entry Validation

Even if the vtable itself is in the correct location, individual entries might be patched. Validate that each entry points to the expected module:

```c
bool validate_vtable_entry(void** vtable, int index, HMODULE expected_module) {
    void* func_ptr = vtable[index];

    MODULEINFO module_info;
    GetModuleInformation(GetCurrentProcess(), expected_module,
                         &module_info, sizeof(module_info));

    uintptr_t func_addr = (uintptr_t)func_ptr;
    uintptr_t module_start = (uintptr_t)module_info.lpBaseOfDll;
    uintptr_t module_end = module_start + module_info.SizeOfImage;

    return (func_addr >= module_start && func_addr < module_end);
}
```

An entry pointing outside the expected module is a strong hook indicator.

### Strategy 3: .rdata Integrity Comparison

Compare the in-memory vtable against the on-disk copy of the module:

1. Load the PE file from disk
2. Find the `.rdata` section
3. Locate the vtable by its known offset or by matching RTTI data
4. Compare each entry against the in-memory version

Any discrepancy indicates tampering. This is the most thorough approach but requires knowing which vtables to check.

### Strategy 4: RTTI (Run-Time Type Information) Validation

MSVC stores RTTI data adjacent to the vtable. The vtable pointer at index -1 points to a `CompleteObjectLocator` structure, which contains class hierarchy information.

```
vtable[-1] → CompleteObjectLocator
               → TypeDescriptor (class name string)
               → ClassHierarchyDescriptor
```

If the RTTI chain is missing, corrupted, or points to unexpected locations, the vtable has been tampered with. Legitimate vtables always have valid RTTI in MSVC builds (unless compiled with `/GR-`).

### Strategy 5: Memory Region Analysis

Vtables belong in `.rdata` (read-only initialized data). Check the memory protection of the region containing the vtable:

```c
MEMORY_BASIC_INFORMATION mbi;
VirtualQuery(vtable, &mbi, sizeof(mbi));

if (mbi.Protect != PAGE_READONLY) {
    // .rdata should be PAGE_READONLY
    // PAGE_READWRITE suggests tampering
}

if (mbi.Type == MEM_PRIVATE) {
    // vtable is in heap/private memory, not in a module image
    // strong indicator of vtable replacement
}
```

---

## 6. Monitoring and Alerting

### Periodic Integrity Scans

For high-value targets (security-critical COM interfaces, graphics subsystem objects), periodically validate vtable integrity:

1. Enumerate known critical objects
2. Validate vtable pointers and entries against expected modules
3. Check RTTI integrity
4. Log and alert on deviations

### ETW Integration

ETW providers can be configured to monitor for:
- `VirtualProtect` calls targeting `.rdata` sections (needed for direct vtable patches)
- Memory allocation near module image ranges (might indicate vtable replacement setup)
- Suspicious `memcpy` patterns targeting known vtable locations

### Kernel-Level Monitoring

A kernel driver can:
- Monitor page table permission changes for `.rdata` pages
- Use hypervisor-based EPT monitoring (see [EPT Internals](/2026/05/18/ept-internals/)) to detect writes to vtable memory without depending on user-mode integrity checks

This is the strongest detection approach, as it cannot be subverted from user mode.

---

## 7. VMT Hooking vs Other Hooking Techniques

| Aspect | Inline Hook | IAT Hook | VMT Hook |
|--------|-------------|----------|----------|
| Modifies code | Yes | No | No |
| Modifies data | No | Yes (IAT) | Yes (vtable) |
| Scope | All callers | Import callers only | Virtual call callers |
| Code integrity detection | Easy | Medium | Hard |
| Requires C++ target | No | No | Yes |
| Detectable by ETW | Partially | Partially | Harder |

VMT hooking occupies a specific niche: it requires a C++ virtual interface, but in return it is the most difficult hook type to detect with standard code scanning tools. For defenders, this means that code integrity alone is not sufficient - data integrity must also be verified.

---

## Conclusion

VMT hooking exploits a core C++ mechanism that was never designed with adversarial use in mind. The vtable is trust-by-convention: the runtime assumes function pointers are legitimate because nothing validates them.

The bottom line: code integrity scanning alone does not catch VMT hooks. You need data integrity checks too. Vtable pointers should point to `.rdata` in the expected module, not to heap or unknown regions. RTTI validation helps for MSVC-compiled binaries. COM interfaces are vtable-based and represent a broad attack surface. And if you really want the strongest detection, hypervisor-based EPT monitoring operates below anything user-mode can subvert.

If you're only scanning for inline hooks, you're leaving a gap that adversaries know about.
