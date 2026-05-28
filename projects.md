---
layout: page
title: Projects
permalink: /projects/
---

Public research prototypes focused on defensive security, detection engineering, and low-level system analysis.

---

### [HvShield](https://github.com/IWishI808/HvShield) - Hypervisor-Based Memory Integrity Monitor

A defensive research prototype that explores Intel VT-x and EPT (Extended Page Tables) for kernel memory integrity monitoring.

The code studies how a hypervisor can sit below the OS and observe writes to protected memory regions. Protected pages can be represented through EPT permissions so access attempts trap as EPT violations for analysis.

Built from scratch in C as a source-level prototype. It includes VMX support checks, VMXON/VMCS scaffolding, EPT structure definitions, identity-map construction with 2 MB pages, and MTRR-aware memory typing.

**Defensive research goals:**
- Kernel code patching (rootkit installation)
- SSDT or IDT modification research
- Unauthorized driver code modification monitoring

**Stack:** C, Intel VT-x, EPT, Windows kernel
**Writeup:** [VMCS by Practice](/2026/05/20/vmcs-by-practice/), [EPT Internals](/2026/05/18/ept-internals/)

---

### [CRTScan](https://github.com/IWishI808/CRTScan) - DLL Injection Detection via CRT Fingerprinting

A defensive prototype that identifies suspicious DLLs by analyzing C Runtime artifacts, PE structure, and return addresses around common initialization-related APIs.

Hooks `GetSystemTimeAsFileTime`, `QueryPerformanceCounter`, `GetCurrentProcessId`, and `GetCurrentThreadId`. When any of these fire, it walks the call stack and checks whether the return address belongs to a signed, known module. Unsigned callers get flagged.

Also performs static analysis on loaded modules: checks for missing security cookies, minimal import tables, absent `.pdata` sections, and other NoCRT indicators that suggest a purpose-built injection payload.

**Detection signals:**
- CRT-linked unsigned DLLs via return address analysis
- NoCRT payloads via structural anomaly scoring
- Late-loaded modules that weren't part of the original process

**Stack:** C, Windows API, PE parsing
**Writeup:** [CRT vs NoCRT Detection](/2026/05/10/crt-nocrt-detection/)

---

### [VTCheck](https://github.com/IWishI808/VTCheck) - Virtual Method Table Integrity Verifier

A runtime integrity checker for COM and C++ vtables. It validates that vtable pointers reference `.rdata` sections within expected modules and that individual function entries stay inside the expected module boundary.

Performs RTTI chain validation on MSVC binaries by walking `CompleteObjectLocator` structures to verify class hierarchy integrity. Detects both direct vtable patching (modified entries in original `.rdata`) and full vtable replacement (object pointing to heap-allocated copy).

Built to monitor DXGI/D3D11 COM interfaces, which are frequent targets for both legitimate overlays and malicious hooks.

**What it detects:**
- Direct vtable entry patching
- Vtable pointer replacement (heap-allocated fake vtables)
- Broken or missing RTTI chains
- `.rdata` permission changes (VirtualProtect on read-only sections)

**Stack:** C++, COM, PE analysis, RTTI parsing
**Writeup:** [VMT Hooking Detection](/2026/05/12/vmt-hooking-detection/)

---

### [PEBWatch](https://github.com/IWishI808/PEBWatch) - Process Environment Block Tamper Detection

A lightweight monitoring agent that periodically snapshots PEB state and cross-references it against image-backed memory regions to detect manipulation.

Compares the PEB module list against image-backed memory regions discovered through `VirtualQuery` to find unlinked modules. Checks `ImagePathName`, `CommandLine`, `BeingDebugged`, and `NtGlobalFlag` for signs of post-creation tampering.

**What it detects:**
- Module unlinking (DLLs hidden from PEB but still loaded)
- ImagePathName spoofing
- CommandLine modification post-creation
- Anti-debug PEB field clearing

**Stack:** C, Windows internals, PEB analysis
**Writeup:** [PEB Internals](/2026/05/15/peb-windows-internals/)

---

### [IDAVtableRecovery](https://github.com/IWishI808/IDAVtableRecovery) - IDA Pro Plugin for C++ Structure Reconstruction

An IDA Pro Python plugin that automates vtable discovery and C++ class hierarchy reconstruction from stripped binaries.

Walks `.rdata` sections looking for vtable signatures, parses RTTI structures when available, and reconstructs class inheritance trees. For binaries compiled without RTTI (`/GR-`), uses heuristic matching on vtable layouts and cross-references to infer relationships.

Exports recovered structures as IDA type definitions and generates annotated call graphs showing virtual dispatch relationships.

**What it does:**
- Automated vtable discovery from `.rdata` scanning
- RTTI-based class hierarchy reconstruction
- Heuristic vtable matching for stripped binaries
- Structure export to IDA type library
- Cross-reference mapping for virtual dispatch

**Stack:** Python, IDAPython, PE format, MSVC ABI
