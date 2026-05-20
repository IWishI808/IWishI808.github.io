---
layout: post
title: "EPT Internals: Understanding Intel's Second Layer of Paging"
date: 2026-05-18
tags: [hypervisor, ept, intel, memory, low-level]
---

This is the follow-up to [VMCS by Practice](/2026/05/20/vmcs-by-practice/). If that article focused on getting a guest to *run*, this one focuses on controlling what it *sees* in memory.

Extended Page Tables (EPT) is Intel's hardware-assisted memory virtualization. Before EPT, hypervisors had to use shadow page tables - maintaining a parallel set of page tables and trapping every guest page table modification. It worked, but it was slow and complex.

EPT adds a second translation layer directly in hardware. The guest manages its own page tables normally (GVA → GPA), and the CPU automatically translates guest physical addresses to host physical addresses (GPA → HPA) through EPT. No traps needed for normal memory access.

I'll go through the structures, the walk, the common mistakes, and how to debug all of it.

---

## 1. The Two-Layer Translation Model

Without virtualization, address translation is:

```
Virtual Address (VA) → Physical Address (PA)
          via CR3 → page tables
```

With EPT enabled, the guest still thinks it controls physical memory, but every "physical" address the guest produces is actually a *guest physical address* (GPA). The CPU then walks EPT to find the real host physical address:

```
Guest Virtual Address (GVA)
    → Guest Page Tables (controlled by guest CR3)
    → Guest Physical Address (GPA)
        → EPT Page Tables (controlled by EPTP in VMCS)
        → Host Physical Address (HPA)
```

The critical insight: **the guest page table walk itself goes through EPT**. When the CPU reads a guest PTE, that PTE lives at a GPA, which must be translated through EPT to find the actual memory. This means a single guest virtual address translation can trigger multiple EPT walks.

### The Cost of Nested Translation

A full 4-level guest page walk with 4-level EPT means up to **20 memory accesses** in the worst case (no TLB hits):

- 4 guest page table levels
- Each level requires an EPT walk (4 EPT levels each)
- 4 × 4 = 16 EPT accesses + 4 guest table reads = 20 total

In practice, TLB caching (especially with VPIDs and EPT-tagged TLB entries) reduces this dramatically. But knowing the worst case explains why EPT misconfigurations hurt so much.

---

## 2. EPT Structure Layout

EPT uses the same hierarchical structure as regular x86-64 paging: 4 levels, 512 entries per table, 8 bytes per entry.

```
EPTP (in VMCS)
  → PML4 (Page Map Level 4)         512 entries, each covers 512 GB
    → PDPT (Page Directory Pointer)  512 entries, each covers 1 GB
      → PD (Page Directory)          512 entries, each covers 2 MB
        → PT (Page Table)            512 entries, each covers 4 KB
```

Each level uses 9 bits of the guest physical address:

```
GPA bits:
  [47:39] → PML4 index
  [38:30] → PDPT index
  [29:21] → PD index
  [20:12] → PT index
  [11:0]  → page offset
```

### EPT Entry Format

An EPT entry at any level has this basic structure:

```
Bits 2:0   → Read / Write / Execute permissions
Bit  7     → Large page (1 GB at PDPT level, 2 MB at PD level)
Bits 51:12 → Physical address of next level (or final page frame)
```

The permission bits are the most important part for security research:

| Bit | Permission | Meaning |
|----:|------------|---------|
| 0   | Read       | Guest can read this memory |
| 1   | Write      | Guest can write this memory |
| 2   | Execute    | Guest can execute from this memory |

Setting all three to 0 on a valid mapping means any access causes an **EPT violation** (VM exit reason 48). This is the foundation of EPT-based memory monitoring.

### The EPTP (EPT Pointer)

The EPT pointer is stored in the VMCS and tells the CPU where the PML4 table lives:

```
Bits 2:0   → Memory type for EPT structures (typically 6 = write-back)
Bits 5:3   → EPT page walk length minus 1 (set to 3 for 4-level walk)
Bits 51:12 → Physical address of PML4 table (4 KB aligned)
```

A common beginner mistake: setting the memory type wrong or forgetting the walk length field. Both produce immediate VM entry failures with unhelpful error messages.

---

## 3. Building an Identity Map

The simplest EPT configuration maps all guest physical memory 1:1 to host physical memory. GPA 0x1000 maps to HPA 0x1000. The guest sees exactly the real physical layout.

This is not useful for isolation, but it is the correct first step when bringing up a hypervisor. Get identity mapping working before attempting anything more complex.

### Allocation Strategy

For a system with 4 GB of physical memory:

```
PML4:  1 table   (covers up to 256 TB)
PDPT:  1 table   (covers up to 512 GB, we need ~4 GB)
PD:    4 tables  (each covers 1 GB, 4 × 1 GB = 4 GB)
PT:    0 tables  (use 2 MB large pages to avoid this level)
```

Using 2 MB large pages simplifies the initial setup significantly. Set bit 7 in the PD entries to enable large pages:

```c
for (uint64_t i = 0; i < 2048; i++) {  // 2048 × 2 MB = 4 GB
    uint64_t pd_index = i % 512;
    uint64_t pdpt_index = i / 512;

    pd_tables[pdpt_index][pd_index] =
        (i * 0x200000)    // physical address
        | (1 << 7)        // large page
        | 0x7;            // read + write + execute
}
```

### Common Identity Map Mistakes

MTRR interaction will get you. The memory type in EPT entries interacts with MTRR (Memory Type Range Registers). For identity mapping, write-back (6) works for RAM regions, but MMIO regions need uncacheable (0). I spent way too long debugging subtle corruption before realizing this.

MMIO ranges need to be covered too. Device MMIO regions (like the local APIC at `0xFEE00000`) must also be mapped. Missing MMIO mappings cause EPT violations when the guest accesses hardware.

Also watch out for physical address width. Not all CPUs support 48-bit physical addresses. Check `CPUID.80000008H:EAX[7:0]` for the actual width. Mapping beyond what the hardware supports causes undefined behavior.

---

## 4. EPT Violations (VM Exit Reason 48)

When the guest accesses memory in a way that violates EPT permissions, the CPU generates a VM exit with reason 48. This is the most important EPT-related exit for security research.

### Exit Qualification

For EPT violations, `EXIT_QUALIFICATION` contains detailed information about what happened:

```
Bit 0  → caused by data read
Bit 1  → caused by data write
Bit 2  → caused by instruction fetch
Bit 3  → EPT entry read permission (at the faulting level)
Bit 4  → EPT entry write permission
Bit 5  → EPT entry execute permission
Bit 7  → GPA is valid in GUEST_PHYSICAL_ADDRESS field
Bit 8  → fault was a GPA translation (not a page walk)
```

### Relevant VMCS Fields

After an EPT violation, read these fields:

- `GUEST_PHYSICAL_ADDRESS` - the GPA that caused the violation
- `GUEST_LINEAR_ADDRESS` - the GVA the guest was accessing (if bit 7 of qualification is set)
- `GUEST_RIP` - where the guest was executing
- `VM_EXIT_INSTRUCTION_LEN` - length of the faulting instruction

### EPT Violation vs Page Fault

This is a critical distinction that confuses beginners:

**Page fault (exit reason 0, vector 14):** The guest's *own* page tables rejected the access. The guest OS would normally handle this via its page fault handler. The hypervisor sees it only if exception bitmap bit 14 is set.

**EPT violation (exit reason 48):** The guest's page tables were fine, but EPT rejected the GPA → HPA translation. The guest OS has no idea this happened. Only the hypervisor sees it.

```
GVA → guest page tables → GPA → EPT → HPA
         page fault ↑              ↑ EPT violation
```

### EPT Misconfiguration (Exit Reason 49)

Different from EPT violations. A misconfiguration means the EPT entry itself is structurally invalid - for example, a write-only page (write=1, read=0) which Intel does not allow. The CPU cannot meaningfully process the entry.

EPT misconfigurations usually indicate a hypervisor bug, not a guest behavior issue. Check your EPT construction logic when you see exit reason 49.

---

## 5. EPT-Based Memory Monitoring

The reason EPT matters for security research: it provides transparent memory access control below the operating system.

### Read/Write Monitoring

Set an EPT page to execute-only (read=0, write=0, execute=1). Any data read or write by the guest triggers an EPT violation, but code execution continues normally.

Use case: monitoring access to sensitive structures without modifying the guest. The guest kernel cannot detect this monitoring because EPT operates below its privilege level.

### Execute Monitoring

Set an EPT page to read/write but not execute (read=1, write=1, execute=0). Any instruction fetch from that page triggers an EPT violation.

Use case: detecting code execution in data regions, monitoring shellcode, tracking JIT compilation.

### The Split-TLB Approach

A more advanced technique: maintain two EPT views of the same physical memory.

- **View A**: read+write, no execute. Used for data access.
- **View B**: execute-only, no read/write. Used for code execution.

Switch between views on EPT violations. This allows monitoring both code execution and data access to the same memory region, which is useful for detecting self-modifying code or analyzing packed executables.

The complexity cost is significant. Each EPT violation requires determining whether to switch views, and high-frequency switching destroys performance. This is a research technique, not a production approach.

---

## 6. Debugging EPT Issues

EPT bugs are hard to debug because the symptoms are indirect. The guest crashes, hangs, or behaves incorrectly, with no obvious connection to EPT.

### Diagnostic Checklist

**Guest triple-faults immediately after VMLAUNCH:**
- EPT identity map is incomplete. The guest's first instruction fetch hits an unmapped GPA.
- Check that the guest RIP's physical page is mapped with execute permission.

**Guest runs but crashes accessing devices:**
- MMIO regions are not mapped in EPT.
- Map at minimum: local APIC (`0xFEE00000`), IOAPIC, any device the guest uses.

**Random guest corruption:**
- Memory type mismatch. EPT entry memory type conflicts with MTRR settings.
- For RAM, use write-back. For MMIO, use uncacheable.

**Performance is unexpectedly terrible:**
- Using 4 KB pages where 2 MB pages would work. Every TLB miss is more expensive with smaller pages.
- VPID not enabled. Without VPID, every VM exit/entry flushes TLB entries.

### EPT Walk Validation

When debugging, manually walk the EPT for a suspect GPA:

```
Given GPA = 0x00000000_001F5000:

PML4 index   = (GPA >> 39) & 0x1FF = 0
PDPT index   = (GPA >> 30) & 0x1FF = 0
PD index     = (GPA >> 21) & 0x1FF = 0
PT index     = (GPA >> 12) & 0x1FF = 0x1F5

Walk: EPTP → PML4[0] → PDPT[0] → PD[0] → PT[0x1F5]
```

At each level, verify:
1. The entry is present (at least one permission bit set, or the entry is valid)
2. The physical address in the entry points to a real allocated table
3. Permission bits match your intent

---

## 7. EPT in Defensive Security

This is where EPT gets interesting from a defensive perspective. A bunch of modern security products rely on EPT, and knowing how they use it helps you evaluate what they actually protect.

EPT can make kernel code pages non-writable at the hardware level. Any attempt to patch kernel code - a common rootkit technique - triggers an EPT violation. Microsoft's HVCI relies on this principle.

During incident response, a hypervisor can read guest physical memory through EPT without being subverted by kernel-level rootkits that manipulate the OS's own page tables. Forensic analysts get a trustworthy view of memory that the OS itself can't tamper with.

EPT execute-monitoring can also detect when data regions start executing code - a strong indicator of exploitation. EDR products increasingly use hypervisor-based telemetry for exactly this, because it operates below the level where malware can interfere.

Windows Credential Guard uses a separate VTL (Virtual Trust Level) with its own EPT mapping to isolate LSASS secrets. Even if an attacker gains kernel access in VTL0, EPT prevents reading the isolated memory.

All of these rely on the same thing: EPT gives you a monitoring layer that the OS and anything running inside it cannot see or bypass.

---

## Conclusion

EPT transforms a hypervisor from "a thing that runs a guest" into "a thing that controls what the guest sees." The identity map gets things working. Permission manipulation makes things interesting.

Quick recap of what matters:

- Two-layer translation: GVA → GPA → HPA, each with its own page tables
- EPT violations (reason 48) are your primary tool for memory monitoring
- EPT violations are not page faults - different translation layer entirely
- Start with identity mapping using 2 MB large pages
- Memory type and MTRR interaction causes the most subtle bugs
- EPT-based monitoring sits below the OS, which is what makes it powerful

Next up: the PEB (Process Environment Block) on Windows. Completely different domain, but the same theme of understanding internal structures to do useful security work.
