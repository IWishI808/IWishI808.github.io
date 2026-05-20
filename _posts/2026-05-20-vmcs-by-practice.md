---
---
layout: post
title: "VMCS by Practice: Notes from Writing a Hypervisor"
date: 2026-05-20
tags: [hypervisor, vmx, intel, reverse-engineering, low-level]
---

If you start reading Intel VMX documentation seriously, you quickly notice something frustrating: the Intel SDM is extremely precise, but not pedagogical. It's a reference manual, not a learning path.

Most beginner questions are not about individual fields. They're about *relationships* between concepts:

- How many VMCS structures actually exist?
- What does "current VMCS" really mean?
- Why does `VMPTRLD` fail right after allocation?
- What's the difference between `VM_EXIT_REASON` and `VM_INSTRUCTION_ERROR`?
- Why do some VM exits feel impossible to debug?

This article is not a complete VMX reference. It's a collection of practical notes and mental models I wish I had earlier while working on a custom hypervisor for learning purposes.

The target reader has already opened Intel SDM Vol. 3C, read the first VMX chapters, maybe looked at projects like HyperPlatform or KVM, and now has concrete debugging questions.

**We will focus on:**

- VMCS lifecycle
- VMCS activation rules
- common beginner mistakes
- VMX debugging flow
- VM exit diagnostics

**We will not cover:** EPT internals, posted interrupts, nested virtualization, APIC virtualization, advanced scheduling, or production-grade VMM design. Those deserve separate articles.

---

## 1. How Many VMCS Exist, and How Many Are Current?

A common beginner misunderstanding is assuming there is "one VMCS per VM". That is incorrect.

**The VMCS is tied to a vCPU, not to the VM itself.**

Consider this scenario:

- 4 VMs
- 2 vCPUs per VM
- 8 logical processors on the host

That means `4 × 2 = 8` vCPUs, and because each vCPU needs its own execution context, **8 VMCS regions allocated**.

A mental model:

```
VM1:  vCPU0 → VMCS A    VM2:  vCPU0 → VMCS C
      vCPU1 → VMCS B          vCPU1 → VMCS D

VM3:  vCPU0 → VMCS E    VM4:  vCPU0 → VMCS G
      vCPU1 → VMCS F          vCPU1 → VMCS H
```

That tells us how many VMCS structures exist in memory. But Intel VMX introduces another concept: the **current VMCS**.

A VMCS becomes *current* on a logical processor after `VMPTRLD`. This loads the VMCS pointer into the processor's VMX state. The important rule:

> A logical processor has exactly one current VMCS at a time. A VMCS cannot be current on multiple logical processors simultaneously.

That second clause is what makes SMP hypervisor work non-trivial.

### Allocated vs Current vs Launched

These three terms are often confused, and the distinction is the single most useful mental model you can build early.

**Allocated** — a 4 KB VMCS region exists in memory. Nothing more. The CPU doesn't know about it.

**Current** — `VMPTRLD` has been executed for this VMCS on a logical processor. The CPU now associates VMX execution state with that structure. `VMREAD` / `VMWRITE` operate on the current VMCS.

**Launched** — `VMLAUNCH` has succeeded at least once on this VMCS. From this point, `VMLAUNCH` can no longer be used on it; only `VMRESUME`. The CPU internally tracks this launch-state bit.

A VMCS therefore lives in one of several states: *clear* (just allocated or just `VMCLEAR`'d), *current but not launched*, or *current and launched*. `VMCLEAR` transitions a VMCS back to the *clear* state, which means after a clean migration to another LP you use `VMLAUNCH` again, not `VMRESUME`.

### Maximum Current VMCS at Once

In our example:

- 8 vCPUs
- 8 logical processors

All 8 VMCS structures *could* be current simultaneously, one per LP:

```
LP0 → VMCS A    LP4 → VMCS E
LP1 → VMCS B    LP5 → VMCS F
LP2 → VMCS C    LP6 → VMCS G
LP3 → VMCS D    LP7 → VMCS H
```

But if only 2 vCPUs are scheduled at this instant: 8 VMCS allocated, 2 current, 6 sitting inactive in RAM.

### VMCS Migration Trap

One of the easiest mistakes in multi-core hypervisor development is reusing a VMCS on another CPU without properly clearing it first.

Before a VMCS can migrate cleanly between logical processors, you must issue `VMCLEAR` on the source LP. Otherwise:

- the CPU on the source LP may still consider it current
- `VMPTRLD` on the destination LP can fail
- internal cached state may not be flushed to the in-memory VMCS

This is one of the reasons VMCS lifecycle management gets complicated once SMP enters the picture.

---

## 2. Why Does `VMPTRLD` Fail Right After Allocation?

This is one of the most classic VMX beginner failures. You allocate a 4 KB page:

```c
void* vmcs = MmAllocateContiguousMemory(0x1000, ...);
```

Then `VMPTRLD` fails immediately with `VMfailInvalid`. The usual reason: **you forgot to initialize the VMCS revision identifier**.

### The VMCS Revision Identifier

A VMCS region is not just "any aligned page". Intel requires the first 32 bits of the page to contain a specific value, the *VMCS revision identifier*:

```
offset 0x000:
  bits  0-30  → VMCS revision ID
  bit   31    → shadow VMCS indicator (keep at 0 unless using shadow VMCS)
```

Before `VMPTRLD`, you must write the revision ID at offset 0. It comes from MSR `IA32_VMX_BASIC` (`0x480`):

```c
uint64_t vmx_basic = __readmsr(0x480);
uint32_t revision_id = (uint32_t)(vmx_basic & 0x7FFFFFFF);

memset(vmcs, 0, 0x1000);
*(uint32_t*)vmcs = revision_id;
```

After that, `VMPTRLD` can succeed.

### Aside: VMXON Region

The VMXON region is a *different* 4 KB structure used by the `VMXON` instruction itself. It is **not** a VMCS, but confusingly it also requires the revision ID written at offset 0 (same MSR, same format). Beginners often allocate one and reuse it incorrectly. Keep them as separate allocations.

### Physical vs Virtual Address Trap

`VMPTRLD` expects a *physical* address. Not a virtual address.

```c
// Wrong:
__vmx_vmptrld(&vmcs_virtual);

// Correct:
__vmx_vmptrld(&vmcs_physical);
```

The VMCS region lives in physical memory from the CPU's perspective.

### Alignment Requirements

The VMCS region must be 4 KB aligned and 4 KB in size. This is why contiguous physical allocation is commonly used. Misalignment alone produces immediate VMX failures.

### Why Intel Designed It This Way

Unlike AMD's VMCB, the VMCS format is intentionally opaque. Intel does not expose an official C structure layout. The CPU owns the real internal format, and software interacts through `VMREAD` / `VMWRITE`.

The revision ID lets Intel evolve internal VMCS layouts across processors while keeping compatibility rules clear. The VMCS page is therefore partly a memory structure, and partly a CPU-managed object. That matters when debugging VMX state issues.

---

## 3. The 6 Regions of a VMCS

The VMCS is easier to understand once you stop viewing it as a giant opaque structure and instead split it into functional areas. Intel conceptually divides it into six regions.

**1. Guest-State Area.** Guest CPU state: RIP, RSP, CR0/CR3/CR4, segment state, MSRs, etc. On VM entry, the CPU loads guest execution state from here. On VM exit, the CPU saves it back here. This is a *transition snapshot*, not a live view of the guest CPU.

**2. Host-State Area.** Defines the state restored during VM exit: host RIP, host RSP, host CR3, segment selectors. Again, transition state — not a live host CPU mirror.

**3. VM-Execution Control Fields.** What should cause VM exits? CPUID intercept, MOV CR3 intercept, EPT enable, MSR bitmaps, exception bitmap, etc.

**4. VM-Exit Control Fields.** What happens during the exit transition: host address-space size, save/load debug controls, MSR switching behavior.

**5. VM-Entry Control Fields.** What happens during the entry transition: IA-32e guest mode, event injection, MSR loading.

**6. VM-Exit Information Fields.** Read-only diagnostic fields filled by the CPU during VM exits: `VM_EXIT_REASON`, `EXIT_QUALIFICATION`, `VM_EXIT_INTR_INFO`. These are critical for debugging — they answer *why* the VM exited.

---

## 4. `VM_EXIT_REASON` vs `VM_INSTRUCTION_ERROR`

This is probably the single most common conceptual confusion in beginner VMX development. These two fields answer completely different questions.

### `VM_EXIT_REASON`

> Why did the guest stop executing?

The important implication: **the guest was successfully running**, and a VM exit happened afterward.

```
VMLAUNCH
  → guest runs
  → VMEXIT occurs
  → hypervisor resumes
  → VM_EXIT_REASON available
```

Typical reasons: CPUID intercept, EPT violation, exception, HLT, I/O instruction, MOV CR3 intercept. You read it after a successful VM exit via `VMREAD(VM_EXIT_REASON)`.

### `VM_INSTRUCTION_ERROR`

> Why did a VMX instruction fail?

Completely different concept. Examples: `VMLAUNCH`, `VMRESUME`, `VMPTRLD`, `VMWRITE`. The guest may never have executed at all.

```
VMLAUNCH
  → VMfailValid
  → VM_INSTRUCTION_ERROR explains why
```

This is not a VM exit. This is a VMX API failure.

### The Car Analogy

`VM_EXIT_REASON` — *the car was driving; why did it stop?* Red light, crash, police stop, engine failure.

`VM_INSTRUCTION_ERROR` — *the car never started; why?* Invalid key, dead battery, broken engine.

### The Beginner Trap

A very common mistake:

```
if (VMLAUNCH failed)
    read VM_EXIT_REASON;
```

Conceptually wrong. No VM exit occurred. The guest never ran. The correct field is `VM_INSTRUCTION_ERROR`.

### `VMfailInvalid` vs `VMfailValid`

Another distinction worth knowing.

**`VMfailInvalid`** — fundamental VMX failure: invalid VMCS pointer, non-aligned VMCS, VMX disabled. There may be no valid `VM_INSTRUCTION_ERROR` to read.

**`VMfailValid`** — the instruction was understood, but parameters or VMCS state are invalid. `VM_INSTRUCTION_ERROR` will contain a precise reason.

### Common `VM_INSTRUCTION_ERROR` Codes

Worth keeping a printed table near your debugger. The ones that come up most often:

| Code | Meaning |
|-----:|---------|
| 4  | `VMLAUNCH` with non-clear VMCS |
| 5  | `VMRESUME` with non-launched VMCS |
| 7  | VM entry with invalid control fields |
| 8  | VM entry with invalid host-state field |
| 9  | `VMPTRLD` with invalid physical address |
| 10 | `VMPTRLD` with `VMXON` pointer |
| 11 | `VMPTRLD` with incorrect VMCS revision identifier |
| 12 | `VMREAD`/`VMWRITE` to unsupported VMCS component |
| 13 | `VMWRITE` to read-only VMCS component |
| 26 | VM entry with events blocked by MOV SS |

Codes 7 and 8 are by far the most common when wiring up a new hypervisor.

### Practical Rule

- If the guest executed and then exited → read `VM_EXIT_REASON`.
- If a VMX instruction itself failed → read `VM_INSTRUCTION_ERROR`.

This distinction alone removes a massive amount of VMX debugging confusion.

---

## 5. Debugging Exit Reason 0

One of the most confusing VM exits for beginners:

```
EXIT_REASON = 0
EXIT_QUALIFICATION = 0
```

This often looks meaningless. It is not.

### Exit Reason 0 = Exception or NMI

A guest exception occurred (or an NMI), and VMX controls caused a VM exit. The key point: **`EXIT_QUALIFICATION` is usually not the important field here**. The most important field is `VM_EXIT_INTR_INFO`.

### `VM_EXIT_INTR_INFO`

This field tells you:

- exception vector
- interruption type
- whether an error code exists
- **whether the field is valid (bit 31 — check this first)**

If bit 31 is 0, the rest of the field is meaningless. Beginners often skip this check and chase a phantom vector. Always validate first, then decode.

Common vectors:

| Vector | Exception |
|-------:|-----------|
| 3  | `#BP` (breakpoint) |
| 6  | `#UD` (invalid opcode) |
| 13 | `#GP` (general protection) |
| 14 | `#PF` (page fault) |

### Page Faults (`#PF`, vector 14)

`EXIT_QUALIFICATION` becomes useful — it contains page-fault semantics. Also inspect:

- `GUEST_LINEAR_ADDRESS`
- guest `CR2`
- guest `RIP`

Important: a normal guest page fault is **exit reason 0**. An EPT violation is **exit reason 48**. Do not mix them up — they are routed by completely different logic in the CPU.

### General Protection Faults (`#GP`, vector 13)

Common causes when bringing up a hypervisor: invalid segment state, bad CR4 setup, invalid MSRs, non-canonical addresses, broken host-state fields. Priority checks: guest `RIP`, guest `CS`, guest `CR3`, host-state validity.

### Invalid Opcode (`#UD`, vector 6)

Likely causes: unsupported instruction, broken `RIP`, invalid execution mode, VMX instruction leaking into the guest, XSAVE/XRSTOR issues.

### Useful Debug Checklist for Exit Reason 0

1. Read `VM_EXIT_INTR_INFO`. Check bit 31. Identify the vector.
2. Read `GUEST_RIP`. Locate the crashing instruction.
3. Read `VM_EXIT_INSTRUCTION_LEN`. Decode instruction bytes correctly.
4. Read guest `CR3` / `CS` / `RSP`. Understand execution context.
5. Read `GUEST_LINEAR_ADDRESS` if memory-related.
6. Distinguish guest fault from EPT fault. (Big source of confusion.)

---

## 6. Suggested Reading Order for SDM Vol. 3C

If I restarted VMX learning from zero, I would read the Intel SDM in a very different order from how it's printed. The SDM is structured as a reference manual, not a tutorial.

**Start with VMX operation basics.** VMX root vs non-root, VM entry, VM exit, VMCS lifecycle. Without this, the rest feels random.

**Then read the VMCS layout chapter.** Focus on guest state, host state, control fields, exit information fields. Do not try to memorize encodings yet — build a mental structure first.

**Then read the VM-entry and VM-exit chapters.** These explain what the CPU actually does, in which order, what gets validated, and what can fail. This section alone explains many mysterious crashes.

**Keep these tables open while coding:**

- VM instruction error codes
- VM exit reason codes
- Control-field allowed settings (`IA32_VMX_PINBASED_CTLS`, `IA32_VMX_PROCBASED_CTLS`, etc.)

You will reference them constantly.

### External References

- **HyperPlatform** — very readable educational VMX codebase.
- **KVM** (`arch/x86/kvm/vmx/`) — production-quality reference. Dense, but valuable.
- **Daax / Karvandi / Sina Karvandi (Hvpp / Hypervisor From Scratch)** — some of the best practical VMX writing publicly available.

---

## Conclusion

VMX becomes much easier once you stop thinking of it as "magic CPU behavior" and instead treat it as state transitions, execution contracts, and strict validation rules.

Most beginner VMX debugging problems are not caused by advanced concepts. They come from:

- misunderstanding VMCS lifecycle
- confusing VM exits with VMX instruction failures
- reading the wrong diagnostic field
- not knowing which state is *transition* state versus *live execution* state

This article focused on those foundations. It did not cover EPT internals, VPID, APIC virtualization, MSR bitmaps, posted interrupts, or nested virtualization — each deserves its own write-up, and EPT will be next.

If you understand VMCS lifecycle, current vs launched VMCS, VM exit diagnostics, and the difference between VM exits and VMX failures, you've already eliminated a surprisingly large percentage of early hypervisor debugging pain.
