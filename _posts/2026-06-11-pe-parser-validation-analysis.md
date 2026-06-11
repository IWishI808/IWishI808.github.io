---
layout: post
title: "PE Header Validation: How Parsers Fail and What Defenders Can Learn"
date: 2026-06-11
tags: [reverse-engineering, pe-format, vulnerability-research, malware-analysis, fuzzing, c++]
---

Most security tools that inspect PE files share the same implicit assumption: the file they are handed is structurally sound. This assumption is wrong in exactly the cases where it matters most — when analyzing attacker-controlled binaries. Understanding how PE parsers fail under adversarial input is useful both for writing better defensive tooling and for identifying vulnerabilities in open-source security tools.

This post analyzes the PE header validation patterns in C++ parsers, focusing on pe-parse (Trail of Bits), and documents the classes of bugs that arise from insufficient input validation against the PE specification.

---

## 1. The PE Structure and Its Traps

The Portable Executable format is defined in the Microsoft PE/COFF specification, but that specification leaves significant room for ambiguity. Parsers make choices about how to handle edge cases, and those choices create attack surface.

The minimal PE walk looks like this:

```
DOS Header (IMAGE_DOS_HEADER)
  └─ e_lfanew → PE Signature (0x00004550)
       └─ COFF Header (IMAGE_FILE_HEADER)
            └─ Optional Header (IMAGE_OPTIONAL_HEADER32/64)
                 └─ Data Directories
                      └─ Section Headers × NumberOfSections
                           └─ Raw section data
```

At every arrow in this chain, the parser trusts a user-controlled offset or size value. The entire format is essentially a chain of user-controlled pointers.

### The Core Trust Problem

Every field that describes a location or size in the PE format can be set to an arbitrary value by whoever created the file:

- `e_lfanew` — offset to the PE signature, can be anything in the file
- `SizeOfOptionalHeader` — how many bytes to read for the optional header
- `NumberOfSections` — how many section headers to iterate
- `VirtualAddress` / `PointerToRawData` — where sections live on disk and in memory
- `SizeOfRawData` — how many bytes to read from disk for a section
- `NumberOfRvaAndSizes` — how many data directories exist

A parser that reads these fields and acts on them without validation is one adversarial PE away from a crash.

---

## 2. pe-parse: Architecture and Trust Boundaries

[pe-parse](https://github.com/trailofbits/pe-parse) is a well-maintained C++ library from Trail of Bits. Its architecture separates parsing from analysis: a core parser walks the PE structure and populates typed data structures, which consumers then query.

The central parsing entry point is `ParsePEFromFile` / `ParsePEFromPointer`, which feeds raw bytes into `detail::parseHeader`. From there, the code walks headers sequentially, with each step using the output of the previous step.

```cpp
// Simplified flow from pe-parser/src/parse.cpp
parsed_pe *ParsePEFromPointer(uint8_t *data, uint64_t len) {
    // bounds check: is there room for DOS header?
    if (len < sizeof(IMAGE_DOS_HEADER)) return nullptr;

    auto *dos = reinterpret_cast<IMAGE_DOS_HEADER *>(data);

    // e_lfanew points to PE signature
    uint32_t pe_offset = dos->e_lfanew;
    if (pe_offset + sizeof(uint32_t) > len) return nullptr;

    // Check PE signature
    uint32_t sig = *reinterpret_cast<uint32_t *>(data + pe_offset);
    if (sig != NT_MAGIC) return nullptr;

    // ...section iteration follows
}
```

This is the correct pattern. The interesting question is whether every subsequent step maintains the same discipline — especially in the less-traveled paths.

---

## 3. Validation Failure Patterns in PE Parsers

### 3.1 NumberOfSections Integer Handling

The `IMAGE_FILE_HEADER.NumberOfSections` field is a `UINT16` (0–65535). A parser that naively allocates or iterates based on this value without a sanity bound is vulnerable.

```cpp
// Dangerous pattern
for (uint16_t i = 0; i < hdr->FileHeader.NumberOfSections; i++) {
    IMAGE_SECTION_HEADER *sec = sections_base + i;
    // If sections_base + i * sizeof(SECTION_HEADER) exceeds file size,
    // this reads out of bounds
    process_section(sec);
}
```

The correct check requires verifying that `sections_base + (NumberOfSections * sizeof(IMAGE_SECTION_HEADER))` does not exceed the file buffer. This calculation itself can overflow on 32-bit values: `65535 * 40 = 2,621,400` bytes, which is large but fits. However, if the multiplied result is compared against a `uint32_t` offset near `UINT32_MAX`, the addition can wrap.

A well-formed section count check:

```cpp
uint64_t sections_end = (uint64_t)sections_offset +
    (uint64_t)hdr->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
if (sections_end > file_size) {
    // reject: section table extends past EOF
    return nullptr;
}
```

Using `uint64_t` for the intermediate calculation prevents the overflow.

### 3.2 SizeOfRawData vs. Physical File

`IMAGE_SECTION_HEADER.SizeOfRawData` tells the parser how many bytes to read from `PointerToRawData` on disk. A parser that trusts this value directly:

```cpp
// Dangerous
memcpy(dest, file_data + section->PointerToRawData, section->SizeOfRawData);
```

If `PointerToRawData + SizeOfRawData > file_size`, this reads beyond the file buffer. The correct check:

```cpp
uint64_t raw_end = (uint64_t)section->PointerToRawData + section->SizeOfRawData;
if (raw_end > file_size) {
    // either truncate to actual file size or reject
    size_t actual = file_size - section->PointerToRawData;
    memcpy(dest, file_data + section->PointerToRawData, actual);
}
```

This is not just a crash vector — it is a **information disclosure** bug in parsers that expose section content to callers, since the extra bytes read contain whatever was in memory adjacent to the file buffer.

### 3.3 Overlapping Sections

The PE spec does not prohibit section headers where `PointerToRawData` values overlap. A parser that maps sections into a trusted in-memory representation without detecting overlaps may process the same bytes as two different sections — a source of logic bugs in signature validation and hash computation.

A well-formed PE for legitimate use cases never has overlapping sections. A PE crafted for analysis evasion commonly does.

Detection:

```cpp
// Check for section overlap
for (int i = 0; i < n_sections; i++) {
    for (int j = i + 1; j < n_sections; j++) {
        uint32_t a_start = sections[i].PointerToRawData;
        uint32_t a_end   = a_start + sections[i].SizeOfRawData;
        uint32_t b_start = sections[j].PointerToRawData;
        uint32_t b_end   = b_start + sections[j].SizeOfRawData;
        if (a_start < b_end && b_start < a_end) {
            // overlapping sections — flag as malformed
        }
    }
}
```

### 3.4 Data Directory Count: NumberOfRvaAndSizes

`IMAGE_OPTIONAL_HEADER.NumberOfRvaAndSizes` specifies how many data directory entries follow the fixed optional header fields. The theoretical maximum per spec is 16 (`IMAGE_NUMBEROF_DIRECTORY_ENTRIES`). However, a PE file can claim any value.

A parser that iterates data directories up to `NumberOfRvaAndSizes` without capping at 16:

```cpp
// Dangerous: NumberOfRvaAndSizes can be attacker-controlled up to ~4 billion
for (DWORD i = 0; i < opt->NumberOfRvaAndSizes; i++) {
    process_data_dir(&opt->DataDirectory[i]);
}
```

If `NumberOfRvaAndSizes` is `0xFFFFFFFF`, this loop runs off the end of the optional header and into section headers, then off the end of the file buffer.

The fix is a bounds cap:

```cpp
DWORD dir_count = min(opt->NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
```

### 3.5 RVA to File Offset Translation

Many parser operations require translating a Relative Virtual Address (RVA) to a file offset. The translation walks the section table: find the section whose `VirtualAddress ≤ rva < VirtualAddress + VirtualSize`, then compute `PointerToRawData + (rva - VirtualAddress)`.

Edge cases:

- RVA that falls in a section gap (between sections)
- RVA that falls in a zero-padded region (`VirtualSize > SizeOfRawData`)
- RVA that points to the PE headers themselves (before the first section)

A parser that fails to handle these gracefully will either crash, return a wrong offset, or silently skip the lookup. For security tools that use RVA translation to locate imports, exports, or debug directories, a silent wrong offset means wrong analysis output.

---

## 4. Crafting Adversarial PE Files for Testing

To test a parser's resilience, craft PE files that hit each validation boundary. A minimal test corpus for a PE parser:

```python
import struct

def make_minimal_pe():
    # DOS header with e_lfanew pointing to PE sig
    dos = bytearray(0x40)
    dos[0:2] = b'MZ'
    struct.pack_into('<I', dos, 0x3C, 0x40)  # e_lfanew = 0x40
    return dos

def corrupt_section_count(pe_bytes, count):
    # Patch NumberOfSections in COFF header
    # COFF header starts at e_lfanew + 4 (skip PE sig)
    e_lfanew = struct.unpack_from('<I', pe_bytes, 0x3C)[0]
    coff_offset = e_lfanew + 4
    struct.pack_into('<H', pe_bytes, coff_offset + 2, count)
    return pe_bytes

# Interesting values to test
INTERESTING_COUNTS = [0, 1, 96, 256, 0xFFFF]
```

The approach:
1. Start with a valid PE (a real system binary)
2. Patch individual fields to boundary values
3. Run the target parser against each variant
4. Check for crashes, assertions, or wrong output

For crash discovery, compile the parser with AddressSanitizer:

```bash
CC=clang CXX=clang++ \
  CFLAGS="-fsanitize=address,undefined" \
  CXXFLAGS="-fsanitize=address,undefined" \
  cmake -DCMAKE_BUILD_TYPE=Debug ..
make
```

ASAN will report out-of-bounds reads before they manifest as crashes in production.

---

## 5. Implications for Defensive Tooling

### 5.1 Parser Bugs as Detection Evasion

A PE file crafted to crash or misbehave analysis tools is a detection evasion technique. If an EDR's PE parser segfaults on malformed input, the signature check never runs. If a sandbox's import extractor reads the wrong offset due to integer overflow in RVA translation, the malware's actual imports go undetected.

Malware families have been observed using:
- Overlapping sections to confuse hash-based detection
- Truncated section data (`SizeOfRawData` larger than the actual file) to bypass scanners that reject incomplete reads
- Invalid data directory counts to cause parsers to skip import/export analysis
- Multiple PE signatures at different offsets (using a large `e_lfanew`) to confuse tools that verify signature placement

### 5.2 What a Robust Parser Should Do

A PE parser used in a security context should:

1. **Reject rather than truncate** — if a field describes data that extends past the file, reject the file as malformed rather than silently reading less
2. **Validate every offset before dereference** — every pointer derived from a header field gets bounds-checked before use
3. **Cap unbounded counts** — `NumberOfSections`, `NumberOfRvaAndSizes`, import thunk counts all get sanity caps
4. **Use 64-bit arithmetic for size calculations** — prevents overflow in the multiplication step
5. **Detect structural anomalies** — overlapping sections, duplicate section names, zero-length sections with data, negative `VirtualSize` — and surface them to the caller

A parser that silently handles malformed input by truncating reads or skipping checks makes it impossible for the caller to know whether the analysis result is trustworthy.

### 5.3 For Malware Analysts

When analyzing a suspicious sample:
- Check `e_lfanew` — values over `0x1000` are rare in legitimate software and may indicate tampering or a packer
- Compare `SizeOfRawData` vs. actual bytes before the next section's `PointerToRawData` — discrepancies indicate padding or overlay data hidden by the parser
- Verify `NumberOfSections` against the physical file size — a claimed section count that implies section headers extending past the file is a corruption or evasion indicator
- Check for overlapping sections — legitimate compilers do not produce them

---

## 6. Responsible Research Notes

The analysis in this post is based on reading source code and understanding the PE format. Any testing was done against files I created in an isolated environment.

If you identify a crash or correctness bug in an open-source parser through this methodology:
1. Open a GitHub Security Advisory on the project's repository (Settings → Security → Advisories)
2. Give maintainers 90 days to patch before public disclosure
3. Request a CVE through the project's CNA or directly via cveform.mitre.org

Trail of Bits, the maintainer of pe-parse, has a documented security contact and responds to responsible disclosure. Most active open-source security tools do.

---

## Conclusion

PE parsers occupy a critical position in the defensive security stack: everything from EDR signature engines to sandbox unpacking depends on correct PE interpretation. A parser that crashes or misparses under adversarial input is not just a reliability problem — it is a security boundary failure.

The validation patterns described here — integer overflow in size calculations, unbounded iteration on header-supplied counts, unchecked offset arithmetic — are not exotic. They are the same bugs that appear in network protocol parsers and file format handlers across the industry. The PE format is old and well-documented, but the attack surface created by parsers that trust it unconditionally is still largely unexamined in the open-source security tooling ecosystem.

For defenders: audit the PE parsers in your stack the same way you audit the tools they are supposed to protect against.
