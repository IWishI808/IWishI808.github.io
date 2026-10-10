---
layout: post
title: "DirectIo64 Forensics and Process Code Redirection"
date: 2026-10-10
author: Youssef Mekkaoui
permalink: /research/directio64-physical-memory-forensics/
description: "Independent forensic analysis of a signed PassMark driver recovered from a commercial game loader, physical memory access, and temporary process code redirection."
tags: [reverse-engineering, driver-security, windows-internals, malware-analysis, byovd]
---

While investigating a purchased commercial game loader, I recovered a signed PassMark DirectIo64 driver and traced how the loader used physical memory access to modify code in a target process. The captured execution path temporarily redirected a user-mode function to a trampoline, executed the mapped payload, and restored the original function bytes.

This is independent forensic research by **Youssef Mekkaoui**. The physical memory interface overlaps published DirectIo64 vulnerabilities. The contribution here is the analysis of the recovered sample and its observed use in a loader; a new CVE has not been established.

## Recovered driver identity

The driver was extracted from the recovered loader and preserved separately from the process memory captures. A subsequent file check confirmed that its size and SHA-256 matched the forensic record. Windows Authenticode verification reported a valid signature from **PassMark Software Pty Ltd**.

| Property | Observed value |
| --- | --- |
| Driver family | DirectIo64 |
| Embedded debug filename | `DirectIo64.pdb` |
| Extracted filename | `embedded_driver_0x0009A0C0.sys` |
| File size | 43,752 bytes |
| Authenticode signer | PassMark Software Pty Ltd |
| Signature verification result | Valid |
| Product and file version metadata | Not present in the extracted file |

SHA-256:

```text
0EC793B3F71F11165C3A360E9F58F9FFC9A377BA0CBC55BE9BAAD02677E43FEA
```

A valid signature identifies the publisher of the signed binary. It does not establish that the driver is safe, current, or endorsed for use by the loader that embeds it. The absence of version metadata also means this sample cannot be assigned to a particular PassMark product build from its filename or signature alone.

## Physical memory access and code redirection

The driver and the loader have different roles. The driver supplies access to physical memory. The loader uses that access to reach the pages backing the target process, prepare a mapped image, and modify a function entry in that process.

The captured function entry changed from its original bytes to a temporary branch. The branch redirected execution to a trampoline associated with the mapped image. Captured context state recorded completion, and subsequent observations showed restoration of the original function bytes. The payload remained mapped after the temporary redirection ended.

These observations explain the security impact in concrete terms: physical memory access can support modification of process code and redirection of its execution. A process may therefore be modified even when the loader's access path does not use the usual process-memory APIs. For defenders, the driver load, mapped image, and transient code change are parts of the same event.

The execution evidence comes from captures of the investigated loader. The separate local driver check recorded successful loading and a rejected, unsupported device request. That limited check establishes device reachability in that laboratory session; it does not establish access from an unprivileged account or independently reproduce a privilege escalation.

## Relationship to published vulnerabilities

DirectIo64 physical memory access was already publicly documented before this investigation. In particular, [CVE-2025-52347](https://github.com/CVEProject/cvelistV5/blob/main/cves/2025/52xxx/CVE-2025-52347.json) describes kernel memory access through the same mapping interface identified in the recovered driver. Its [original researcher disclosure](https://github.com/netero1010/Vulnerability-Disclosure/tree/main/CVE-2025-52347) explains the resulting exposure to callers with low privileges in the affected products.

Additional published issues in this driver family include [CVE-2026-80112](https://www.vulncheck.com/advisories/passmark-performancetest-burnintest-and-osforensics-improper-access-control-via-directio64-sys), concerning access control on the device, and [CVE-2026-80114](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/80xxx/CVE-2026-80114.json), concerning authentication of physical memory writes. Those records provide context; they are not a claim that every listed issue has been verified against this exact extracted binary.

PassMark's [PerformanceTest release history](https://www.passmark.com/products/performancetest/history.php) records a restriction on non-administrator access in build 11.1.1005, released on June 11, 2025, and a further DirectIO security update in build 11.1.1012, released on June 22, 2026.

Using a known memory-access weakness to redirect a process function demonstrates a consequence of that weakness. It does not, by itself, identify a separately fixable vulnerability that would warrant another CVE. Any request for a new identifier would need to distinguish the affected implementation and root cause from these earlier disclosures.

## Defensive significance

The recovered driver is a useful indicator because its hash survives renaming by a loader. Monitoring should connect driver-load events and signer information with changes to executable pages in processes. A check performed only after a transient branch has been restored may miss the code change visible in the capture.

Administrators should use supported, updated versions of the affected products and review Microsoft's [vulnerable driver blocklist guidance](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules). A sample's ability to load in one laboratory configuration does not establish its behavior under other Windows, HVCI, or application-control policies.

The original driver and captures remain evidence for this investigation. This publication provides the sample identity, the observed behavior, and the relationship to earlier disclosures without distributing the driver or an operational injection procedure.

## Research credit

**Youssef Mekkaoui** conducted this independent loader and driver analysis. Credit for the previously published vulnerabilities remains with the researchers acknowledged in their original disclosures. This case study has no newly assigned CVE identifier.
