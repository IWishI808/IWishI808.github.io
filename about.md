---
layout: page
title: About
permalink: /about/
---

Security researcher focused on building defensive tools at the lowest layers of the system: hypervisors, kernel structures, and binary internals.

## What I Work On

Most of my time goes into two areas: hypervisor-based security (using Intel VT-x and EPT to enforce memory integrity below the OS) and Windows detection engineering (finding injected code through CRT analysis, vtable integrity checks, and PEB monitoring).

I also spend a lot of time in IDA Pro, reconstructing C++ class hierarchies and tracing control flow in stripped binaries. The reverse engineering work feeds directly into the detection tools: you can't detect a technique if you don't understand exactly how it works at the binary level.

## Tools

IDA Pro, WinDbg, x64dbg, Ghidra, Visual Studio, Hyper-V, Process Monitor, Volatility, Sysmon, ETW

## Focus Areas

- Hypervisor security (Intel VT-x, EPT, VMCS)
- DLL injection detection and CRT/NoCRT analysis
- Windows kernel internals and PEB forensics
- Vtable integrity and COM interface monitoring
- C++ binary structure reconstruction

## Contact

- GitHub: [IWishI808](https://github.com/IWishI808)
