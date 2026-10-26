# windows-internals-lab

> Hands-on journey into Windows internals: building real red team and blue team skills through deep understanding.
> Each lab = commented code + visuals + offensive **and** defensive perspective.
> Isolated VM on Proxmox — no binary executed outside this controlled environment.

---

## Goals

- Understand Windows core internals (processes, threads, memory, handles, tokens, DACLs …)
- Implement classic and advanced injection techniques **from scratch**
- Systematically answer: **How do we detect this?** and **How do modern defenses respond?**
- Share this work with the security community and get feedback

---

## Progress

| # | Lab | Folder | Status | Key Techniques / Tools |
|---|-----|--------|--------|------------------------|
| 1.1 | Process Anatomy | `01-process-anatomy/` | Done | Process Hacker, handles, access rights, DACL |
| 1.2 | First Debugger | `02-first-debugger/` | Done | x64dbg, breakpoints, stack, registers, call stack |
| 1.3 | Toolhelp32 | `03-toolhelp32/` | Done | CreateToolhelp32Snapshot, PROCESSENTRY32 |
| 2.1 | DLL Injection — DLL | `04-dll-injection/` | Done | DllMain, LoadLibrary, OutputDebugString |
| 2.2 | DLL Injection — Injector | `04-dll-injection/` | Done | OpenProcess (minimal rights), VirtualAllocEx, WriteProcessMemory, CreateRemoteThread |
| 2.2+ | NtCreateThreadEx (challenge) | `04-dll-injection/` | Done | Undocumented NT API, direct syscall path, comparison with CreateRemoteThread |
| 2.3 | Defensive Observation | `05-defensive-observation/` | Done | Sysmon Event 8 / Event 7, SOC perspective, IOC mapping |
| 3.1 | Shellcode from scratch | `06-shellcode/` | Next | PIC shellcode, manual API resolution, no imports |
| 3.2 | Injection Variants | `07-injection-variants/` |  Planned | QueueUserAPC, SetWindowsHookEx, CRT — Sysmon diff |
| 3.3 | Thread Hijacking / Early Bird | `08-thread-hijacking/` | Planned | CREATE_SUSPENDED, GetThreadContext / SetThreadContext, ctx.Rip |
| 3.4 | Shellcode Encoding | `09-shellcode-encoding/` | Planned | XOR encoder/decoder, in-memory IOC reduction |
| 4.1 | Reflective DLL Injection | `10-reflective-dll/` | Planned | Self-loading DLL, IAT resolution, relocations |
| 4.2 | Process Hollowing | `11-process-hollowing/` | Planned | NtQueryInformationProcess, PEB+0x10, entry point overwrite |
| 4.3 | AMSI — Understand, not patch | `12-amsi/` | Planned | AMSI.dll internals, IAT hooks, scanning pipeline |
| 5.1 | RWX Detector | `13-rwx-detector/` | Planned | Custom C/Rust tool, RWX region / out-of-module thread detection |
| 5.2 | Malware Analysis | `14-malware-analysis/` | Planned | MalwareBazaar sample, sandbox, DFIR-style report |
| 5.3 | Capstone | `15-capstone/` | Planned | Mini red/blue lab, detection + response, end-of-study project |

---

## MITRE ATT&CK Coverage

| Technique | ID | Labs |
|-----------|----|------|
| Process Discovery | T1057 | 1.3 |
| Dynamic-link Library Injection | T1055.001 | 2.1, 2.2 |
| Thread Execution Hijacking | T1055.003 | 3.3 |
| Asynchronous Procedure Call | T1055.004 | 3.2 |
| Process Hollowing | T1055.012 | 4.2 |
| Reflective Code Loading | T1620 | 4.1 |
| Obfuscated Files or Information | T1027 | 3.4 |
| Impair Defenses: AMSI Bypass | T1562.001 | 4.3 |

---

## Environment

| Component | Config |
|-----------|--------|
| Hypervisor | Proxmox (Beelink EQR5 ; 16 GB RAM, 512 GB SSD) |
| Lab VM | Windows 11 Enterprise · 8 GB RAM · 4 vCPU · logically isolated network |
| Snapshots | `clean-baseline` after OS install · `pre-lab` before each manipulation |
| Isolation | No physical NIC, temporary internet via vmbr0 switch only, then reverted |

---

## Each Lab Follows This Structure

```
XX-lab-name/
├── README.md        ← theory, mechanisms, "why it works"
├── src/             ← commented source code (hand-typed, not copy-pasted)
├── screenshots/     ← execution proof, Sysmon events, debugger views
└── detection/       ← Sysmon config, Sigma rules, SOC perspective
```

---

## Legal

All manipulations are performed exclusively inside an isolated VM, on self-written binaries.  
**Absolute rule: if the binary is not mine, I do not inject.**  
This repository is for **educational purposes only.**  