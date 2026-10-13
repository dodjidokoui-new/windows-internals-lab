# windows-internals-lab

> Hands on journey into WIndows internals : building real red team and blue team skills and a deep understanding
> Each lab = commented code/steps + visual + offensive and defensive persepective
> Isolated VM on proxmox, no binary executed outside of this controlled environment

## Goals

- Understand Windows core internals (processes, threads, memory, handles, tokens, ...)
- Implement classic and advanced injection techniques **from scratch**
- Systematically try to answer these question : **How do we detect this ?**, **How to bypass modern detection solutions ?**
- Share this work with the security community and get feedback

## Progress

| # | Lab | Status | Key Techniques/Tools |
|---|-----|--------|----------------|
| 1.1 | Process Anatomy | In Progress | Process Hacker, handles, DACL |

## Environment 

| Component | Config |
|-----------|--------|
| Hypervisor | Proxmox (Beelink EQR5, 16 GB RAM, 512 SSD) |
| Lab VM | Windows 11 Enterprise · 8 GB RAM · 4 vCPU · logically isolated network |
| Isolation | No physical NIC — temporary internet via vmbr0 switch only |

## Legal 

All manipulation are performed exclusively inside an isolated VM, on self-written binaries.
**Absolute rule: if the binary is not mine, I do not inject.**
This repository is for **educational purposes only.**

