# Syscall-Invoker (PoC)

**Syscall-Invoker** is a proof-of-concept project originally inspired by syscall spoofing techniques from around **2017–2020**. This implementation has been revisited and cleaned up in **2025** to improve clarity, modularity, and cross-platform (x86/x64) support — but the underlying idea remains the same.

## Overview

This project demonstrates a working proof-of-concept for indirect syscalls — a technique that emerged around 2017–2020, allowing direct system call invocation without relying on user-mode API (e.g., Nt*, Zw*, or WinAPI).

The approach avoids direct `syscall` or `int 0x2e` usage and instead performs:
- Manual syscall invocation via syscall stubs from modules like ntdll.dll, skipping the prologue to avoid hooks (e.g., skipping first 5–8 bytes).
- Return address spoofing by manipulating the stack and using gadgets (e.g., jmp rdi) to obfuscate both:
  - the return address used during the syscall,
  - and the return address that leads back to the caller.
- Dynamic parameter pushing, supporting both register-based and stack-based calling conventions (x64: R10/RDX/R8/R9 + stack; x86: full stack).
- XOR obfuscation of return addresses using user-supplied keys.
- Full control over syscall SSN, gadget, and return target, allowing any syscall to be issued from any valid syscall instruction stub.

## How It Works

1. The syscall stub is located in `ntdll.dll` via `GetProcAddress`.
2. A simple "gadget" (like `jmp rdi`) is located in `kernel32.dll` to hijack control flow.
3. A return address is faked (e.g., to `VirtualAlloc`) for stack/return spoofing.
4. Parameters are passed in register/stack (depending on architecture) via `invoke_syscall`.

## Modern Limitations

**EDRs (as of 2023–2025)** are fully capable of detecting spoofed return addresses via:
- Return address integrity checks.
- ROP gadget detection heuristics.
- Kernel ETW + syscall tracing.

For **more realistic testing**, consider implementing full **call stack manipulation** (e.g., stack pivoting or call emulation) instead of relying on spoofed addresses alone.

## Legal Notice
This code is published for educational and research purposes only. Use it responsibly and only in controlled environments (e.g., malware lab, red teaming testbeds).