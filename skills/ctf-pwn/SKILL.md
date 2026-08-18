---
name: ctf-pwn
description: Binary exploitation CTF workflow. Use for ELF binaries, libc/ld files, remote nc services, stack overflow, heap exploitation, format string, ROP, shellcode, sandbox escape, and exploit script planning.
---

# CTF Pwn

## Workflow

1. Inventory artifacts: binary, libc, loader, source, remote host, port, architecture, and protection flags.
2. Run static triage: file type, symbols, strings, checksec, imports, interesting functions, and obvious input paths.
3. Run controlled dynamic checks: sample inputs, crash reproduction, offsets, leaks, and protocol framing.
4. Choose an exploit path: ret2win, ROP, ret2libc, format string write/read, heap primitive, or shellcode.
5. Build a minimal reproducible exploit with clear local and remote modes.

## Evidence Rules

Record crash input, offset, leaked address, calculated base, gadget/source line, and final service response. Do not accept a guessed flag without process or remote output evidence.

## Output

Return exploit hypothesis, required primitives, tool outputs, candidate flags, and next actions such as "need libc leak" or "need heap primitive validation".
