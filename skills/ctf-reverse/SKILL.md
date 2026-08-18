---
name: ctf-reverse
description: Reverse engineering CTF workflow. Use for binaries, bytecode, packed programs, license checks, crackmes, obfuscated validation logic, VM challenges, firmware snippets, and static or dynamic analysis tasks.
---

# CTF Reverse

## Workflow

1. Identify format, architecture, symbols, strings, imports, packers, and runtime dependencies.
2. Locate validation logic using strings, xrefs, main/init functions, comparison sites, and error/success messages.
3. Recover constraints from code paths, tables, transforms, and byte operations.
4. Prefer solving constraints or reimplementing check logic over manual guessing.
5. Confirm the recovered input locally when the binary can be executed safely.

## Evidence Rules

Record file metadata, relevant functions, constants, transforms, constraints, and validation output. Do not treat a decompiled guess as final without a local check or direct evidence.

## Output

Return recovered algorithm, candidate input or flag, confidence, supporting tool outputs, and next actions such as "needs debugger trace" or "needs unpacking".
