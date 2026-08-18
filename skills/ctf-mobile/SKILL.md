---
name: ctf-mobile
description: Mobile CTF workflow. Use for Android APK/AAB, iOS IPA, mobile app source, native libraries, hardcoded secrets, storage issues, exported components, Frida-style dynamic analysis planning, and mobile network traffic.
---

# CTF Mobile

## Workflow

1. Identify platform, package metadata, permissions, exported components, native libraries, and bundled assets.
2. Extract low-cost evidence: manifest, strings, resources, certificates, config files, and obvious endpoints.
3. Decompile or inspect code paths for flag construction, crypto misuse, API keys, debug logic, and root/emulator checks.
4. Plan dynamic hooks only after static evidence identifies a target function or storage location.
5. Check local files and network traces for recovered tokens or flags.

## Evidence Rules

Record artifact path, package identifier, class/function, resource key, endpoint, and command output. Do not confirm a secret as a flag without matching format or challenge response.

## Output

Return app metadata, suspicious code/resources, candidate flags, tool outputs, and next actions such as "hook validation method" or "inspect native library".
