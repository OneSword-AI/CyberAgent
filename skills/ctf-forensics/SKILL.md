---
name: ctf-forensics
description: Digital forensics CTF workflow. Use for PCAPs, disk images, memory dumps, logs, documents, images, archives, carved files, metadata, timeline analysis, steganography-adjacent artifacts, and evidence extraction.
---

# CTF Forensics

## Workflow

1. Preserve artifact paths and hashes before analysis when possible.
2. Identify file types, container layers, embedded files, compression, encryption, metadata, and timestamps.
3. Extract low-cost evidence first: file, strings, exiftool-style metadata, archive listings, binwalk-like signatures, and PCAP conversations.
4. Follow recovered indicators into focused analysis: carved files, credentials, HTTP objects, DNS queries, clipboard data, process memory, or document macros.
5. Decode candidate data through common encodings only when evidence supports it.

## Evidence Rules

Record source artifact, extraction command, offset/path/stream, decoded value, and final flag location. Keep intermediate artifacts under the run artifacts directory.

## Output

Return evidence chain, extracted files, candidate flags, and next actions for missing passwords, encrypted archives, or deeper memory/network analysis.
