---
name: ctf-misc
description: Miscellaneous CTF workflow. Use for puzzles, encodings, esolangs, QR/barcodes, protocol oddities, jail/sandbox tasks, game logic, math puzzles, constrained shell tasks, and challenges that do not fit Web/Pwn/Crypto/Reverse/Forensics.
---

# CTF Misc

## Workflow

1. Inventory all inputs: text, attachments, remote endpoints, prompts, transcripts, and hidden formatting.
2. Classify the puzzle type: encoding stack, protocol, jail, game, math, automation, or file trick.
3. Try reversible, evidence-backed transforms first: base encodings, compression, archive nesting, OCR/barcode decoding, and simple cipher checks.
4. For interactive tasks, model the protocol and automate only bounded interactions.
5. Escalate to another specialist when strong evidence points to Web, Crypto, Pwn, Reverse, or Forensics.

## Evidence Rules

Record each transform, command, input, output, and why the next step follows. Avoid long blind decoding chains without markers.

## Output

Return the classification, transform chain, candidate flags, tool outputs, and next actions for the most likely specialist or interaction path.
