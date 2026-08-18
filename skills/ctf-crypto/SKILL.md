---
name: ctf-crypto
description: Cryptography CTF workflow. Use for encryption or signing code, RSA/ECC, AES modes, stream ciphers, hash/MAC issues, lattices, padding oracles, weak randomness, encoding layers, and custom protocols.
---

# CTF Crypto

## Workflow

1. Extract scheme details: algorithm, parameters, public values, ciphertexts, signatures, oracle access, and source code.
2. Classify the failure mode before attacking: small RSA exponent, shared primes, nonce reuse, ECB/CBC misuse, padding oracle, length extension, weak RNG, or custom algebra.
3. Preserve exact byte encodings. Distinguish hex, base64, decimal integers, little endian, and text.
4. Build the smallest script that reproduces encryption/decryption or verification.
5. Validate recovered plaintext or key material against the challenge format.

## Evidence Rules

Record parameters, equations, oracle transcript, recovered key/plaintext, and decoding steps. Memory can suggest attacks but must not be the proof.

## Output

Return attack classification, derivation notes, scripts or formulas used, candidate flags, and missing data if the challenge needs more oracle interaction.
