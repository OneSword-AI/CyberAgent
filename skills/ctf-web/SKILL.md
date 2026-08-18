---
name: ctf-web
description: Web CTF challenge triage and active interaction workflow. Use for HTTP/HTTPS targets, web source code, login/forms, API endpoints, cookies, SSRF, SQL injection, SSTI, LFI/RFI, upload, path traversal, auth bypass, and response-based flag extraction.
---

# CTF Web

## Workflow

1. Normalize targets: identify base URL, exposed ports, path hints, credentials, cookies, and source files.
2. Establish baselines with bounded GET requests for `/`, common paths, linked resources, and obvious endpoints.
3. Detect forms, links with parameters, APIs, redirects, status changes, cookies, and response length changes.
4. Try limited active probes: form submission, SQL error payloads, SSTI arithmetic, path traversal, LFI markers, and simple auth bypass values.
5. Extract candidate flags from every response body and relevant headers.

## Evidence Rules

Record URL, method, payload, status, body length, response markers, and extracted flag source. Treat memory or known challenge patterns as hints only. Do not confirm a flag without direct response evidence.

## Output

Return structured findings, candidate flags, tool outputs, and next actions. If no flag is found, publish the most suspicious endpoint or parameter for follow-up instead of repeating the same probes.
