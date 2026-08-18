---
name: ctf-osint
description: OSINT CTF workflow. Use for public-source investigation, usernames, domains, images, maps, social media clues, leaked metadata, timestamps, geolocation, archived pages, and source validation.
---

# CTF OSINT

## Workflow

1. Extract entities: usernames, domains, handles, emails, image metadata, coordinates, timestamps, languages, and visible landmarks.
2. Prefer primary or archived sources. Record exact URLs, capture dates, and query terms.
3. Cross-check identity and timeline claims across independent sources.
4. For images, separate metadata evidence from visual geolocation evidence.
5. Normalize final answers to the expected flag format only after confirming the underlying fact.

## Evidence Rules

Do not treat a single search result snippet as proof. Record source URL, observed fact, access time when relevant, and the reasoning link to the answer.

## Output

Return entities, verified facts, candidate flag values, confidence, source links, and next actions for missing corroboration.
