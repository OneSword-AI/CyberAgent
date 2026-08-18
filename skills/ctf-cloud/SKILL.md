---
name: ctf-cloud
description: Cloud and container CTF workflow. Use for cloud metadata services, object storage, IAM policy mistakes, Kubernetes, Docker/container escape clues, serverless configs, leaked credentials, CI/CD artifacts, and cloud-hosted challenge infrastructure.
---

# CTF Cloud

## Workflow

1. Identify cloud surface: URLs, buckets, metadata endpoints, container files, kube configs, tokens, IAM hints, and CI variables.
2. Inspect local artifacts before remote actions: Dockerfiles, compose files, manifests, policies, environment references, and build logs.
3. For network targets, use bounded requests and avoid destructive operations.
4. Validate permissions with read-only checks first: list, get, describe, or metadata fetch when safe.
5. Trace privilege paths only from evidence: role assumption, token audience, bucket policy, service account, or mounted secret.

## Evidence Rules

Record endpoint, credential source, permission result, object path, policy snippet, and returned data. Never print or commit live credentials.

## Output

Return cloud surface map, read-only evidence, candidate flags, risk notes, and next actions for missing provider-specific tooling.
