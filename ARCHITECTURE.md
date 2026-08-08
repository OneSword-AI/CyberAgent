# CyberAgent Architecture

## Overview

CyberAgent is a LangGraph CTF-solving agent prototype. The current system is not a full autonomous solver yet; it provides the runtime skeleton for challenge ingestion, controller planning, parallel specialist dispatch, blackboard feedback, evidence gating, local flag verification, retries, and state persistence.

## File Organization

```text
CyberAgent/
├── README.md
├── AGENTS.md
├── ARCHITECTURE.md
├── docs/
│   ├── cyberagent-langgraph-flow.excalidraw
│   └── cyberagent-langgraph-flow.md
├── src/cyberagent/
│   ├── __init__.py              # CLI entry point
│   ├── graph.py                 # LangGraph nodes, edges, reducers, initial state
│   ├── runtime.py               # run_challenge(..., save=True, output_dir=...)
│   ├── models.py                # ChallengeState and SpecialistResult
│   ├── llm.py                   # OpenAI-compatible LLM factory
│   ├── blackboard.py            # structured signal store and short leases
│   ├── signals.py               # signal schema and visibility helpers
│   ├── evidence.py              # finding/evidence helpers
│   ├── evidence_gate.py         # evidence gate predicate
│   ├── flag.py                  # default flag format validation
│   ├── checkpoint.py            # state.json persistence
│   ├── trace.py                 # trace event helper
│   ├── agents/
│   │   ├── controller.py        # LLM controller with rule fallback
│   │   ├── router.py            # active specialist selection
│   │   ├── specialists.py       # Web/Pwn/Reverse/Crypto/Misc/Forensics/Other agents
│   │   ├── tool_adapters.py     # replaceable Web/Crypto/Misc adapter boundary
│   │   ├── specialist_signals.py# publish SpecialistResult to blackboard signals
│   │   ├── foundation.py        # observer/analyst/critic/memory signal agents
│   │   ├── foundation_node.py   # foundation agent execution node
│   │   ├── flag_extractor.py    # candidate flag extraction from findings/tools
│   │   ├── flag_verifier.py     # local flag format validation
│   │   ├── evidence_gate.py     # graph node wrapper for evidence gate
│   │   └── retry.py             # failed attempt recording and retry scheduling
│   ├── providers/
│   │   ├── base.py              # provider contract and normalized challenge type
│   │   ├── fetch.py             # graph fetch node
│   │   ├── local_json.py        # local JSON provider
│   │   ├── http_json.py         # HTTP JSON provider
│   │   ├── normalizer.py        # raw field recognition and normalization
│   │   └── registry.py          # provider selection
│   └── tools/
│       ├── adapter.py           # generic low-level ToolAdapter registry
│       ├── defaults.py          # default HTTP/shell/file tools with L0 safety
│       ├── http.py              # bounded HTTP/HTTPS helpers
│       ├── shell.py             # shell execution wrapper
│       ├── filesystem.py        # file inspection helper
│       └── executor.py          # normalized tool output recording
└── tests/
```

## Current Runtime Flow

```text
challenge_id
  -> fetch_challenge
  -> download_attachments
  -> foundation_agents
  -> controller_agent
  -> route_agent
  -> Send(active specialist agents)
  -> publish_specialist_results
  -> controller_agent
  -> repeat until max_controller_rounds is reached
  -> extract_candidate_flags
  -> evidence_gate
  -> verify_flag or retry_agent
```

Important details:

- `fetch_challenge` calls the selected provider and writes normalized metadata into `ChallengeState`.
- `foundation_agents` creates initial `challenge_input`, `observation`, `memory_prior`, `hypothesis`, and `critic_report` signals.
- `controller_agent` reads challenge metadata and signals, asks the LLM for a JSON plan, and falls back to rule classification if LLM configuration or parsing fails.
- `route_agent` selects `active_agents` from controller output or category mapping.
- LangGraph `Send` dispatches selected specialists in parallel.
- Specialist nodes return `SpecialistResult`; the registry adapter merges results into state.
- `publish_specialist_results` emits `specialist_result` signals back to the blackboard snapshot for the controller.
- `controller_round` and `max_controller_rounds` bound feedback dispatch cycles.
- `retry_agent` records failed attempts and resets the controller round for a new bounded pass.

## State Contracts

`ChallengeState` is the shared LangGraph state. Core fields include:

- Challenge input: `challenge_id`, `title`, `description`, `attachments`, `downloaded_attachments`, `remote_targets`, `flag_format`, `category_hint`, `raw_challenge`.
- Controller planning: `predicted_categories`, `next_agents`, `active_agents`, `plan`, `plan_rationale`, `controller_decisions`, `controller_round`, `max_controller_rounds`, `stop_condition`.
- Results: `specialist_results`, `candidate_flags`, `verification_results`, `final_flag`, `failed_attempts`, `findings`, `tool_outputs`.
- Coordination: `signals`, `published_specialist_results`, `trace`, `evidence_gate_passed`.

`SpecialistResult` is the normalized return type for specialist Agents:

```python
{
    "agent": "web_agent",
    "status": "completed",  # completed | skipped | failed
    "summary": "...",
    "findings": [],
    "candidate_flags": [],
    "tool_outputs": [],
    "next_actions": [],
}
```

## Blackboard Signals

Signals are structured messages with type, source, payload, provenance, status, parent IDs, and optional recipients. The current signal types include:

- `challenge_input`
- `observation`
- `hypothesis`
- `memory_prior`
- `critic_report`
- `feedback`
- `evidence`
- `specialist_result`

The blackboard supports short leases to avoid duplicate processing. In the current graph, signals are persisted as `ChallengeState["signals"]`; `Blackboard(...)` can reconstruct a local board from that snapshot.

## Specialist Tool Adapters

Specialist Agents do not hardcode domain tooling. Web, Crypto, and Misc use `SpecialistToolAdapter` implementations from `agents/tool_adapters.py`.

- `WebToolAdapter` currently performs a bounded `http_get` against the first remote target.
- `PlaceholderToolAdapter` provides MVP boundaries for Crypto and Misc until real tools are added.
- Custom adapters can be registered in `SpecialistToolAdapterRegistry` and injected in tests or future runtime wiring.

This keeps Agent orchestration separate from scanner/exploit implementations.

## Provider Extension

Providers return raw dictionaries. Field recognition belongs in `providers/normalizer.py`.

To add a provider:

1. Create `src/cyberagent/providers/custom_platform.py`.
2. Implement `fetch(challenge_id) -> dict[str, Any]`.
3. Register the provider in `providers/registry.py`.
4. Add tests using local fixtures and no real credentials.

## Current Gaps

The orchestration skeleton is functional, but the project is still an MVP:

- Pwn, Reverse, Forensics, and Other are placeholders.
- Crypto and Misc have adapter boundaries but no real solving tools.
- Evidence gating is basic and does not yet bind each candidate flag to a full proof chain.
- Report rendering exists but is not yet integrated into final runtime outputs.
- Docker sandboxing and real scanner integrations are intentionally deferred.
- Budget controls for time, token, request, and tool-call limits are not yet implemented.

## Verification

Run the default test suite:

```bash
uv run pytest
```

Real LLM tests require explicit environment flags and configured credentials.
