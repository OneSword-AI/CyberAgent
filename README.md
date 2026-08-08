# CyberAgent

CyberAgent is a LangGraph-based CTF solving agent prototype. It reads challenge metadata from a pluggable provider, asks a controller Agent to plan the solving path, dispatches specialist Agents in parallel, publishes specialist results back to a blackboard signal stream, and then extracts/verifies candidate flags.

## Current Architecture

```text
fetch_challenge
  -> download_attachments
  -> foundation_agents
  -> controller_agent
  -> route_agent
  -> Send(web/pwn/reverse/crypto/misc/forensics/other)
  -> publish_specialist_results
  -> controller_agent
  -> ...bounded feedback rounds...
  -> extract_candidate_flags
  -> evidence_gate
  -> verify_flag / retry_agent
```

Key implementation points:

- `controller_agent` uses an OpenAI-compatible LLM and falls back to rule classification when unavailable.
- Specialist Agents return normalized `SpecialistResult` objects instead of mutating graph state directly.
- Web, Crypto, and Misc call replaceable specialist tool Adapters; default Crypto/Misc adapters are MVP placeholders.
- Specialist results are published as `specialist_result` blackboard signals for the controller to consume in the next planning round.
- `max_controller_rounds` bounds feedback dispatch cycles; retry resets the controller round.

## Project Layout

```text
src/cyberagent/
├── graph.py                  # LangGraph workflow and initial ChallengeState
├── models.py                 # ChallengeState and SpecialistResult contracts
├── runtime.py                # run_challenge(...) runtime wrapper
├── llm.py                    # OpenAI-compatible chat model configuration
├── blackboard.py             # in-memory signal store and leases
├── signals.py                # structured blackboard signal schema
├── agents/                   # controller, router, specialists, evidence/flag nodes
├── providers/                # challenge providers and normalization
└── tools/                    # tool adapter registry and basic HTTP/shell/file tools
```

Tests live in `tests/`. Design notes and Excalidraw source live in `docs/` and `ARCHITECTURE.md`.

## Setup

```bash
uv sync
cp .env.example .env
```

Run the CLI against a configured provider:

```bash
uv run cyberagent <challenge_id>
uv run cyberagent <challenge_id> --save --output-dir runs
```

## Provider Configuration

Local JSON provider:

```env
CHALLENGE_PROVIDER=local_json
CHALLENGE_LOCAL_JSON_DIR=./challenges
```

HTTP JSON provider:

```env
CHALLENGE_PROVIDER=http_json
CHALLENGE_API_BASE_URL=https://ctf.example.com/api
CHALLENGE_API_PATH_TEMPLATE=/challenges/{challenge_id}
CHALLENGE_API_TOKEN=replace-me
CHALLENGE_API_AUTH_SCHEME=Bearer
CHALLENGE_API_TIMEOUT=20
```

Example local challenge:

```json
{
  "title": "easy web",
  "description": "Find the SQL injection.",
  "category": "Web",
  "attachments": ["attachment.zip"],
  "remote_targets": ["http://example.test"]
}
```

## LLM Configuration

CyberAgent uses an OpenAI-compatible Chat API. DeepSeek example:

```env
OPENAI_API_KEY=your-deepseek-api-key
OPENAI_BASE_URL=https://api.deepseek.com/v1
OPENAI_MODEL=deepseek-chat
OPENAI_TEMPERATURE=0
OPENAI_TIMEOUT=60
OPENAI_MAX_RETRIES=2
```

For another OpenAI-compatible service, usually replace `OPENAI_API_KEY`, `OPENAI_BASE_URL`, and `OPENAI_MODEL`.

## Tests

```bash
uv run pytest
```

Real LLM tests are opt-in:

```bash
RUN_LLM_INTEGRATION_TESTS=1 uv run pytest tests/test_llm_classifier.py -s
RUN_LLM_ANALYSIS_TESTS=1 uv run pytest tests/test_llm_challenge_analysis.py -s
PRINT_LLM_CLASSIFICATION_PROMPT=1 uv run pytest tests/test_llm_classifier.py::test_print_llm_classification_prompt -s
```

## Extension Points

- Add new providers in `src/cyberagent/providers/` and register them in `providers/registry.py`.
- Add field recognition in `providers/normalizer.py`, not inside provider fetchers.
- Add specialist tool integrations through `agents/tool_adapters.py` or a compatible `SpecialistToolAdapter` implementation.
- Add new specialist nodes through `agents/specialists.py` and `agents/registry.py`.
- Keep external actions behind tool adapters and L0 safety checks where applicable.

## Development Notes

- Use atomic Conventional Commits, preferably Chinese descriptions such as `feat: 接入专科工具Adapter`.
- Do not commit `.env` or API keys.
- Default tests must not require network access or real credentials.
