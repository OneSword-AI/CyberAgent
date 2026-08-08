# Repository Guidelines

## Project Structure & Module Organization

CyberAgent is a Python `src/` layout project. Core package code lives in `src/cyberagent/`.

- `graph.py`: LangGraph workflow, conditional routing, `Send` fan-out, and initial state.
- `models.py`: shared `ChallengeState` and `SpecialistResult` contracts.
- `agents/`: controller, router, specialists, foundation signal agents, flag/evidence/retry nodes.
- `agents/tool_adapters.py`: replaceable Web/Crypto/Misc specialist tool adapter boundary.
- `providers/`: challenge data providers plus raw-field normalization.
- `tools/`: low-level HTTP, shell, filesystem, registry, and L0 safety-wrapped execution helpers.
- `tests/`: pytest suite. Design docs live in `docs/` and `ARCHITECTURE.md`.

Do not commit `.env`, API keys, challenge secrets, or generated run artifacts.

## Build, Test, and Development Commands

```bash
uv sync
```
Install project and development dependencies from `pyproject.toml` and `uv.lock`.

```bash
uv run cyberagent <challenge_id>
uv run cyberagent <challenge_id> --save --output-dir runs
```
Run the CLI against the configured provider, optionally saving `state.json`.

```bash
uv run pytest
```
Run the default offline test suite. Real LLM tests are opt-in:

```bash
RUN_LLM_INTEGRATION_TESTS=1 uv run pytest tests/test_llm_classifier.py -s
RUN_LLM_ANALYSIS_TESTS=1 uv run pytest tests/test_llm_challenge_analysis.py -s
```

## Coding Style & Naming Conventions

Use Python 3.14, 4-space indentation, and type hints for public functions. Use `snake_case` for modules, functions, variables, and tests. Keep LangGraph nodes small and shaped as `def node(state: ChallengeState) -> ChallengeState`. Specialist Agents should return `SpecialistResult`; use registry adapters to merge results back into state.

## Testing Guidelines

Tests use `pytest`; name files `tests/test_*.py` and functions `test_*`. Default tests must not require network access, real CTF services, or API keys. Use monkeypatching or custom adapters for tool behavior. Guard real LLM/API checks with environment variables and print only non-secret diagnostics.

## Commit & Pull Request Guidelines

Recent commits use Conventional Commits with Chinese descriptions, for example `feat: 接入专科工具Adapter` and `fix: 不限制题目分类，添加Other类型`. Keep commits atomic. PRs should include summary, tests run, config changes, and architecture impact. Link issues when available.

## Security & Configuration Tips

Configure providers and LLMs through environment variables. DeepSeek-compatible example:

```env
OPENAI_BASE_URL=https://api.deepseek.com/v1
OPENAI_MODEL=deepseek-chat
```

Keep external actions behind tool adapters and L0 safety checks where applicable.
