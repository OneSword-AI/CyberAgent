# Repository Guidelines

## Project Structure & Module Organization

CyberAgent is a Python `src/` layout project. Core package code lives in `src/cyberagent/`.

- `src/cyberagent/graph.py`: LangGraph workflow construction and initial state.
- `src/cyberagent/models.py`: shared `ChallengeState` definitions.
- `src/cyberagent/llm.py`: OpenAI-compatible chat model configuration.
- `src/cyberagent/agents/`: agent nodes, including rule and LLM classifiers.
- `src/cyberagent/providers/`: challenge data providers and normalization.
- `tests/`: pytest test suite.
- `docs/` and `ARCHITECTURE.md`: design notes and flow diagrams.

Do not commit secrets from `.env`; use `.env.example` for documented configuration.

## Build, Test, and Development Commands

```bash
uv sync
```
Install project and development dependencies from `pyproject.toml` and `uv.lock`.

```bash
uv run cyberagent <challenge_id>
```
Run the CLI entry point against a configured challenge provider.

```bash
uv run pytest
```
Run the full default test suite. Real LLM tests are skipped unless explicitly enabled.

```bash
RUN_LLM_INTEGRATION_TESTS=1 uv run pytest tests/test_llm_classifier.py -s
RUN_LLM_ANALYSIS_TESTS=1 uv run pytest tests/test_llm_challenge_analysis.py -s
```
Run real model integration checks and print model analysis output.

## Coding Style & Naming Conventions

Use Python 3.14 syntax, 4-space indentation, and type hints for public functions. Prefer small, pure LangGraph node functions shaped as:

```python
def node_name(state: ChallengeState) -> ChallengeState:
    ...
```

Use snake_case for modules, functions, variables, and test names. Keep provider logic focused on fetching raw data; put field recognition in `providers/normalizer.py`; put prompt and model parsing logic in agent modules.

## Testing Guidelines

Tests use `pytest`. Name files `tests/test_*.py` and functions `test_*`. Default tests must not require network access or real API keys. For real LLM/API behavior, guard tests with environment variables and keep printed output useful for debugging.

## Commit & Pull Request Guidelines

Recent commits use Conventional Commits with Chinese descriptions, for example:

- `feat: 实现大模型题目分类节点`
- `fix: 不限制题目分类，添加Other类型`
- `tests: 添加真实大模型调用测试`

Keep commits atomic. PRs should include a short summary, test commands run, configuration changes, and any relevant architecture impact. Link related issues when available.

## Security & Configuration Tips

Configure LLM and challenge providers through environment variables. For DeepSeek-compatible usage:

```env
OPENAI_BASE_URL=https://api.deepseek.com/v1
OPENAI_MODEL=deepseek-chat
```

Never print API keys in tests, logs, or documentation.
