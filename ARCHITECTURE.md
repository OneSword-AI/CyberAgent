## 文件组织

当前项目采用 `src/` 布局，核心代码位于 `src/cyberagent/`：

```text
CyberAgent/
├── README.md
├── pyproject.toml
├── uv.lock
├── .env.example
├── docs/
│   ├── cyberagent-langgraph-flow.excalidraw
│   └── cyberagent-langgraph-flow.md
├── src/
│   └── cyberagent/
│       ├── __init__.py
│       ├── graph.py
│       ├── models.py
│       ├── agents/
│       │   ├── __init__.py
│       │   └── classifier.py
│       └── providers/
│           ├── __init__.py
│           ├── base.py
│           ├── fetch.py
│           ├── http_json.py
│           ├── local_json.py
│           ├── normalizer.py
│           └── registry.py
└── tests/
    └── test_providers.py
```

核心文件职责：

- `src/cyberagent/__init__.py`：命令行入口，读取 `challenge_id`，启动 LangGraph。
- `src/cyberagent/graph.py`：定义 LangGraph 流程，目前是 `fetch_challenge -> classify_challenge`。
- `src/cyberagent/models.py`：定义全局共享状态 `ChallengeState`。
- `src/cyberagent/agents/`：放 Agent 节点实现，例如分类 Agent、Web Agent、Pwn Agent 等。
- `src/cyberagent/agents/classifier.py`：当前的题目方向分类节点，现阶段使用关键词规则。
- `src/cyberagent/providers/`：放题目信息来源和标准化逻辑。
- `src/cyberagent/providers/base.py`：定义 provider 接口和标准化后的题目数据结构。
- `src/cyberagent/providers/fetch.py`：LangGraph 的题目信息获取节点，负责调用 provider 并写入 `ChallengeState`。
- `src/cyberagent/providers/http_json.py`：从 HTTP JSON 接口读取原始题目信息。
- `src/cyberagent/providers/local_json.py`：从本地 JSON 文件读取原始题目信息，适合开发和测试。
- `src/cyberagent/providers/normalizer.py`：把不同格式的原始题目信息统一转换为内部格式。
- `src/cyberagent/providers/registry.py`：根据配置选择具体 provider。
- `docs/`：项目设计文档和 Excalidraw 流程图。
- `tests/`：测试用例。

## 当前运行链路

当前最小链路如下：

```text
challenge_id
  -> fetch_challenge
  -> provider.fetch()
  -> normalize_challenge()
  -> classify_challenge
  -> 输出 ChallengeState
```

运行示例：

```bash
cp .env.example .env
uv run cyberagent 123
```

HTTP JSON provider 配置：

```env
CHALLENGE_PROVIDER=http_json
CHALLENGE_API_BASE_URL=https://ctf.example.com/api
CHALLENGE_API_PATH_TEMPLATE=/challenges/{challenge_id}
CHALLENGE_API_TOKEN=replace-me
CHALLENGE_API_AUTH_SCHEME=Bearer
CHALLENGE_API_TIMEOUT=20
```

本地 JSON provider 配置：

```env
CHALLENGE_PROVIDER=local_json
CHALLENGE_LOCAL_JSON_DIR=./challenges
```

本地题目文件示例：

```json
{
  "title": "easy web",
  "description": "Find the SQL injection.",
  "category": "Web",
  "attachments": ["attachment.zip"],
  "remote_targets": ["http://example.test"]
}
```

## 后续扩展方式

### 新增题目信息来源

如果要接入新的平台或数据来源，新建一个 provider：

```text
src/cyberagent/providers/custom_platform.py
```

provider 只负责返回原始 `dict`，不要在 provider 内写复杂识别逻辑：

```python
from typing import Any


class CustomPlatformProvider:
    name = "custom_platform"

    def fetch(self, challenge_id: str) -> dict[str, Any]:
        # 请求接口、读取数据库或读取文件
        return raw_payload
```

然后在 `src/cyberagent/providers/registry.py` 注册：

```python
providers = {
    HttpJsonProvider.name: HttpJsonProvider(),
    LocalJsonProvider.name: LocalJsonProvider(),
    CustomPlatformProvider.name: CustomPlatformProvider(),
}
```

### 扩展题目信息识别

不同平台返回的字段名可能不同，统一在 `src/cyberagent/providers/normalizer.py` 里处理。

例如新增字段兼容：

- 标题：`title`、`name`、`subject`
- 描述：`description`、`body`、`content`、`prompt`
- 附件：`attachments`、`files`、`downloads`
- 远程目标：`remote_targets`、`targets`、`services`、`connection_info`

后续可以继续扩展：

- HTML/Markdown 清洗。
- 从描述里提取 URL、`nc host port`、附件链接。
- 把远程目标解析成结构化对象。
- 识别 flag 格式、题目标签、分值、比赛 ID。

### 新增 Agent 节点

新增专科 Agent 时，在 `src/cyberagent/agents/` 下创建文件：

```text
src/cyberagent/agents/web.py
src/cyberagent/agents/crypto.py
src/cyberagent/agents/pwn.py
```

每个 Agent 节点应遵循同一个模式：

```python
from cyberagent.models import ChallengeState


def web_agent(state: ChallengeState) -> ChallengeState:
    findings = [
        *state.get("findings", []),
        {
            "agent": "web_agent",
            "summary": "发现登录接口可能存在 SQL 注入",
        },
    ]

    return {
        **state,
        "findings": findings,
    }
```

然后在 `src/cyberagent/graph.py` 中注册节点和边。

### 扩展 LangGraph 路由

当前图是线性的：

```text
fetch_challenge -> classify_challenge
```

后续应扩展为条件路由：

```text
fetch_challenge
  -> classify_challenge
  -> route_agent
  -> web_agent / pwn_agent / reverse_agent / crypto_agent / misc_agent / forensics_agent
  -> merge_findings
  -> verify_flag
  -> finalize_report
```

复杂题目可以让 `route_agent` 根据 `predicted_categories` 调度多个子 Agent，并在 `merge_findings` 中合并结果。

### 接入大模型

当前 `classifier.py` 使用关键词规则，不是大模型分析。后续可以新增 LLM 分类节点：

```text
src/cyberagent/agents/llm_classifier.py
```

建议大模型输出结构化 JSON：

```json
{
  "predicted_categories": ["Web"],
  "complexity": "simple",
  "reasoning_summary": "题目包含 HTTP 服务和登录绕过线索",
  "next_agents": ["web_agent"]
}
```

工程上建议保留关键词分类作为 fallback：大模型不可用或输出非法时，退回规则分类。

### 扩展工具执行层

后续工具调用建议单独放到：

```text
src/cyberagent/tools/
```

建议先实现统一工具接口，再给各 Agent 使用：

```text
tools/
├── executor.py
├── docker.py
├── http.py
├── filesystem.py
└── shell.py
```

工具调用结果统一写入 `ChallengeState["tool_outputs"]`，包括命令、输入、输出摘要、退出码和产物路径。
