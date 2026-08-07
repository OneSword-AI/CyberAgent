# CyberAgent 全自动 CTF 解题 Agent 开发流程

配套流程图：[cyberagent-langgraph-flow.excalidraw](./cyberagent-langgraph-flow.excalidraw)

## 目标

CyberAgent 是一个基于 LangGraph 的全自动 CTF 解题 Agent。系统由主 Agent 负责读取题目信息、识别题目方向、调度专科子 Agent，并在解题过程中维护共享状态、工具输出、候选 flag 和失败反馈。

复杂题目允许主 Agent 以并行或串行方式调度多个专科子 Agent 协同求解，最终由主 Agent 汇总结果并验证 flag。

## 总体架构

核心分层如下：

- 输入层：接收题目描述、附件、远程服务链接、flag 格式、比赛上下文等信息。
- 主控层：主 Agent 负责题目理解、信息抽取、方向判断、策略制定和最终汇总。
- 编排层：使用 LangGraph 构建节点、条件路由、状态流转和失败重试路径。
- 专科解题层：由 Web、Pwn、Reverse、Crypto、Misc、Forensics 等子 Agent 执行具体解题任务。
- 工具执行层：通过 Docker 沙箱和常用安全工具完成脚本运行、二进制分析、HTTP 探测、取证分析等操作。
- 验证与复盘层：验证候选 flag，输出解题报告，并沉淀日志、失败路径和成功策略。

## 主流程

1. 题目信息输入

   用户或任务系统提供题目描述、附件、服务地址、端口、flag 格式和可用时间预算。

2. 主 Agent 读取题目

   主 Agent 解析题目文本和附件元信息，抽取关键线索，例如文件类型、协议、端口、关键字符串、加密参数、二进制保护信息等。

3. 判断题目方向

   主 Agent 根据题目描述和初步分析判断题目类型。可能的方向包括：

   - Web
   - Pwn
   - Reverse
   - Crypto
   - Misc
   - Forensics
   - 混合题型

4. LangGraph 条件路由

   LangGraph 根据主 Agent 的判断结果选择下一个节点。简单题目路由到单个专科子 Agent，复杂题目可路由到多个子 Agent。

5. 专科子 Agent 解题

   子 Agent 读取共享 State，调用必要工具执行分析和利用，输出候选 flag、证据、脚本、失败原因或下一步建议。

6. 多 Agent 协作

   对于复杂题目，主 Agent 可以：

   - 并行调度多个子 Agent 进行不同方向探索。
   - 串行调用多个子 Agent，将前一个 Agent 的发现作为后一个 Agent 的输入。
   - 在多个 Agent 结果之间做冲突消解和证据合并。

7. 主 Agent 汇总验证

   主 Agent 汇总候选 flag 和证据，执行本地格式校验、远程提交验证或题目环境验证。

8. 失败反馈重试

   如果验证失败，主 Agent 更新共享 State，记录失败路径，调整策略后重新路由到合适的子 Agent。

9. 输出结果与复盘

   成功后输出 flag、关键解题步骤、使用工具、利用脚本和解题报告。日志和策略可沉淀为后续题型经验与回归测试。

## LangGraph 节点设计

建议将流程拆成以下 LangGraph 节点：

| 节点 | 职责 |
| --- | --- |
| `ingest_challenge` | 读取题目描述、附件和远程服务信息 |
| `classify_challenge` | 判断题目方向和复杂度 |
| `route_agent` | 根据分类结果选择一个或多个子 Agent |
| `web_agent` | Web 漏洞探测、利用和 flag 提取 |
| `pwn_agent` | 二进制分析、漏洞利用和远程交互 |
| `reverse_agent` | 逆向分析、算法还原和 key/flag 提取 |
| `crypto_agent` | 密码题参数识别、攻击建模和求解 |
| `misc_agent` | 编码、隐写、脚本处理和杂项分析 |
| `forensics_agent` | 流量、磁盘、内存、图片和日志取证 |
| `merge_findings` | 合并多个子 Agent 的发现和候选结果 |
| `verify_flag` | 验证候选 flag 是否正确 |
| `reflect_retry` | 失败复盘、更新策略并决定是否重试 |
| `finalize_report` | 输出 flag、脚本、证据和解题报告 |

## 共享 State 设计

LangGraph 的共享 State 应贯穿全流程，建议包含：

```python
class ChallengeState(TypedDict):
    challenge_id: str
    title: str
    description: str
    attachments: list[str]
    remote_targets: list[str]
    flag_format: str | None
    category_hint: str | None
    predicted_categories: list[str]
    complexity: str
    active_agents: list[str]
    findings: list[dict]
    tool_outputs: list[dict]
    candidate_flags: list[str]
    failed_attempts: list[dict]
    budget: dict
    final_flag: str | None
    report: str | None
```

关键状态字段说明：

- `predicted_categories`：主 Agent 判断出的题目方向，支持多个方向。
- `active_agents`：当前被调度的子 Agent。
- `findings`：子 Agent 产生的关键发现、证据和推理结论。
- `tool_outputs`：工具执行记录，包括命令、输出摘要、退出码和产物路径。
- `candidate_flags`：所有候选 flag。
- `failed_attempts`：失败的 payload、思路、flag 和验证原因。
- `budget`：时间、token、工具调用次数、远程请求次数等限制。

## 专科子 Agent 职责

### Web Agent

- 识别 Web 框架、路由、参数、认证逻辑和常见漏洞。
- 执行目录扫描、参数 fuzz、SQL 注入、SSRF、文件上传、模板注入、反序列化等测试。
- 输出可复现 payload、HTTP 请求记录和候选 flag。

### Pwn Agent

- 分析 ELF、libc、保护机制和运行环境。
- 使用 GDB、pwntools、ROPgadget、one_gadget、angr 等工具。
- 构造 exploit 脚本并与远程服务交互。

### Reverse Agent

- 分析二进制、APK、字节码、脚本混淆和自定义 VM。
- 还原校验逻辑、加密算法和输入约束。
- 输出求解脚本、key 或候选 flag。

### Crypto Agent

- 识别 RSA、ECC、格、流密码、分组密码、自定义协议等题型。
- 根据参数弱点选择攻击方式。
- 输出数学推导、求解脚本和候选明文。

### Misc Agent

- 处理编码、压缩包、二维码、音频、图片、隐写、脑洞题和自动化脚本。
- 尝试常见转换、爆破、字典和格式恢复。

### Forensics Agent

- 分析 pcap、磁盘镜像、内存镜像、日志、图片和文档。
- 提取文件、凭据、会话、流量内容和隐藏数据。

## 工具与执行环境

工具执行建议统一放入 Docker 沙箱，避免污染宿主环境并提升复现能力。

常见工具类别：

- 通用脚本：Python、Shell、正则、批处理脚本。
- Web：HTTP 客户端、浏览器自动化、目录扫描、参数 fuzz。
- Pwn：GDB、pwntools、ROPgadget、checksec、angr。
- Reverse：反汇编器、反编译器、字符串提取、符号执行。
- Crypto：SageMath、Python 数学库、常见攻击脚本。
- Misc/Forensics：binwalk、foremost、exiftool、tshark、volatility、stegsolve 类工具。

每次工具调用都应记录：

- 调用方 Agent。
- 命令或工具名称。
- 输入文件或目标。
- 输出摘要。
- 退出状态。
- 生成文件路径。
- 是否产生候选 flag。

## 失败重试策略

验证失败时不应简单重复同一操作。主 Agent 应读取失败记录并调整策略：

- 更换题目分类判断。
- 引入其他专科子 Agent。
- 放宽或收紧搜索空间。
- 基于已有证据构造新的 payload。
- 将失败路径加入 `failed_attempts`，避免重复执行。
- 当预算耗尽时输出当前最有价值的分析报告。

## 最小可行实现顺序

1. 定义 `ChallengeState`。
2. 实现题目信息读取节点 `ingest_challenge`。
3. 实现主 Agent 分类节点 `classify_challenge`。
4. 实现 LangGraph 条件路由 `route_agent`。
5. 先实现 Web、Crypto、Misc 三个轻量子 Agent。
6. 接入 Docker 工具执行接口。
7. 实现候选 flag 汇总与验证节点。
8. 增加失败反馈和重试策略。
9. 扩展 Pwn、Reverse、Forensics 子 Agent。
10. 生成解题报告和回归测试样例。

## 产物

一次完整运行建议输出以下产物：

- `flag.txt`：最终 flag。
- `report.md`：解题报告。
- `artifacts/`：脚本、提取文件、payload 和中间结果。
- `run.log`：主 Agent、子 Agent 和工具调用日志。
- `state.json`：最终 LangGraph State 快照。
