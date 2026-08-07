# CyberAgent

Fully Automated CTF Agent

## 开发说明

- 新特性：新建功能分支 → 提交 PR → 审核后合并。
- `main` 分支已开启保护：禁止直接推送，所有改动必须通过 PR 合并。
- 请不要一次性提交大量代码，请提交`原子化`的commit，[参考](https://www.conventionalcommits.org/zh-hans/v1.0.0/)

**原因：**

- 分支隔离：在分支上开发，不干扰 `main` 上的稳定代码。
- 代码审查：PR 强制审核，及早发现问题和风格不一致。
- CI 检查：合并前跑测试，保证 `main` 始终可部署。
- 可追溯：PR 记录改动历史，方便回溯问题。
- 防止误操作：禁止直接推送，避免破坏主分支。

## 环境配置

```bash
uv sync
```
