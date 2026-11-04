# 用 5 个真实仓库证明：一个 AI 安全工具不是玩具

> 一个周末写完的扫描器，怎么证明它真有用？我把它跑在 gin、express、flask、axios、fastapi 上——结果从 103 条高危噪声，调到 0。

## 问题：AI 编码代理信任仓库里的每一个字

Codex、Claude Code、Cursor、DSH 这类工具会**无条件读取并执行仓库文本里的"指令"**：README、AGENTS.md、Issue 模板、Skill 文件、MCP 配置。攻击者不再攻击代码，而是攻击上下文——2026 年已有公开案例：投毒 README 诱导编码代理执行远程脚本并绕过人工审批。

现有工具都不扫这条面：CodeQL/Semgrep 扫代码漏洞，SkillSpector 只审计 skill 包，MCP 扫描器只看 MCP。**"仓库上下文提示注入 + CI 门禁"是空白。**

于是我写了 [agent-surface-scan](https://github.com/CN-001/agent-surface-scan)：一个零依赖的 Go 单二进制，17 类规则（映射 OWASP ASI），扫 6 类代理上下文文件，输出 SARIF 进 GitHub Code Scanning，还带 Claude/Codex hooks 和 DSH 插件。

```sh
go install github.com/CN-001/agent-surface-scan/cmd/surface-scan@v0.2.1
surface-scan scan . --fail-on high   # 有高危发现时退出码 2
```

## 方法：拿 5 个热门仓库当"误报测试集"

浅克隆五个仓库，只看 AI 代理会读的文件（README/AGENTS/Issue 模板/skills/MCP 配置/docs，共 2,017 个文件），按推荐 CI 门禁 `--fail-on high` 跑。

**第一版结果很打脸**：103 条 critical，全部是文档误报——`[npm registry](https://www.npmjs.com/)` 徽章链接、`api_key.py` 文件名、`@app.webhooks.post(...)` 代码示例、OAuth2 教程里的 JWT 示例 token、emoji 零宽字符、`user:pass@example.com` 文档示例。

## 数据：一轮调优后

| 仓库 | 代理可读文件 | 调优前 critical | 调优后 high/critical | 剩余（全部 medium/low） |
|---|---|---|---|---|
| gin-gonic/gin | 9 | 0 | 0 | 0 |
| expressjs/express | 2 | 7 | 0 | 0 |
| pallets/flask | 9 | 0 | 0 | 0 |
| axios/axios | 154 | 17 | 0 | 12 medium |
| fastapi/fastapi | 1673 | 79 | 0 | 16 medium + 13 low |

**0 高危误报，而恶意样本（bench 语料）依旧 12 条全中。** 剩余 medium/low 全是"审查级"信号：JWT 教程示例、短链示例、裸 sudo 文档——刻意留在低级别，不进 CI 门禁。

## 按数据改掉的 8 处规则

- 包管理器模式改为"动词 + 参数 token + URL"语法，徽章/链接不再触发
- 外泄规则只认具体凭据物（.env、auth.json、id_rsa…），去掉笼统的 secrets/credentials 字样
- exfil 动词要求后跟空格（`webhooks.post(` 不再误报）
- JWT 形状的 token 单独降为 medium（教程到处都是）
- 零宽字符排除 ZWJ（emoji 不再误报）
- 文档示例域名（RFC 2606）不再报欺骗链接
- 去掉裸 "debug mode" 匹配
- docs/ 目录按路径段识别，单文件扫描同样生效

完整记录在 [docs/false-positive-report.md](docs/false-positive-report.md)，并带一键复现脚本 `bench/fp-run.ps1`。

## 诚实的边界

"0 高危"是必要不充分的证明：样本只有 5 个仓库、一天快照；启发式规则对新措辞仍可能漏报；medium/low 误报仍需人工。但工具现在有了最小可信闭环：**真实问题 × 真实测试 × 可复现的数据报告**。

下一步：扩充公开样本集、收集更多仓库的误报统计、接入更多代理 hook。欢迎 star、issue、PR——以及把你仓库的误报反馈给我。

*作者：Aurox（GitHub [@CN-001](https://github.com/CN-001)）· MIT License · 仅防御用途*
