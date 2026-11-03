# agent-surface-scan

扫描仓库里 **AI 代理会读到的攻击面**（AGENTS.md / CLAUDE.md / .cursorrules / README / Issue 模板 / Skill / MCP 配置 / docs），检测其中针对编码代理的**提示注入、远程执行、外泄、绕过审批、隐藏字符、欺骗性链接、硬编码密钥、危险 MCP 配置**。

> 为什么存在：AI 编码代理会无条件阅读并执行仓库文本里的"指令"。2026 年已出现真实事件（投毒 README 诱导代理执行恶意代码、绕过人工审批）。本工具在 CI 里充当"提示注入攻击面"的静态门禁。

## 特性

- 单二进制、纯标准库（Go），无运行时依赖
- 14 条规则，覆盖 6 类代理上下文文件，映射 OWASP Agentic Security Initiative（ASI）分类
- 4 种输出：文本 / Markdown / JSON / SARIF 2.1.0（可直接上传 GitHub Code Scanning）
- `--fail-on` 门禁 + 退出码，适合 CI
- 自带恶意/良性样本语料与单元测试

## 使用

```sh
# 构建
go build -o surface-scan ./cmd/surface-scan

# 扫描当前仓库（默认阈值 high，有高危发现时退出码为 2）
surface-scan scan .

# 输出 SARIF 供 GitHub Code Scanning 使用
surface-scan scan . --format sarif --out results.sarif --fail-on high

# 只看扫描了哪些文件
surface-scan scan . --list

# 生成 CI 工作流模板（写入 .github/workflows/surface-scan.yml）
surface-scan init-ci

# 查看全部规则
surface-scan rules
```

## 规则一览

| ID | 严重度 | ASI | 说明 |
|---|---|---|---|
| AGI-001 | high | ASI01 | 显式要求忽略/覆盖此前指令 |
| AGI-002 | high | ASI01 | 角色翻转 / 关闭护栏（uncensored、safety off） |
| AGI-003 | high | ASI03 | 过度授权（执行任意命令、完全访问） |
| AGX-001 | critical | ASI07 | 远程命令执行（curl 下载后经管道执行、pip 安装远程包） |
| AGX-002 | high | ASI07 | 提权指令（管理员权限、执行策略绕过、宽松权限位） |
| AGX-003 | high | ASI07 | 绕过人工审批 / HITL |
| AGE-001 | critical | ASI06 | 数据外泄指令（密钥/凭据 → 外部端点） |
| AGE-002 | medium | ASI06 | 可疑 webhook / OOB 端点 |
| AGEV-001 | medium | ASI01 | HTML 注释/不可见元素藏指令 |
| AGEV-002 | medium | ASI01 | Base64/编码载荷 + 执行动词 |
| AGEV-003 | medium | ASI01 | 零宽/不可见字符 |
| AGD-001 | medium | ASI01 | 欺骗性链接 / 短链 / 同形异义域名 |
| AGS-001 | critical | ASI03 | 硬编码活跃密钥（OpenAI/GitHub/AWS/Slack/JWT/PEM） |
| AGC-001 | high | ASI05 | MCP 服务器执行远程代码 |
| AGC-002 | high/medium | ASI03 | MCP autoApprove / alwaysAllow |
| AGC-003 | low | ASI05 | 无法解析的 MCP 配置 |
| AGC-004 | low | ASI03 | MCP 服务器未声明权限范围 |

## 目录

```
cmd/surface-scan      CLI 入口
internal/model        共享类型
internal/rules        规则引擎（14 条规则）
internal/scan         文件发现、引擎、输出渲染
testdata/corpus       恶意/良性样本语料（用于回归测试）
testdata/repo         端到端演示仓库
```

## Roadmap

- [ ] `agentscan-dsh`：DSH 插件形态（扫描当前工作区 + 会话内报告）
- [ ] Codex / Claude Code hook 集成（agent 读文件前提示）
- [ ] `--allowlist` 与行内豁免注释（`surface-scan:ignore`）
- [ ] 规则覆盖率基准（对公开恶意样本集 + 良性大仓库的 FP 报告）
- [ ] Windows Defender / OTel 导出（与 Agent 飞行记录器联动）

## 许可

MIT
