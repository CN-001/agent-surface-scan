# agentscan-dsh

DeepSeek Harness 插件：把 `agent-surface-scan` 变成 agent 可以直接调用的 `surface_scan` 工具，扫描当前工作区的「AI 代理攻击面」（提示注入、远程执行、外泄、密钥、MCP 配置等），并附带一个 `agentscan` 技能指导 agent 何时/如何审计。

## 安装

前置：本机已安装 `surface-scan` 二进制：

```sh
go install github.com/CN-001/agent-surface-scan/cmd/surface-scan@v0.2.0
```

从本地目录安装插件（发布前测试用）：

```powershell
dsh plugin --profile desktop add "E:\agent-surface-scan\dsh"
```

从 npm 安装（发布后）：

```powershell
dsh plugin --profile desktop add agentscan-dsh
```

安装后重启 DeepSeek Harness 生效。新会话的工具列表里会出现 `surface_scan`，技能目录里出现 `agentscan`。

## 配置

在 profile 的 `cordis.patch.yml` 里给 `agentscan` 插件加配置（或通过插件管理器）：

```yaml
- id: agentscan
  name: agentscan-dsh
  config:
    binaryPath: ""        # 留空 = 自动找 PATH 上的 surface-scan；也可填绝对路径
    registerSkill: true   # 是否注册 agentscan 技能
    maxOutputChars: 20000 # 输出截断长度
```

## 行为

- 只读扫描，不执行被检出的内容
- 找不到二进制时返回安装提示（fail-open，不报错）
- 默认按 `--fail-on critical` 运行，便于 agent 直接看结果文本

## 维护者

Aurox（GitHub [@CN-001](https://github.com/CN-001)）
