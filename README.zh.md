# ARTEx Agent Profiles for Claude Desktop

[한국어](README.md) · [English](README.en.md) · [日本語](README.ja.md) · 简体中文

本仓库用于在本地 Claude Desktop 会话中连接由操作者配置的 ARTEx 服务，包含 Claude 代理配置、技能、命令以及 Python MCP 连接器。

> 连接器仅可用于你有权访问的 ARTEx 实例和评估任务。目标请求连接器受到范围和预算限制，但它不是通用扫描器。启用目标请求前，请检查任务范围、allow/deny 规则、请求预算和停止条件。

## 项目目的与责任

本项目旨在帮助应对日益增多的安全事件，为你开发、运营或获得明确评估授权的服务提供安全评估、维护和事件响应准备支持。仅可在你拥有或运营、或事先获得书面授权的系统之批准范围内使用。用于工作时，请确认所在组织的政策和批准要求。公开或下载本项目不会授予你测试第三方系统的权限。

用户负责选择目标、取得并核实授权、配置范围和安全措施、遵守适用法律及第三方条款，并承担使用所产生的后果。维护者不指示、授权、监控或认可任何用户活动，也无法控制发布后的使用行为。

在适用法律允许的最大范围内，本软件及资料按 **“原样（AS IS）”** 提供，不附带任何保证。在同等范围内，维护者不承担因使用或无法使用而产生的索赔、损失或损害责任。本声明不排除法律禁止排除的责任，也不改变适用于各组件的许可证或适用法律规定的权利和义务。

本声明说明项目预期的责任分配，但不保证维护者不会受到调查、诉讼或被追究责任。法律后果取决于具体事实、司法管辖区、行为及适用法律。仅因资料已公开，并不意味着任何使用均获授权。

## 包含内容

- `claude-cowork-plugin/agents/`：用于协调、规划、评估、报告和复测的角色配置
- `claude-cowork-plugin/skills/`：ARTEx 工作流、API 侦察、浏览器和范围指导
- `claude-cowork-plugin/commands/`：评估工作流命令
- `src/artex_agent/`：只读、证据写入、任务设置和目标请求 MCP 连接器
- `tests/`：离线连接器测试
- `scripts/package_cowork_plugin.py`：在 `dist/` 下生成插件 ZIP
- `scripts/smoke_mcp_stdio.py`：检查 MCP 启动和工具列表，不写入 ARTEx，也不连接目标

## 要求

- Python 3.11 或更高版本
- 支持兼容本地插件/MCP 工作流的 Claude Desktop
- 单独安装并运行的 ARTEx 服务

本仓库不包含 ARTEx 服务、Claude 账户、API 密钥、凭据或任务数据。Claude 会话身份验证与 ARTEx 自身的 LLM 配置属于不同运行环境。

## 配置本地连接器

1. 在本仓库中创建并激活 Python 虚拟环境。
2. 运行 `python -m pip install -e .` 安装连接器包。
3. 将 `claude-cowork-plugin/.mcp.json.example` 复制到插件的本地配置中，并将 Python 与源代码路径占位符替换为本机绝对路径。
4. 将 `ARTEX_API_BASE_URL` 设置为 ARTEx 服务地址。使用提供的 `artex-auth-store` 命令保存凭据；不要把秘密写入 MCP JSON 或提交到源代码管理。
5. 使用当前 Claude Desktop 版本支持的插件安装流程，安装由 `python scripts/package_cowork_plugin.py` 生成的 ZIP 文件。

示例 MCP 配置只是模板。使用前请在 Claude Desktop 中检查实际连接器列表和权限。

## 检查

运行离线测试：

```powershell
python -m unittest discover -s tests -v
```

运行本地 MCP 握手检查：

```powershell
python scripts/smoke_mcp_stdio.py
```

冒烟检查会启动本地 MCP 进程并列出工具；它不能证明与 ARTEx 部署环境的端到端连接。进行写入/回读测试时，请使用指定的合成任务，不要创建虚构的漏洞 Finding。

## 运行环境边界

代理配置在调用它的 Claude Desktop 会话中运行，并可调用已配置的本地 MCP 连接器。本集成不会将 Claude 订阅身份凭据传递给 ARTEx 原生 planner 或 worker 运行环境，也不会自行启用 ARTEx 无人值守执行。

## 发布说明

本仓库是整理后的源代码快照，并具有新建的 Git 历史。已排除本地虚拟环境、凭据、机器专用路径、日志和任务专属评估资料。包含组织专属内容的内部 Web 渗透测试技能也未纳入。发布前请审查依赖项及再分发许可证，并添加适当的许可证文件。
