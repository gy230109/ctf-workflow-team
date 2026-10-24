# 模型可替换，系统接口固定

## 职责

系统管理题面和附件原件、工具目录、执行规则、任务状态、失败记录、WP 与验证凭据。AI 客户端提供当前模型并传递工具调用。适配器只转换调用格式，不切换模型账户，不改变工具权限或题目流程。

模型可以采用不同的解题思路；系统不会因此更换接口、错误处理规则或验证口径。这里的统一不意味着不同模型会给出完全相同的答案。

## 八个公开操作

| 操作 | 用途 |
| --- | --- |
| `ctf_system_status` | 读取当前版本、协议、工具数和可选依赖状态 |
| `ctf_start` | 接收原题和附件，建立共享任务 |
| `ctf_tools` | 实时读取内部工具名称、参数和说明 |
| `ctf_analyze` | 执行受限分析，自动记录证据 |
| `ctf_call` | 通用执行入口，保留原有确认要求 |
| `ctf_note` | 记录观察、假设、待办和失败恢复决定 |
| `ctf_progress` | 读取原任务、附件、错误和调用记录 |
| `ctf_finish` | 保存完成或阻塞状态，导出 WP 和附件包 |

MCP 启动命令仍是 `python -X utf8 tools/ctf_entry.py --stdio --root 系统目录`。可执行文件、脚本和 root 参数都应使用真实安装的绝对路径。新客户端通过 `tools/list` 获取当前参数，不硬编码另一版本的 schema。

## 服务端规则

新任务的 `workflow.phase` 为 `needs_triage`，先经 `ctf_analyze` 成功调用 `ctf_profile`。之后实际分析由 `ctf_analyze` 或 `ctf_call` 执行。

执行失败进入 `needs_recovery`。先看 `pending_error` 的原始错误、证据路径和 `source_step`，再用 `ctf_note(resolve_error=true, source_step=对应编号)` 记录诊断和下一步。没有编号的超时事件可省略 `source_step`。普通备注或诊断工具成功不能自动清除失败。

`request_id` 标识一次具体执行。同一任务中相同编号和相同参数会返回原记录；不同参数复用同一编号会被拒绝。工具已开始但没收到最终结果时，记录为 `request_indeterminate`，应检查现有证据和进程，不自动重跑。完成后有意重新执行属于新动作，使用新编号。

`analysis_complete_unverified` 表示分析和导出完成，`answer_verified` 仍为 false。只有原有受支持的平台正确判定凭据才能设置平台验证状态。调用成功、flag 格式正确、生成 WP，都不能独立证明答案正确。

旧任务缺少流程元数据时，只从已有事件推导状态；不补造成功操作或恢复记录。旧失败未有明确恢复记录时，需要按新的恢复流程说明处理决定。只读进度操作不会改写旧任务文件。

## 客户端适配

`tools/ctf_client_adapter.py` 仅依赖 Python 标准库。把系统 tools 目录加入模块搜索路径后：

```python
from ctf_client_adapter import CTFClient, StdioTransport

client = CTFClient(StdioTransport(r'D:\强网杯大师'))
deepseek_tools = client.tools('deepseek')
openai_chat_tools = client.tools('openai')
anthropic_tools = client.tools('anthropic')
mcp_tools = client.tools('mcp')
```

供应商返回 OpenAI Chat Completions / DeepSeek 风格的 `tool_calls` 时，把每个调用对象传给 `client.openai_call(call)`，把返回的 `role=tool` 消息交回当前模型。Anthropic 的 `tool_use` 块交给 `client.anthropic_call(block)`，再将返回的 `tool_result` 交回当前模型。这不是 OpenAI Responses API 的直接适配器。

调用编号会作为执行请求编号传递，结果中的 `isError`、`structuredContent` 与 `workflow` 不被丢弃。不识别的原生工具名会被拒绝。模型账户、网络请求、生成参数和会话循环仍由接入端负责。

多个客户端连接同一个系统 root 并传入同一 `task_id`，才会读取同一份状态。系统写操作沿用任务锁；不同安装目录或不同电脑之间不自动同步。

## Harness 插件

`integrations/deepseek-harness/ctf-route-guard.mjs` 通过实际的 `ctx.tools.guard` 拦截工具执行。支持 `mcp__ctf_system__` 和 `mcp__ctf-system__` 两个命名空间，但只放行八个准确操作名称。拒绝决定不会被普通 allow 监听器覆盖。

`after_ctf_intake` 模式按 agent 会话激活，`always` 模式从第一步生效。系统提示要求新题先接题、续题先读取进度。通用模式不能在模型尚未接题时可靠判断每个原生工具调用是否属于 CTF；需要第一步强制路由时，在专用 profile 使用 `always`。

安装脚本只往已连接 CTF 的 Harness profile 添加带边界标记的插件配置，保留其他配置字节。重启客户端并新建会话后检查真实调用记录，才可认定运行中的客户端已加载策略。本次隔离测试没有冒充真实模型联调。
