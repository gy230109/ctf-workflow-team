# 接入任何 Agent

Trae 是本版主要目标：[详细指南](../skills/ctf-team-workflow/references/trae.md)。先 `install-trae.ps1` 安装技能，再在客户端实际验证工具往返。复杂参数使用 `tools/ctf_call.py <工具> --request <UTF-8 JSON> --wp-case <题号>`；不依赖 HTTP 或 MCP，失败返回非零退出码。

## CLI

使用仓库 `.venv/Scripts/python.exe` 调用 `tools/ctf_os.py --once`。PowerShell 参数优先 key=value；带空格时把整个参数放进引号。长字符串/数组由具有终端能力的 agent 在 Python 中构造参数对象并调用 `ctf_os.call_tool`，不要拼接未经转义的 shell 字符串。

## MCP stdio

```json
{
  "mcpServers": {
    "ctf-os": {
      "command": "<仓库绝对路径>/.venv/Scripts/python.exe",
      "args": ["-X", "utf8", "<仓库绝对路径>/tools/ctf_os.py", "--stdio"]
    }
  }
}
```

具体客户端配置文件格式不同，先读客户端现有格式再合并；保留其余服务。重新连接后实际 `tools/list`，不要把配置写入等同接入验收。没有 MCP 能力时 CLI 仍可用。

## HTTP

```json
{"tool":"math_gcd","args":{"values":[48,60],"wp_case":"demo"}}
```

发送到 `http://127.0.0.1:8787/call`。先用 `wp_init` 初始化 `demo`。不要将无鉴权的服务改成局域网公开监听。工具日志保存在本机；不会自动同步 agent 的完整聊天记录。
