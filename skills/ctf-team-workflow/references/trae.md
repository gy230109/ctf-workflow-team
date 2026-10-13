# Trae 接入、安装和验收

## 安装位置与版本

本系统面向本机 Trae IDE / Trae 中国版；TraeWork 的云端任务不能直接访问你电脑上的 VMware、Windows 路径或本机 SSH 身份。使用云端模型不等于工具在云端执行：本机 Trae 发起 CTF-OS，CTF-OS 再调用本机配置的 Kali。

已安装系统的用户在自己的仓库根目录执行：

```powershell
# 中国版全局技能，跨项目可用。
.\install-trae.ps1
# 只安装到指定项目；不改项目其他技能。
.\install-trae.ps1 -ProjectDir 'E:\my-ctf-project'
# 国际版全局技能，或 Trae CLI。
.\install-trae.ps1 -International
.\install-trae.ps1 -Cli
```

安装器校验固定技能文件白名单。升级只覆盖本安装器管理且摘要没有被本机改写的旧技能；遇到同名手工技能或本机编辑会明确拒绝，保留原文件。已管理旧版本保留备份，位置记录写入当前用户 `.ctf-workflow-team/location.json`。不能把安装器返回的 `files_verified=true` 当 Trae 模型已调用成功。

中国版全局路径为 `%USERPROFILE%/.trae-cn/skills/ctf-team-workflow`；项目路径为 `<项目>/.trae/skills/ctf-team-workflow`。Trae CLI 使用 `.traecli/skills`。国际版全局目录应与该客户端当前官方设置核对，本脚本的 `-International` 使用 `.trae/skills`，项目安装不依赖此区别。

官方技能目录与本地导入说明：[Trae IDE 技能](https://docs.trae.cn/ide_skills)、[Trae CLI 技能](https://docs.trae.cn/cli_skills)。安装后开启新会话，在“设置 > 技能与命令”核对启用状态，并明确说“用 ctf-team-workflow 技能检查这台机器”。

## CLI 先通，再接 MCP

在 Trae 中打开自己的系统仓库，让终端先运行：

```powershell
.\.venv\Scripts\python.exe -X utf8 tools\ctf_os.py --selftest
.\.venv\Scripts\python.exe -X utf8 tools\ctf_os.py --once ctf_profile --args category=reverse
.\.venv\Scripts\python.exe -X utf8 tools\ctf_os.py --once ctf_specialist_status
```

前两项不调用解题模型、不派题；第三项通过真实桥检查 Kali 独立环境。缺专项配置时先读 upgrade.md，不反复调用同一个缺配置错误。

MCP 使用当前仓库 Python 的绝对路径，stdio 模式。以下路径只是格式示例，必须替换为定位结果：

```json
{
  "mcpServers": {
    "ctf-os": {
      "command": "E:/ctf-workflow-team/.venv/Scripts/python.exe",
      "args": ["-X", "utf8", "E:/ctf-workflow-team/tools/ctf_os.py", "--stdio"]
    }
  }
}
```

通过 Trae 的 MCP 设置添加/合并这一服务；保留现有其他服务及账号配置。[官方添加 MCP 说明](https://docs.trae.cn/ide_add-mcp-servers)。官方提醒 command 路径不能含空格；仓库位于含空格路径时优先使用 CLI，或配置经过验证的无空格可执行入口，不照搬未经测试的命令。不要整体覆盖用户已有 MCP JSON。stdout 只承载协议，诊断看 stderr 和本机审计。刷新或重连只针对本服务，等当前工具调用结束再做。

HTTP 是可选接口：先 `start.ps1`，本机 `/tools` 看目录；`tools/ctf_post.py <工具> <request.json> --wp-case <case>` 调用。默认回环地址；不要把队长内网 IP 当队友服务地址。没有 HTTP/MCP 也能走 `ctf_call.py`。

## 最小端到端验收

1. 让 Trae 自己执行定位脚本，报告实际系统路径、Python 路径、接口和依赖缺项。
2. 新建 `trae_smoke_<时间>` 的 WP，调用 `math_gcd values=48,60`，检查结果为 12 和 `wp_record`。
3. 用自建无答案文本附件调用 `misc_file_inspect`，核对本机与 Kali 的 SHA256；不得用真实比赛题冒充部署自测。
4. 写 observed 引用真实步骤，执行 `wp_status`、`wp_build`。确认文件存在、完整性通过、报告没有写“比赛题已解”。
5. 这些动作须由 Trae 实际发起；其他客户端过去的证据不能替代本机 Trae 验收。截图、付费模型和第三方调试器按需单独验证。

## 常见失败

| 现象 | 核对与修复 |
|---|---|
| 新工具不出现 | 找到旧 MCP/HTTP 对应路径；更新代码后等空闲重连，CLI 现查目录 |
| 技能不出现 | 核对项目/全局目录、SKILL.md frontmatter、启用状态；开启新会话 |
| 仓库移动后指向旧目录 | 在新目录重新运行 install-trae.ps1，刷新位置记录与 MCP 的绝对路径 |
| PowerShell 数组/约束参数错误 | 用 UTF-8 JSON 和 ctf_call.py，不拼大段 JSON 命令行 |
| Kali 上传失败 | 先查桥与实际 VM；保留 SHA/SSH 身份检查，不降低校验 |
| “已连接”但工具无法完成 | 查看原始 stdout/stderr/退出码，检查对应软件与账号；连接成功不算功能验收 |
