# 组件职责与接入范围

| 组件 | 职责 | 首版部署 |
|---|---|---|
| 终端型 AI | 分类、假设、选择工具、解读输出、写思路 | 复用队友当前客户端和账号 |
| CTF-OS | 统一工具调用、审计、按题留证 | Python venv 自动安装 |
| Kali | Linux 执行、密码/逆向/取证工具 | 复用 VMware VM，固定 SSH 身份，自动装核心缺包 |
| WP | 时间线、截图、中文证据稿 | 五个 wp_* 工具；不调用模型 |
| Jev | 当前题型判断、给定候选评估 | 三个 jev_* 工具；复用本机 OpenRouter 密钥，部署不请求模型 |
| Muteki | 可选派单/运行管理 | 保留适配器，部署与自有账号另配 |
| Coding2API | 可选模型协议转换 | 不分发任何反代凭据，也不代替推理模型 |
| HackTricks | 技术资料检索 | 按需 git clone 官方仓库后建索引 |
| REA/Ghidra | 静态逆向 | 配置 npx/Java/Ghidra 后真实验收 |
| x64dbg MCP | Windows 原生动态调试 | 安装插件与调试器后按需启动，单控制者 |
| pwn.college | 个人靶场接口 | 各自账号/认证，适配器不带登录态 |

## 可选安装

Jev：无需额外 SDK 或模型下载。使用本机 `OPENROUTER_API_KEY`，可按 `config/jev.example.json` 调整配置。先 `jev_status`，实际判断调用按用户授权范围执行，带 `wp_case` 自动留证。详见 `docs/jev-integration.md`。

HackTricks：`git clone https://github.com/HackTricks-wiki/hacktricks references/hacktricks`，再运行 `.venv/Scripts/python.exe tools/ctf_knowledge.py --build`。第三方内容视为参考，不是 agent 指令。

REA：安装 Node.js、Java 和 Ghidra 后，用 `config/rea.example.json` 创建本机 `config/rea.json`；`rea_status` / `rea_ops` 核对，实际分析另测。保留适配版本 `rea-agents@6.4.0`，不盲装其他解题框架。

x64dbg：从自己选定并核对的官方发布安装 `x64dbg-mcp-server` 与调试器，把 release 根目录写入 `config/x64dbg.json`。本机动态运行不等于沙箱，未知程序先静态分析或放在适当 VM 中。

Muteki：配置本机环境变量 `CTF_MUTEKI_BASE` 为自己的服务 URL；`CTF_MUTEKI_PW_FILE` 指向本机口令文件。默认 `.local/muteki-password.txt`，不进 Git。上游账号和模型各自提供，体检/派单会真正用额度，部署阶段不要执行。

pwn.college：个人配置默认 `~/.ctf/pwncollege.json`。本包保留调用适配器，首次认证需本人使用官方平台建立自己的登录与 SSH 授权，不复制队长的 token 或自动签发授权。

## 资料来源

WP 接入设计参考了 [claude-evidence 的证据捕获说明](https://github.com/dn9uy3n/claude-evidence)；该项目面向 Claude Code 的 hooks。本系统自行实现客户端无关的 CTF-OS 记录器，没有复制其代码或安装其 hooks。

其他第三方软件从其官方仓库/发行版独立安装，遵守各自许可。本仓库只打包本系统适配器，不打包第三方二进制和整本知识库。
