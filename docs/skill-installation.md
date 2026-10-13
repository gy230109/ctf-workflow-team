# 给队友安装 CTF 引导 Skill

本版主要对接 Trae。中国版全局安装运行 `install-trae.ps1`，项目级加 `-ProjectDir <项目路径>`，CLI 用 `-Cli`。完整操作、MCP/CLI 与最小验收见 [Trae 指南](../skills/ctf-team-workflow/references/trae.md)。安装后开启新会话，确认技能启用并让 Trae 实际调用；文件复制成功不代表客户端模型已完成往返。

把仓库交给能操作**当前电脑终端和文件**的 AI，部署时读 AGENTS.md，按本机客户端运行安装器。Skill 固定操作顺序和恢复规则，本机路径保存在本机位置记录，当前题事实保存在独立 case 的 WP；三者不依赖压缩后的聊天记忆。

## 安装

拉取仓库，选定长期保留的位置。Python 尚未安装时，按 README 的 setup.ps1 流程补齐 Python；仅 Skill 安装无需 Pillow、SSH、模型账号或 VM，完整解题环境按原部署流程验收。已有 Python 的 Windows 电脑，在仓库根目录执行：

```powershell
py -3 tools\install_skill.py --client codex
```

也可用 `.\.venv\Scripts\python.exe` 替代 `py -3`。使用 Claude Code 时改 `--client claude`，两者都使用时选 `--client both`。Linux/macOS 可用 `python3 tools/install_skill.py --client ...` 安装引导，但首版完整 Windows/VMware 桥的支持范围不因此扩大。

| 本机客户端 | 安装位置 | 新会话显式调用 |
|---|---|---|
| Codex | 当前用户 `.agents/skills/ctf-team-workflow/` | `$ctf-team-workflow` |
| Claude Code | 当前用户 `.claude/skills/ctf-team-workflow/` | `/ctf-team-workflow` |

安装器返回绝对目录、复制校验结果与本机仓库记录位置。这里只证明文件已安装；重开客户端后确认 Skill 出现在列表中，再显式调用并核对定位输出，才证明该客户端实际能发现并使用它。其他支持 SKILL.md 的客户端，可将整个 `skills/ctf-team-workflow` 目录导入其支持的路径，不仅复制 SKILL.md；若没运行本机安装器，首次定位用 `--repo` 或 `CTF_WORKFLOW_HOME` 指定仓库。

位置配置写到当前用户 `.ctf-workflow-team/location.json`，仅含本机仓库路径。安装登记文件只保存目标路径和 Skill 文件 SHA256。不要把它们复制成队友的路径，也不要把账号、私钥、VM 信息或题目答案放入 Skill。

## 新会话怎么说

部署：`使用 ctf-team-workflow 找到本机系统，检查和安装缺失依赖，报告实际验收结果。`

解题：`使用 ctf-team-workflow 解我提供的已授权 CTF，题号 case=qwb_web_001，真实调用留证，关键画面截图，最后生成 WP。` 每道题使用独立英文题号。

恢复：`使用 ctf-team-workflow 继续 case=qwb_web_001，先从本题 WP 恢复实际进度。`

明确调用比期待任意客户端每次自动触发更可靠。Skill 是操作引导，不是额外的执行服务；仍需当前 AI 的本机工具权限。仅在云端网页或普通手机聊天里加载文件，不会因此访问队友本机 VM。没有 MCP 时按 CLI 使用，不必为了 Skill 先修改客户端的 MCP 配置。

## 更新、移动和冲突

仓库更新后，重跑同一安装命令，重开客户端会话；只拉代码不会自动替换已复制到用户目录的 Skill。仓库移动后，在新目录运行安装器，更新本机位置记录。显式 `--repo` 优先，其次 CTF_WORKFLOW_HOME、本机位置记录、Skill 所属仓库和当前目录祖先。

安装器更新自己此前安装且未被修改的版本，不覆盖其他 Skill。同名目录来源不明、被手工编辑或包含符号链接时会停止并给出冲突路径；检查并备份后自行解决，不自动清掉队友的修改。安装不改客户端其余配置、MCP 服务、账号或开机任务。

Skill 会核对本机真实 tools/list/catalog，只有工具与对应文档都存在时才使用扩展。这个发布只增加 Skill、定位/安装脚本和说明，不把队长工作区的可选模型改动或私人配置一起发布。

## 开发验收

```text
python -m unittest discover -s tests -v
```

测试覆盖临时用户目录安装/更新、冲突保护、移动仓库、跨目录新进程定位与依赖隔离，不使用真实模型、账号或 VM。客户端是否实际加载 Skill、Windows/Kali 部署及比赛效果仍需在队友电脑上实测。

加载路径依据 [OpenAI 官方 Skill 文档](https://learn.chatgpt.com/docs/build-skills) 和 [Claude Code 官方 Skill 文档](https://code.claude.com/docs/en/skills)（2026-10-12 核对）。仅按本机客户端支持的方式安装，不把本地目录安装等同云端账号技能安装。
