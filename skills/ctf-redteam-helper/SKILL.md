---
name: ctf-redteam-helper
description: 在 CTF 单题解题中使用红队工具的正确姿势：解题优先，红队工具（资产/漏洞/POC/隧道/证据）只在需要时用；交付物始终是 ctf_finish 导出的 WP，不写渗透测试报告。
---

# CTF 解题里的红队工具（辅助位）

本系统是 **CTF 系统**。红队工具是副武器，不是主流程。

## 默认走法

`ctf_start → ctf_plan → ctf_analyze(tool=ctf_profile) → ctf_analyze/ctf_call 执行 → ctf_finish 出 WP`

## 什么时候才用 redteam_*

| 场景 | 用 |
|---|---|
| 试过的脚本/POC 想留档 | `redteam_attack_file_add` |
| 打到多个接口/主机，要记资产面 | `redteam_asset_add` / `redteam_asset_query` |
| 记录一个确认的漏洞点 | `redteam_vuln_add` |
| 题目是内网/容器多主机，需要落隧道 | `redteam_tunnel_add` + `redteam_session_check` |
| 需要把动作挂到 WP 证据链 | 任何 `ctf_call` 都带 `wp_case` / `source_step` |

## 不要做的事

- 不要因为融合了红队就套「五阶段渗透推进」，CTF 单题没有这回事。
- 不要用 `ctf_redteam_report` / `redteam_score_report` 当交付物：它们是附录，WP 才是交付物。
- 不要用 `redteam_agent_slot` 派角色，除非题目本身就是内网演练。
- 不写渗透测试报告、不堆「得分点」叙事。
