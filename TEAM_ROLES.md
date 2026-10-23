# 团队角色和首读资料

## 2026-10-23 最新团队规则与完整记录

所有队员均使用全题型系统，不按 A/B/D/G 限定主攻方向、资料或工具。不以未登记角色阻塞安装或解题；旧角色表和说明保留作历史参考。按当前题目读取对应方法，不要求一次加载所有题型资料。

队友接收资料时读取 docs/team-records.md，运行 tools/team_records.py verify 和 restore，获取完整共享记录。快照在 knowledge/records/20261023/，按用户要求不加密；其中已审阅处理的 WP、调用日志、附件和图片可随本次发布。新增私人任务和凭据仍不自动提交。历史成功、失败、自建验收和未完成状态分别保留。

所有人获取同一份系统与共享经验。角色决定首接队列和优先阅读内容，不限制工具访问，不代表某类题只有某台电脑能做。题型按出题方标签认领，每人一个活跃主任务，当前负责人保留验证、提交回执与 WP。

## 历史周六四人配置 saturday-four

| 代号 | 首接 | 空闲时优先接替 |
|---|---|---|
| A | Web、轻量协调 | Crypto |
| B | Pwn | Reverse |
| D | Reverse | Pwn |
| G | Crypto | Web |

Misc、Forensics 及其他类别从开场进入公共队列，空闲且工具合适的人可认领；不要求先做完首接类别。遇到积压或资源限制时整题转派，不常态化跨机代跑。首接类无题就分担其他队列。

### 流量能力增强后的分题规则

四个首接队列保持不变。新增流量处理、停滞提示和参考检索对所有角色开放，不设第五席，不把新增取证题固定交给 A。官方标签为 Misc/Forensics 的流量题仍进公共队列；由空闲且本机工具实际可用的成员认领，一人一个活跃主任务。

流量题先按证据选用 `forensics_pcap` 的 summary、streams、follow、http_objects、dns、usb 动作；具体参数用 `ctf_tools` 实时发现。USB 当前仅提取原始字段，不等于还原键盘输入。已有明确可验证下一步的流量题，可以优先于没有新证据的主线；正在有效推进的主线不强制让位。各机依赖是否可用仍须本机确认，共享升级包不等于四机均已实测。

`task_health` 对重复调用、连续失败及 80 次调用或累计工具耗时 30 分钟给出复核提示。负责人检查新证据和下一步后决定继续、换方法、暂挂或整题交接；提示不自动终止任务，也不代表模型用量或费用。有进展可记录理由后继续，不为消除提示重开任务。

移交流量题时保留原始抓包、过滤条件、流编号、脚本、真实输出、导出对象及其 WP 附件关系，再写清已排除路线和下一步。接收人先读已有证据，按需复核，不把操作和写 WP 长期拆给其他成员。

NoobCTF 等参考检索用于按需学习方法；独立解题默认隔离历史答案，实际验证仍由当前负责人完成。新增本机能力已完成部署验收，队友运行范围、具体赛事解题收益与模型费用未验证；本方案没有实际分派赛题。

## 历史月底七人配置 full-seven

| 代号 | 首责 | 备用 |
|---|---|---|
| A | 总控机动 | 短题和跨类问题 |
| B | Pwn | Reverse |
| C | Web | Crypto |
| D | Reverse | Pwn、队长接替 |
| E | Forensics | Web、Misc |
| F | Misc | Pwn、Forensics |
| G | Crypto | Misc |

具体机器当前依赖仍需实际发现；不得把角色表当作已安装证据。四人/七人配置显式切换，不按日期偷偷变更。

## 自动找到自己的资料

四人各有一份角色执行说明，装在同一个 `ctf-system` Skill 内。AI 先恢复本机身份，再读取 `ctf_team_role` 返回的 `role_guide`；不用安装四套重复系统，也不用每次重新说明分工。角色说明、工具协议与共享经验分别维护，系统升级时全员更新同一入口。

| 代号 | 本人角色说明 |
|---|---|
| A | [Web 与轻协调](skills/ctf-system/references/roles/a-web.md) |
| B | [Pwn](skills/ctf-system/references/roles/b-pwn.md) |
| D | [Reverse](skills/ctf-system/references/roles/d-reverse.md) |
| G | [Crypto](skills/ctf-system/references/roles/g-crypto.md) |

真实姓名不公开进入仓库。本机角色登记只写 `.local/team-member.json`，可使用队内提供的个人角色卡，或首次登记自己的代号。之后说“我是某某”时，AI 可通过本机记录恢复对应角色。

```text
python tools/ctf_roles.py register --member B --profile saturday-four
python tools/ctf_roles.py register --identity-file <自己的角色卡JSON>
python tools/ctf_roles.py show
```

也可以把自己的角色卡放在仓库根目录并命名 `team-member.private.json`；它已被 Git 忽略。AI 使用 `ctf_team_role` 读取本机身份与首读路径。没有登记或角色卡时，仅凭未登记的姓名无法可靠知道代号，首次确认一次即可，不能猜人。

## 资料层次

根 AGENTS.md → 本文件 → `knowledge/README.md` → 角色返回的本类方法和 Obsidian 笔记。具体路径由 `team/roles.json` 维护，`ctf_team_role` 会检查文件确实存在。

案例位于 `knowledge/cases/`，用于学习和复现；独立解题默认不读其中已有答案材料。历史部署记录位于 `knowledge/history/`，不是当前机器配置。所有人都能按需读其他题型资料，不必整库通读。

完整的现场认领、积压分流、停滞复核和证据交接规则见 [四人分题方案](docs/saturday-four-allocation.md)。
