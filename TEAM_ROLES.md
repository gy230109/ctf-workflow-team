# 团队角色和首读资料

所有人获取同一份系统与共享经验。角色决定首接队列和优先阅读内容，不限制工具访问，不代表某类题只有某台电脑能做。题型按出题方标签认领，每人一个活跃主任务，当前负责人保留验证、提交回执与 WP。

## 周六四人配置 saturday-four

| 代号 | 首接 | 第一接替 |
|---|---|---|
| A | Web、轻量协调 | Crypto |
| B | Pwn | Reverse |
| D | Reverse | Pwn |
| G | Crypto | Web |

Misc、Forensics 及其他类别从开场进入公共队列，空闲且工具合适的人可认领；不要求先做完首接类别。遇到积压或资源限制时整题转派，不常态化跨机代跑。首接类无题就分担其他队列。

## 月底七人配置 full-seven

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
