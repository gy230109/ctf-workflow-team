# CTF 系统 × 破甲（Purge）完整融合 · 架构契约 v1

## 现状（已核实的“半截集成”）
```
D:\强网杯大师\                        ← 原始 CTF 系统（Python，tools/ 100+ 模块，ctf_os.ALL_TOOLS 注册表）
  tools\ctf_os.py            (1066 行, ALL_TOOLS = solver ∪ OPS ∪ SEC ∪ SCRIPT ∪ PC ∪ knowledge ∪ pcap)
  tools\ctf_redteam.py       (155 行, 8 个 ctf_redteam_* 工具 → 子进程调 bridge.mjs)
  integrations\purge-redteam\
    bridge.mjs               (53 行, stdin/stdout 单次调用, 55 个 store 操作)
    manifest.json            (56 条 tool_mapping, 23 playbooks, upstream commit 27919a3)
    references\*.md          (23 篇红队 playbook)
    schemas\*.json           (源工具参数定义)
    upstream\lib\redteam\    (只 vendored 了 8 个“纯”模块：schema/store-core/score-rules/report-replay/remove-tree/platform-config/validate/ip-utils)
    suite-ui.html / OPEN_PANEL / upgrade-installer.py
```
**缺失**（= 只装了一部分）：
1. `lib/redteam/tools.js`（125 KB，56 个工具的**工具层**实现与呈现）
2. `skill-fixes.js`(35 KB)、`skill-availability.js`(17 KB)、`preset-composition.js`(16 KB)
3. `presets/redteam/{agent.cordis.yml,preset.yml,anchor-gate.mjs}`（红队预设与身份层）
4. 23 篇 playbook 只当“参考资料”读，**没有**进 CTF 技能注册表
5. score-rules 未接 WP 评分；role prompts 未接 ctf_suite 角色
6. 56 个工具被压成 2 个泛化入口（`ctf_redteam_query` / `ctf_redteam_record`），agent 看不到独立工具与各自 schema

## 目标形态
一个 MCP 服务、两族工具无缝共存：
- `ctf_*`（原 CTF 系统，全部保留，行为不变）
- `redteam_*`（破甲全量 56 个，**每个都是独立工具**，带 `lib/redteam/schema.js` 的 JSON Schema）
共用：`task_id ⇄ engagement` 绑定、证据链（WP step ↔ 资产/漏洞/POC）、评分（score-rules）、技能（23 playbook 进注册表）、预设（redteam 身份层与 CTF agent 组合）。

## 目录契约（新增/改动）
```
D:\强网杯大师\integrations\purge-redteam\
  upstream\lib\redteam\        ← 补齐全部 18 个模块（含 tools.js/skill-fixes/skill-availability/preset-composition）
  upstream\presets\redteam\    ← agent.cordis.yml / preset.yml / anchor-gate.mjs
  upstream\skills\redteam\     ← 23 篇（与 references 保持同源）
  runtime\redteam-mcp.mjs      ← 【新】常驻/单次两用运行时（见下）
  runtime\catalogue.json       ← 【新】由 runtime 生成的 56 工具目录（name/description/parameters）
D:\强网杯大师\tools\
  ctf_redteam_fusion.py        ← 【新】把 catalogue 注册进 ALL_TOOLS，dispatch 到 runtime
  ctf_redteam.py               ← 保留 8 个兼容工具；内部改为复用 fusion 的运行时路径
  ctf_os.py                    ← 仅追加 1 行 import + 1 行 ALL_TOOLS.update(fusion.TOOLS)
D:\强网杯大师\skills\           ← 23 个 redteam 技能落位（若已有同名则合并描述，不覆盖正文）
D:\强网杯大师\integrations\purge-redteam\FUSION.md  ← 【新】融合说明、工具对照、回滚
```

## 运行时契约（`runtime/redteam-mcp.mjs`）
stdin 单请求 → stdout 单 JSON，父进程用 `subprocess.run(timeout=…)` 调；另支持 `--serve` 常驻行协议（每行一个请求）。
```jsonc
// 请求
{"op":"list"}                                        → {"ok":true,"tools":[{"name":"redteam_asset_add","description":"…","parameters":{…JSON Schema…}}]}
{"op":"call","tool":"redteam_asset_add","args":{…},"case":"ctf-xxxxxxxxxxxxxxxx"} → {"ok":true,"result":{…}}
{"op":"store","name":"assetAdd","data":{…},"case":"ctf-…"}                        → {"ok":true,"result":{…}}   // 兼容路径
// 错误统一：{"ok":false,"error":"CODE","detail":"…"}
```
- 数据根：`D:\强网杯大师\.local\purge-redteam`（每 case 一个 engagement，`store.openEngagement(case,[],{bindCurrent:false})`）
- `case` 必须是 `ctf-[a-f0-9]{16}`，且 `.local/ctf-system/tasks/<case>/task.json` 存在（沿用现有校验）
- 禁止符号链接存储路径（沿用 bridge.mjs 的 `noLinks`）
- 不联网、不自动装依赖、不写 CTF 任务库之外的位置

## Python 契约（`ctf_redteam_fusion.py`）
- `load_catalogue()`：读 `runtime/catalogue.json`；缺失时调 runtime `{"op":"list"}` 生成并缓存（带 mtime 校验）
- `TOOLS`：`{ "redteam_xxx": (handler, description, parameters) }`，直接并入 `ALL_TOOLS`
- handler 签名沿用现有 CTF 工具约定：`def h(args: dict) -> dict`，异常用 `ValueError`/`RuntimeError`
- 保留：`task_id` 绑定、`source_step` 证据校验（不得引用 `ctf_redteam_*` 自身作为执行证据）、`timeout ≤ 600`、`confirm=true`（主动操作）
- 兼容：现有 8 个 `ctf_redteam_*` 工具行为不变（内部可改走 fusion）

## 语义融合契约
| 破甲层 | 落点 | 验收 |
|---|---|---|
| 23 playbook | `integrations/.../references` + `D:\强网杯大师\skills\redteam-*`，登记进 CTF 技能清单 | 技能列表出现 23 项，`ctf_redteam_playbook` 仍可按行读 |
| skill-availability / skill-fixes | 技能可用性探针接入 `ctf_redteam_capabilities`（报告“已装/缺失”，不假装可用） | capabilities 输出含逐技能 available 字段 |
| preset-composition + agent.cordis.yml | 红队身份/规则段落进入 CTF agent 配置的组合层（生成 `D:\强网杯大师\config\purge-redteam-preset.md` 供 AGENTS/角色引用） | 生成物存在且与 upstream 内容同源 |
| score-rules | 接 WP 评分：`ctf_wp` / `ctf_wp_review` 可读红队评分（不改变原 WP 结构） | 评分 API 可返回 scoreChain/scoreReport |
| role prompts | `ctf_suite` / 角色派单引用 role-section 文本 | role 列表包含红队角色 |

## 非目标
- 不搬 `ui.js` / `client.js`（DSH 面板 UI，CTF 系统无对应插槽）
- 不改 `ctf_os.py` 既有工具行为，不重排现有 WP/任务库结构
- 不联网、不改系统策略、不自动起服务

## 验证（Lead 最终执行）
1. `python -c "import ctf_os; print(len(ctf_os.ALL_TOOLS))"` 工具数增加 56（含兼容 8 个不重复计数）
2. `node integrations/purge-redteam/runtime/redteam-mcp.mjs <<< '{"op":"list"}'` 返回 56 项，schema 合法
3. 端到端：`ctf_start` → `redteam_asset_add` → `ctf_redteam_query assets` → `redteam_score_report` → `ctf_finish`
4. `python tools\test_ctf_os_system.py`、`tests\` 既有用例全绿
5. 回滚：删 `ctf_redteam_fusion.py` + 还原 `ctf_os.py` 那 1 行，其余资产无害保留
