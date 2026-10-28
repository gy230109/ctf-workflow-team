# ctf-purge-fusion 1.0.0

把 [dsh-purge](https://github.com/kingcharleslzy-ai/dsh-purge)（破甲 1.6.60 @ 27919a32）
的红队能力完整接进 CTF 系统：56 个 `redteam_*` 工具（各自 JSON Schema）+ 23 个红队技能 + 语义层，
与原 `ctf_*` 共用一套 MCP 与同一份 `task_id` 隔离。

## 安装（装到你自己的 CTF 系统）

```bash
python install.py --root "/path/to/ctf-root"          # Windows: --root "D:\强网杯大师"
python install.py --root "/path/to/ctf-root" --dry-run
python install.py --root "/path/to/ctf-root" --uninstall
```

安装器：逐文件核对 manifest 的 SHA256 → 备份 `tools/ctf_os.py`、`AGENTS.md`
→ 写入资产与模块 → 追加 `# BEGIN PURGE-FUSION` 接入块 → 自检（`ALL_TOOLS` 数量 + runtime `list`）。
装完重启 CTF 系统 MCP，`ctf_tools` 里才会出现 `redteam_*`。

要求：Python ≥ 3.9（只用标准库）；Node ≥ 22（runtime 用 `node:sqlite`）。

## 本次改动

- 新增 `integrations/purge-redteam/`：上游 `lib/redteam` 18 个模块（含 `tools.js`）、`presets/redteam`、
  23 篇 playbook、schemas；新增 `runtime/redteam-mcp.mjs`（list / call / store）与 `ctx-shim.mjs`
  （cordis 插件 → 裸函数表适配，上游文件保持原样可校验）
- 新增 `tools/ctf_redteam_fusion.py`（56 工具注册 + 运行时调用）、`tools/ctf_redteam_semantics.py`
  （技能 / 预设 / 评分 / 角色 四个只读工具）
- 新增 `skills/redteam-*`（23 个）与 `skills/redteam-index.json`
- 新增 `config/purge-redteam-preset.md`、`docs/purge-redteam-scoring.md`
- 修改 `tools/ctf_os.py`：末尾追加带标记的接入块（删除该块即回滚）
- 修改 `AGENTS.md`、`README.md`：增补 purge-fusion 说明

## 校验（SHA256）

```
024a69462d1c42af4d490d039d08be992135f24e27744b9299a7196452a2d069  ctf-purge-fusion-1.0.0.zip
43f87562c90cedb885889f1f6c155186a298502fd4dae03374957fe6872e1d4f  ctf-purge-fusion-1.0.0.tar.gz
```

核对：`Get-FileHash .\ctf-purge-fusion-1.0.0.zip -Algorithm SHA256`（PowerShell）
或 `sha256sum -c SHA256SUMS-dist.txt`（Linux/macOS）。

## 已知边界

- 技能可用性只到 **probe** 级（PATH 上有没有那个二进制），不代表工具可打。
- 红队评分与 CTF WP 评分两套量纲：只并存，不合并、不替代平台判题。
- 未搬 DSH 面板 UI；`preset-composition` 只做只读提取，不执行宿主组合逻辑。
- 上游 MIT，本仓库只做接入适配。
