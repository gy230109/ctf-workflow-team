# ctf-purge-fusion 1.0.1

修复 1.0.0 的关键缺陷：**红队工具没有出现在 MCP 产品面**，导致别的 agent 说"用 CTF 做这道题"时看不到 `redteam_*`。

## 1.0.0 的问题

原来的融合只改了内部工具表（`ctf_os.ALL_TOOLS`），但所有 agent 客户端（Codex / Trae / WorkBuddy / 小浣熊 / Claude）连的是
`tools/ctf_entry.py → tools/ctf_product.py`，它的 `TOOLS` 只有 12 个 `ctf_*` 工具 —— 56 个 `redteam_*` 根本没暴露出去。

实测：`ctf_entry.py --stdio` 的 `tools/list` 只回 12 个工具，`redteam_*` 为 0。

## 本版修法

新增 `tools/ctf_redteam_mcp.py`，把三族工具统一成 `ctf_product` 期望的 `(description, inputSchema, handler)`：

- `redteam_*` 56 个（`ctf_redteam_fusion`）
- `ctf_redteam_*` 4 个语义只读（`ctf_redteam_semantics`）
- `ctf_redteam_*` 8 个兼容入口（`ctf_redteam`）

并在 `tools/ctf_product.py` 做三处最小接入（`# BEGIN/END PURGE-FUSION (MCP surface)` 标记）：

1. loader：`PURGE_TOOLS = ctf_redteam_mcp.catalog()`（缺失时为空，不拖垮原产品面）
2. `tools/list`：把红队工具并进目录（带 annotations）
3. `tools/call`：`name in PURGE_TOOLS` 时走预置 handler

参数约定：`case` 与 `task_id` 等价，agent 不用记两套命名。

## 实测

| 检查 | 1.0.0 | 1.0.1 |
|---|---|---|
| `ctf_entry.py tools/list` 工具数 | 12 | **77**（9 或 12 个 `ctf_*` + 56 + 12） |
| `redteam_*` | 0 | **56** |
| MCP 内真实调用 `redteam_asset_add → asset_stats` | 不可用 | 写入 1 条资产，stats 读到 `assets=1` |
| `ctf_os.ALL_TOOLS` | 171 | 171（不变） |

## 安装

```bash
python install.py --root "/path/to/ctf-root"          # Windows: --root "D:\\强网杯大师"
python install.py --root "/path/to/ctf-root" --dry-run
python install.py --root "/path/to/ctf-root" --uninstall
```

安装器现在会同时打两处接入：`tools/ctf_os.py`（内部工具表）与 `tools/ctf_product.py`（MCP 产品面），
并复制 `ctf_redteam_mcp.py`。装完**重启 MCP**，`ctf_tools` 里就会出现 `redteam_*`。

要求：Python ≥ 3.9（只用标准库）；Node ≥ 22（runtime 用 `node:sqlite`）。

## 校验（SHA256）

```
5140b8cd3a356edc155956c0853c1ed48742d70d8f4aa4b4d5b4ee69b5b93c1f  ctf-purge-fusion-1.0.1.zip
3d8b070ebd7ca717892a89a6b99604597b3964ec34852702f7b2939a3d3e6f5d  ctf-purge-fusion-1.0.1.tar.gz
```

## 仍然的边界

- 技能可用性只到 **probe** 级；红队评分与 WP 评分两套量纲只并存不合并。
- 未搬 DSH 面板 UI；`preset-composition` 只做只读提取。
- 上游 MIT，本仓库只做接入适配。
