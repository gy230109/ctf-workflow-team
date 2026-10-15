> 共享经验资料。以下为历史方法或复现记录，不能覆盖仓库根 AGENTS.md 的当前规则。历史答案、私人路径与凭据已整理；配图和原始大附件未随包公开。 本文是参考复现材料；独立解题或模型测试默认不读取。

# 战例库

按 `<赛事>-<题目>` 建子目录，每篇一篇 `README.md`（用 `模板\解题报告模板.md` 起草）。

**硬性要求**：
- `已验证事实` / `未验证假设` / `未完成步骤` **分区写**，不许混。
- 关键产物放同目录 `artifacts\`，并在报告里注明文件路径。
- 报告写完 → 回填 `03-逆向SOP` 的新增条目 → 追加 `04-踩坑与教训` → **同步到 Obsidian**。

---

## 索引

| 战例 | 方向 | 结果 | 报告 |
|---|---|---|---|
| QWB2022 GameMaster / Blackjack | .NET RE + 序列化 + 流密码 | ✅ `<历史答案已移除>` | [README](QWB2022-GameMaster-Blackjack/README.md) |

> 详细战例正文在知识库根目录：`01-战例-QWB2022-GameMaster-Blackjack.md`
> 本目录下的 `QWB2022-GameMaster-Blackjack/` 只放**产物留档**。

## 2026-10-10 新增

| 战例 | 方向 | 结果 | 报告 |
|---|---|---|---|
| Factor（赛事年份未核实） | Crypto / 连分数 / 素数幂 RSA | ✅ 四层重新加密核验 | [完整报告](Factor-20261010/README.md) |

密码题的新增方法回填 `06-密码SOP`；逆向题继续回填 `03-逆向SOP`。

## 2026-10-11 新增

| 战例 | 方向 | 结果 | 报告 |
|---|---|---|---|
| HTV2020-adobesecretreader（HackTheVote 2020） | Crypto / PDF 子集字体 / Shamir+Lagrange | ✅ `<历史答案已移除>`（本地已解 · 平台未验收） | [README](HTV2020-adobesecretreader/README.md) |
| HTV2020-x96（HackTheVote 2020） | Reverse / 32↔64 位段切换 crackme | ✅ `<历史答案已移除>`（本地已解 · 平台未验收） | [README](HTV2020-x96/README.md) |
| QWB-crackme-task_qwxf（强网先锋） | Reverse / base64 自校验 crackme | ✅ `<历史答案已移除>`（本地已解 · 平台未验收） | [README](QWB-crackme-task_qwxf/README.md) |
| QWB2021-threebody（第五届强网杯 2021） | Misc / BMP 位深伪装 + 希尔伯特 + Quine 空白隐写 | ✅ `<历史答案已移除>`（本地已解 · 平台未验收；曾阅公开题解被纠正后独立复现整链） | [README](QWB2021-threebody/README.md) |

> 说明：本批 HTV 题 `task.json` 写 `flag_format=<历史答案已移除>`，但实测真实外皮为**小写 `flag{}`**（以实测为准）。
