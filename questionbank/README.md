# 2026-10-13 题库公开交接

本目录来自既有 `ctf_questionbank_2026-10-13.zip`，用于交给本机维护者接入已经安装好的团队系统。源包 8,938,458 字节、126 文件，SHA256 `307724a137106ad1ae06d475e4fdee44ffbf97892456e8ca4c83f611aedff988`。

本分支只增加 `questionbank/`，不修改 main 或已有系统源码。系统升级、Trae Skill、Kali/SSH 接线由接收方合入 main。本目录不是已经完成本机接入的证明。

## 交接内容

- `bank.py`、`prompt_extract.py`、`tests/test_bank.py`：原包完整代码，字节和摘要不变。
- `data/challenges.jsonl`：2,488 条来源记录，3 条跨源别名，2,485 条初步去重记录；1,108 个比赛题、865 个课程练习、512 个在线实验。231 个保留评测条目默认不抽取。
- `data/sources.json`：18 个仓库的固定提交以及 2 个官方在线目录。
- `data/download-manifest.json`：首批 66 题、86 个文件的真实来源 URL、固定提交、大小、SHA256、Git blob SHA1、目标相对路径；总计 8,591,668 字节。原附件不提交 Git。
- `data/prompt-sources.jsonl`：比赛题原始元数据/明确题目章节的获取位置、Git blob SHA1、应提取的字段。**这是管理员输入，原始文件可能混有答案，禁止原样送给解题 AI。**
- `data/downloads.json`：初始为空，不能把云端下载记录当作本机文件已经存在的证明。
- `data/challenges.csv`：公开元数据导出。SQLite 由 `rebuild_indexes.py` 在本机重建，不把二进制数据库放进本次源码交接。
- `AGENT_GUIDE.md`、`docs/training.md`、`data/team-curriculum.json`：既有精确引导和六人六天 36 题轮换资料，作为接收方编写 Trae Skill 的输入。
- `handoff/original-package.json`、`original-package-files.json`：原 ZIP 的大小、摘要、关键文件信息和完整 126 文件清单。
- `handoff/cloud-validation.json`、`cloud-pilot-summary.json`：此前云端核验摘要；不代表 Windows/Kali 验收。
- `handoff/public-file-manifest.json`：本次公开导出每个文件的 SHA256/大小/Git blob SHA1，明确与原包的不同。

## 题面公开策略

未整体转载第三方比赛题面，不因仓库公开就推定全部允许重分发。公开索引保留题名、分类、来源、附件与环境线索，比赛题 `description` 为空、`full_prompt_available=false`。本机维护者按 `prompt-sources.jsonl` 在正常来源访问范围内取得原资料，只提取题面；JSON/YAML 只取指定描述字段，Cybench 只取 `hard_prompt`，不能导入 `flag`、`flags`、`base64_flag`、`subtasks`、`easy_prompt`。Markdown 使用随包 `prompt_extract.extract_question`，遇到不完整边界仍需人工核对。来源、许可和署名继续保留。

因此公开 JSONL/CSV 的摘要与原包不同；它们不是原文件的逐字副本。源包原始摘要另见 handoff。下载完附件仍需补齐题面和验收挑战环境才能训练。

## 本机接收步骤

1. 取得此分支 `questionbank/` 目录，使用已经能运行 CTF-OS 的 Python 3.10+，无需为题库入口安装第三方库。原有虚拟机、SSH、用户配置由现有系统复用。
2. 核对 `handoff/public-file-manifest.json` 中的逐文件摘要，读取 `data/summary.json` 与上述题面策略。
3. 执行 `python -X utf8 rebuild_indexes.py`，重建公开索引的 CSV/SQLite，核对 SQLite integrity 与记录数。该数据库摘要与原包数据库不同；跨 SQLite 版本也不要求二进制摘要一致。
4. 执行 `python -X utf8 bank.py stats` / `search --category pwn`。此时完整下载数应该是 **0**。
5. 按首批清单的不同 `task_id` 调用 `python -X utf8 bank.py fetch <ID>`。现有 fetch 核验固定提交 Git blob SHA1，并生成本机 `downloads.json`；接收方再逐项对照清单的 SHA256、大小和相对路径，只有一致才计为本机下载成功。SHA256 缺失的其他目录附件只具备上游 Git blob 标识，不能冒称已经本批下载/校验。
6. 管理员安全补齐题面并重建索引。文件和题面通过后，用 `bank.py prepare <ID> --out <成员独立目录>`；仅把准备目录交给解题 AI。缺题面时默认拒绝，不能用 `--allow-incomplete` 掩盖尚未完成的接入。
7. 按 `AGENT_GUIDE.md` 接现有 `wp_init → ctf_profile → 分题型工具 → wp_build`，所有分析携带同一 `wp_case`。实例必须是维护者明确给出的本地目标或本人在线实验；不使用旧比赛端点。

本次只有目录、附件摘要和入口测试通过；未部署挑战、未测试实际解题正确率、未在你的 Windows/Kali 上运行。接收方完成这些验收后再更新本机状态。
