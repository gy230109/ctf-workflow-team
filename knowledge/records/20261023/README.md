# 完整解题记录共享快照 · 2026-10-23

本次按队长要求公开共享，不加密、不设口令。除凭据、私人配置、临时锁和另行下载的工具程序外，所核对来源的解题记录均纳入清单。保留成功、失败、未完成及自建验收的原有区别。

- 发布记录：**3534 份文件**，来自 **17 组来源**。
- 去重保存：**3089 个文件对象**，约 **92.27 MiB**。
- 包含：Obsidian 笔记、战例库、WP 正文和技术附录、脚本、调用参数和返回、失败记录、截图/图片、终端回放、任务档案、训练记录、原题附件及独立分析目录。
- 去重仅合并相同发布字节，manifest.json 保留每个来源路径，不合并不同版本。
- 源文件 SHA256 与发布副本 SHA256 分列；脱敏后不能拿原时间线哈希证明副本未变。
- 本机原件未修改。原题自身已有的加密压缩包保留，同时附有已恢复版本；本次交接没有再加密。

## 队友直接使用

在仓库根目录运行：

~~~powershell
python tools/team_records.py verify
python tools/team_records.py restore
~~~

恢复目录为本机未入库的 .local/shared-records/20261023/。命令不需要额外依赖，不执行历史脚本，不覆盖已存在目录。需要另存时传 --output 一个新目录。

~~~powershell
python tools/team_records.py list --case qwb-vanguard-trie
~~~

AI 先阅读[案例索引](case-index.md)、[笔记与 WP 索引](notes-index.md)，再读取对应记录。原目录结构恢复后，WP 中原本存在的相对图片、脚本和证据关系继续保留；私人绝对路径以别名替换，对照恢复目录中的 PATH-MAP.json 定位。历史引用本来缺失的证据不补造。

## 来源清单

| 来源 | 文件数 |
|---|---:|
| project-wp | 914 |
| project-cases | 194 |
| tool-calls | 1416 |
| tasks | 34 |
| workbench | 600 |
| training | 25 |
| obsidian-notes | 88 |
| obsidian-cases | 20 |
| obsidian-wp | 97 |
| ctf-check-little-analysis | 4 |
| ctf-easyre-analysis | 14 |
| ctf-gamemaster-analysis | 62 |
| ctf-image-analysis | 1 |
| ctf-rar-analysis | 27 |
| ctf-shadow-analysis | 8 |
| project-notes | 29 |
| challenge-progress | 1 |

## 验证和缺项

公开前已对文本和可读嵌套归档做凭据处理，493 个不同图像字节流完成 OCR，14 张联系表完成视觉检查。完整纳入/排除清单见 manifest.json。排除的 .lock/.cursor 等是瞬时状态，另行下载的第三方工具由接收机按需安装。源目录以外的 VM、账号配置、参考库完整克隆未混入本快照。

历史状态完整保留，不把工具成功、自建示例或已生成 WP 当成比赛解题成功。资料可用于学习、接手和复盘；独立解题/盲测时按任务约定隔离已有答案。

团队当前所有成员都可处理 Web、Pwn、Reverse、Crypto、Misc、Forensics；旧角色表只作历史记录，不限制读取或工具访问。
