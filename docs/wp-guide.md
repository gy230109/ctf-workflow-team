# WP 功能：安装、使用与交付边界

日常仍只需告诉 AI：“用 CTF系统做这道题。”已安装统一 Skill 的 AI 会自行建档、记录证据、撰写正文并生成报告。团队各题型共享这套协议；无须给四个人各维护一份 WP 实现。

维护人员更新系统后，按已有客户端接入方式更新 `ctf-system` Skill；`tools/connect_ai.py` 会连同角色资料安装 `references/wp-guide.md`。安装器保留其他模型、MCP 与外部修改的 Skill；如果报告冲突，先读冲突内容，不强制覆盖。旧客户端会话可能需要一次空闲重连以发现新工具。

## Word/PDF 依赖与升级

正常执行 `upgrade-to-20261016.ps1 -Target <已安装系统目录>` 时，脚本在更新代码后、运行 AI 接入安装器前，用本次选定的 Python 安装 `requirements-wp.txt`；新安装的 `setup.ps1` 同样通过 `requirements.txt` 安装这些依赖。`-Plan` 只预览迁移，不安装。若 pip 失败，升级脚本明确报告“代码更新但Word/PDF依赖未就绪”，不要据此宣称完整升级已完成。

离线或暂不需要 Word/PDF 时，可给升级脚本加 `-SkipWPDependencies`。该开关跳过安装，保留 Markdown/HTML，不保证这台机器能导出 Word/PDF；之后恢复网络再用相同 Python 补装依赖。若 `export_python` 指向另一个解释器，需要让该解释器也具备对应依赖。

需要单独补装时，用准备负责导出的 Python 执行：

```powershell
python -m pip install -r requirements-wp.txt
```

`python-docx` 负责 Word，`reportlab` 负责 PDF，`Pillow` 处理图片。核心接题与 Markdown/HTML 不需要 Word/PDF 两个可选库。无法安装某个库时，系统应保留可用格式并返回具体格式错误；不能把 Word/PDF 缺失说成已完成。

复制 `config/ctf_wp.example.json` 为未入库的 `config/ctf_wp.local.json`，按本机情况设置：

- `export_python`：可选 Python 可执行文件；留空或省略时使用当前解释器。不包含模型账号，也不把某台电脑路径提交到团队仓库。
- `formats`：默认 `docx`、`pdf`；设为 `[]` 时只保留必出的 Markdown/HTML。
- `template`：目前只支持 `plain-v1`；页面是 Letter。任意 Word 模板导入、赛事模板自动适配尚未提供。

若需验收版式，用已安装的 Word/LibreOffice 打开或渲染实际产物，检查所有页的中文、长命令、表格、截图与分页。生成文件成功只证明导出过程结束；没有逐页检查时不要声称版式已验收。

## 记录与成稿

AI 的逐步操作说明见 [WP 记录与成稿协议](../skills/ctf-system/references/wp-guide.md)。关键机制是：题面及原附件追加留存；工具调用包含行动目的；观察关联真实步骤；五类正文通过 `wp_section` 补写；`wp_review` 报缺项；`ctf_finish` 使用同一份 `report.json` 产出各格式。

报告目录中，`writeup.md` 是精简正文，`technical.md` 是完整技术附录；原始输出、附件与采集资料归入私有证据。正文保留回源关系，避免重复贴数千行 JSON。待结束操作、截图失败和未证实的结论不能被导出过程悄悄抹掉，也不能为补材料重跑已发生动作。

`include_images=false` 排除实际图片，`include_log_renders` 独立控制带“日志渲染”标识的图片；统一完成入口默认关闭冗余日志图。图像不是每题必需证据，是否符合赛事要求由实际题型与提交规则决定。

## 提交与分享

分别核对记录是否完整、正文是否清楚、格式是否生成、答案是否经过真实验证。CTFd `correct` 与 `already_solved` 分开处理，后者不能证明新候选正确；自己写“验证通过”也不会变成平台回执。

默认文本会脱敏 flag 和常见凭据，私有原始包保留真实材料，所以私有包并非自动完成的比赛最终稿。提交前在本机核对真实答案、署名和本届规则；公开前另审附件、截图像素、录屏和原始日志。仓库中只发布系统代码、指南与脱敏测试样例，不自动发布私有比赛 WP 或原始证据。
