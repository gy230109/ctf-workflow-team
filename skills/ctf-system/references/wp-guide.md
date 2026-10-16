# WP 记录与成稿协议

在开始解题、继续同题或准备成稿时读本页。用户给题目即可；由 AI 使用统一入口完成建档、记证据、补正文和检查，不把下面流程作为一长段交接话术要求用户重复。

## 接题和恢复

新题 `ctf_start` 保存题面、来源和原附件；继续或换 AI 用 `ctf_progress` 恢复同一任务。题面后补、CTFd 附件后下载时，按实时 schema 使用 `wp_intake` 追加归档。追加内容与旧记录分别留存，不能改写已校验的 session、timeline 或原附件。只归档本题所需材料；其他题的答案、solver 或私人凭据不混入题面。

## 边做边记

- 关键 `ctf_call` 的 arguments 加 `wp_purpose` 写本步目的，可加 `wp_expectation` 写准备核对的现象。先查询实际工具 schema，原有 `confirm` 等要求继续满足。
- 工具返回 `wp_record.step` 后，使用 `ctf_note status=observed source_step=步骤号` 记短结论：看见了什么、它支持什么。假设用 `hypothesis`，待办用 `todo`。观察必须关联已有调用或截图；注释仍是作者对证据的解读。
- 工具自动记录开始、完成、完整原始输出与失败。若调用中断或采集失败，读取记录错误并保留缺项；不要为凑截图、重放日志或完善 WP 再执行已执行动作。
- 连续网页会话可附实际 PNG/Trace，GDB 可附实际 MI 流。需要 PTY 回放时用 `kali_terminal_record`；普通调用沿用原工具。Windows 调试器窗口采集需实际目标可用；额外截取指定窗口用 `wp_capture`。日志渲染图会明确标注，不能充当真实界面截图。

## 写清楚正文

通过 `ctf_call` 调 `wp_section`，使用实时参数填写以下章节：`overview` 题目概况与关键思路；`analysis` 已有证据与判断；`solution` 最终采用的步骤；`validation` 实际验证范围与回执；`reproduction` 环境、命令、脚本及输入输出。简洁解释“证据如何支持下一步”，避免把整份 JSON 日志反复粘贴进正文。

涉及结果与结论的正文提供 `source_steps`，引用真实 call/capture 步骤；关联存在只说明可以回源，**不会把文字声明自动认证为正确**。记录选定思路、可复现操作和可观察依据即可，无需记录隐藏思维过程。失败路线及暂未证明的推测保留原状态。没有做过的验证写“未验证”，不能补写为已通过。

## 查缺、导出与移交

1. 通过 `ctf_call` 调 `wp_review`，检查题面与附件、正文、观察、未结束操作、采集错误和验证状态。合法但不完整的草稿仍可能返回 `ok=true`；以质量报告的缺项和状态为准。
2. 关键缺项若已有真实证据，补注释或正文；若当时未采集，记为未完成。`ctfd_submit` 的 `correct` 才能认证该次候选；`already_solved` 不证明本次候选正确。未接入判题时注明可复现验证的实际边界。
3. `ctf_finish` 生成 `writeup.md` 清晰正文、`technical.md` 完整技术附录、HTML、共用的 `report.json`、清单和私有证据 ZIP。Word/PDF 逐格式生成；缺依赖时保留其余格式并报告错误。完整日志与原件在证据目录，正文预览截断处应能找到完整来源。
4. 记录完整、正文达到提交要求、文件导出成功和真实答案验证是不同结论。检查返回字段及错误，不用一个 `ok` 概括全部状态。

默认文本会遮盖 flag 与常见凭据；`private_bundle=true` 仍不表示已得到可直接提交的比赛最终稿。提交前核对本届要求，在本机核对并补齐真实答案、格式、署名及必需截图。公开前另审题目版权、原始附件、日志、录屏与截图像素；文字脱敏不能清掉图片中的敏感内容。跨机交接完整任务与证据，`ctf_progress` 本身不等于跨机自动同步。

## 格式与依赖边界

Word/PDF 可选依赖为 `requirements-wp.txt` 中的 `python-docx`、`reportlab` 和 `Pillow`。`config/ctf_wp.local.json` 可从示例配置复制，选择安装了依赖的 `export_python`；未指定时使用当前 Python。`formats=[]` 可只保留 Markdown/HTML。导出异常按格式报告，不自动改用其他账号或安装软件。

当前内置模板只有 `plain-v1`，页面为 Letter；没有任意模板导入功能。`include_images=false` 排除实际图片；日志渲染图由独立 `include_log_renders` 控制，统一 `ctf_finish` 默认不生成这类冗余图片。切换 AI 后继续查实时工具与同题记录，不重建一个丢失证据的新任务。
