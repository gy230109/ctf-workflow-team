# WP、截图、恢复和复核

## 持久记录位置

每题 `wp/cases/<case>/` 包含 session、时间线、raw 和 images；导出在 reports 的独立版本目录。核心桥在自己的 cases 目录保留 input/work/results 和执行日志。实际布局和字段以当前实现为准。目录存在不代表题目已经解出。

1. `wp_init case=<独立题号> title=<标题> category=<类别>`。
2. 实际 CTF-OS 调用显式加 `wp_case=<同题号>`。桥接工具的 `case` 同题。读取返回的 `wp_record`；记录失败时底层动作可能已发生。
3. `wp_note` 的 observed 引用真实 `source_step`，hypothesis 记录尚未证明的解释，todo 记录下一步与预期判据。失败和放弃路线同样保留，不改写原记录。
4. `wp_status` 验证时间线和文件摘要，`wp_build` 生成中文证据稿。导出不自动判定题目成功。

```powershell
.\.venv\Scripts\python.exe -X utf8 tools\ctf_os.py --once wp_note --args case=practice_demo status=observed source_step=2 text=该步骤真实返回最大公约数12
.\.venv\Scripts\python.exe -X utf8 tools\ctf_os.py --once wp_status --args case=practice_demo
.\.venv\Scripts\python.exe -X utf8 tools\ctf_os.py --once wp_build --args case=practice_demo
```

## 证据层级

| 实际得到的结果 | 可写结论 |
|---|---|
| 工具目录、连接、认证状态 | 该接口可发现/连接成功/已认证 |
| 工具真实输出和退出码 | 对明确输入完成了该步分析 |
| Z3/angr/统计搜索候选 | 某条件下的候选；尚需回放/独立验证 |
| 目标程序实际回放或数学/密码关系复核 | 已验证该条件/中间结论 |
| 真实比赛平台接受、或题目自身确定性验证 | 对该题有成功证据；记录方法和范围 |

不要把截屏图、格式校验、两个 Agent 同意或已知样例通过提升成比赛成功证据。记录资源/调用次数有助于系统改进，但不改变证据级别。

## 截图

`wp_capture` 默认取配置 VM 的实际界面。网页/调试器客户端实际 PNG 可用 mode=file 导入并写来源；工具渲染的命令日志图应明确为非屏幕截图。没有实际画面就写缺失，不造图。

网页专项的 PNG 摘要回收可自动入该题 WP，但导出前仍检查像素。WP 默认不导出截图；确认截图没有凭据、个人标识或非必要答案后才 `include_images=true`。文字遮盖不能证明所有秘密已移除，原始 raw 与账号不进公开仓库。

## 新会话或压缩后的恢复

重新定位 → 读取当前本机说明和工具目录 → 找到用户明确的 case → `wp_status` → 阅读该题最近 observed/hypothesis/todo 和必要 raw 返回 → 查当前 VM/服务/调试器现场 → 继续已授权工作。

没有明确 case 时只列题号和标题；不能唯一识别才补问题号，不批量读取历史答案。旧 WP 和聊天摘要用于线索，不替代完整性验证。已知中断的网页 GET 等只读步骤可按需要重跑；未知提交、付费派单、调试运行等先核查现场，不盲目重放。

## 多人交接

共享题号、当前已验证事实、证据步骤、失败/假设、下一步及环境缺项。不要共享账号、私钥、参考答案或把所有历史solver发给候选模型。每个题目一个执行者写同一时间线；复核者独立 case 或只读证据，避免并发覆盖。

## 中文 WP 完成标准

题面与运行范围、附件 SHA256、分析路径、关键实际命令/代码与结果、候选验证、失败路线、环境要求和复现方法均能由证据支持。分已验证/未验证/未完成；补写叙述引用步骤。模型评价输入与参考答案保持分开；只在用户明确授权时公开符合比赛/题源规则的 WP。
