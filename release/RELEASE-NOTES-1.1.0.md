# ctf-purge-fusion 1.1.0

构建标签：2026.10.30-wpboost1（完整文件清单与哈希见仓库内 bundle-manifest.json）

## 本版内容（2026-10-30 两轮更新）

### 真实截图纠错（real-capture3）

- 统一口径：黑底日志图、登录/锁屏、空桌面、回放渲染和事后复刻页面不能作为解题截图。规范 WP 不再允许 include_log_renders=true。
- 拿到图必须用图像查看工具打开原图，核对实际应用/页面、命令或输入、输出与 source_step；再用 wp_capture_review 记录 image_step、image_sha256、accepted/rejected、capture_origin、observed_content 及 reason。只有核验通过且可读的原图计入完整性并嵌入正文；重复 SHA256 只展示一次。
- 命令行关键截图使用 kali_terminal_record(argv=[...], capture_window=true)：在有认证、禁用 TCP 的隔离 X11 显示器里启动真正的 xterm，执行一次原命令、录制同次 PTY 并采集原窗口；不读旧日志做图，执行后采集失败明确禁止重跑。
- 截图失败如实留缺项，不重放有副作用的动作；缺项只能导出明确标记的草稿。

### WP 短板改进（wpboost）

- wp_section 的 source_steps 报错直接列出全部可引用步骤号，并提示 wp_operation.operation_id 不是步骤号；wp_purpose/wp_expectation 缺失时兜底继承 operation_started 里执行前记录的值。
- 新增 ctf_note(amend_purpose=true) 事后补记行动目的：追加 purpose_amendment 事件并标记 recorded_after_the_fact，不篡改原 call 事件；体检把补记过的调用计为已覆盖并单列 purposes_amended_after_the_fact。
- wp_capture 新增 auto_review=true 自动像素预检：仅做机械检查（尺寸/非空白/非锁屏纯色），生成 observed_content 草稿并落 image_review 事件，人工可事后改写或 rejected，不冒充人工语义审阅。
- ctf_tools 空字符串 name/query 按"列出全部"处理并返回 total；wp_status 每个缺项附带具体补法提示。
- 交付 docx 被占用（WinError 32）或被编辑过时自动改存带时间戳的新文件名，不阻塞导出；wp_build 未嵌图时的 screenshots_complete 口径与 wp_status 对齐。

## 验证

- 专项自测 23 项通过；WP 回归 59 项通过（4 项可选检查跳过）。
- 当前运行注册 203 个工具；本包 3520 个文件，随包含 knowledge/ 方法与共享记录（按 docs/team-records.md 恢复）。

## 安装与升级

- 首次安装：解压后按 README.md 流程（AGENTS.md → setup.ps1 → connect-ai.ps1），不复制队长的路径、账号或 SSH 身份。
- 已有 Git 安装：git pull --ff-only 更新代码后重连 MCP；保留本机配置、身份和 WP。
- 校验下载件：对照 SHA256SUMS-dist.txt（Get-FileHash / sha256sum -c）。
