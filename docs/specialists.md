# 六类专项工具与依赖

先 `ctf_profile category=<题型>` 查看路线，再实际 `ctf_specialist_status`。接口目录和参数以 `/tools` 为准；看 `modules.<名称>.import_usable`，不要只看安装元数据或文件存在。

通过现有固定身份的 Kali 桥上传代码与 JSON 请求，在独立 `.venv-specialists` 执行。原始附件和回收文件均验证 SHA256；跨 case 文件拒绝，共用 WP 必须同题。默认 60 秒/1536 MiB，Chromium 使用同任务 RSS 监测；符号执行步数和活动状态受限。

Web 四项、Pwn 三项、Reverse 三项、Crypto 五项、Misc 三项、Forensics 两项，再加 profile/status/install 三项，共 23。详细参数与验证方法见 Skill references/solving.md。HTTP/截图/依赖安装必须真实布尔 confirm=true；这是工具参数，不是额外用户确认流程。

安装：`update.ps1 -InstallSpecialists`，或按类 `-Category reverse`。原生 Chromium/GDB/sqlmap/ffuf/tshark/7z/exiftool 复用已有安装；没有时报告对应缺项。Volatility3 的 help 仅为入口检查，真实分析需镜像和符号。

当前兼容约束 angr<10/bitstring<5；队长实际验证为 angr 9.3.4、bitstring 4.4.0。记录各机器版本并实际导入。候选不自动成为答案，符号/密码结果必须独立验证。
