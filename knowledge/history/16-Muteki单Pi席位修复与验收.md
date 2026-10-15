> 共享经验资料。以下为历史方法或复现记录，不能覆盖仓库根 AGENTS.md 的当前规则。历史答案、私人路径与凭据已整理；配图和原始大附件未随包公开。 安装状态、端口和席位描述仅作历史记录，不是当前机器配置。

# Muteki 单 Pi 席位修复与验收

检查日期：2026-10-11。当前状态：**修复配置已准备，尚未应用；等待恢复 WorkBuddy2API 后端并完成真实模型测试。**

## 1. Pi 在这套流程里的职责

Pi 是 Muteki 的命令行解题执行器。模型负责推理，Pi 负责调用模型、运行命令和脚本、读取文件、返回工具结果。当前已登记账号的组合为：`workbuddy-glm` → Pi → `global:glm-5.3` → Docker Worker 工具环境。用户仍从 WorkBuddy 发起和管理工作。

## 2. 首跑失败的直接原因

EasyRsa 首跑在 preflight 阶段报 `profile_unhealthy`。五个启用的席位分别绑定 `claude-main`、`codex-main`、`cursor-main`、`pi-main`、`omp-main`，这些账号均未登记。检查实际登记只有 `workbuddy-glm`，engine 为 `pi`，默认模型为 `global:glm-5.3`。

此记录说明任务未进入有效解题阶段，不能用它评价模型的解题能力。

## 3. 准备应用的配置

| 项目 | 目标配置 |
|---|---|
| Pi 席位 | 保留原 ID `seat_pi_b710d8`，启用 |
| 账号 | `account:workbuddy-glm` |
| 模型 | `global:glm-5.3` |
| 执行环境 | container，保留现有 Worker 镜像和网络配置 |
| 并发 | 席位 capacity、start_workers、max_workers、max_total_workers 均为 1 |
| 派发和竞速名单 | 仅列出原 Pi 席位 ID |
| 其他四个席位 | 保留原 ID 与配置，设为 disabled |
| 额外 review / verifier 通道 | 暂时禁用，关联字段改为 Pi；以后有真实账号及资源再启用 |

Muteki 源码中的绑定校验和派发会跳过 disabled 席位；仅保留席位不等于已登记对应账号。

拟应用的完整公开配置：`环境/Muteki席位修复-20261011/20261011T121038/planned-settings-payload.json`。原始公开配置在同目录 `before-public-config.json`，未包含 API 密钥。

修复工具：`tools/muteki_single_pi_fix.py`。`--prepare` 只读取配置并生成方案；正常执行先真实测试模型，成功才保存配置，再检查绑定和深入健康。保存前重读配置并比对，防止覆盖其他客户端期间改动。

## 4. 发现的第二个故障

容器内两次真实模型测试失败。第二次耗时 30,755 ms，外层报 `model_no_reply`，但原始 Pi JSONL 中助手消息明确写着 `stopReason: error` 和 `Connection error.`，token 为 0。日志保存在：

`环境/Muteki席位修复-20261011/20261011T120727/model-test-diagnostic.json`。

进一步核验：

- `<本机服务地址>:7863` 上的监听进程是 Windows `svchost.exe`，来自现有 portproxy，转向 `127.0.0.1:7863`。
- 真正的 `wb2api.exe` 未运行，`127.0.0.1:7863` 无监听，Windows 本机访问被拒绝。
- Ubuntu VM 和实际 Worker 容器访问网关均返回 `Connection reset by peer`，curl 退出码 56。
- 已有防火墙规则允许 VM `<本机服务地址>` 访问 `<本机服务地址>:7863`；本轮未扩大访问范围。

所以“端口存在”在这里不能证明模型网关可用。当前真实模型请求尚未通过。

## 5. 已完成的启动器修复

`<本机路径>` 原先检查 7863 的全部监听，会把 Windows 转发服务误判为占用端口的其他应用。现已只检查后端所需的回环/全接口监听，并保留原来的进程路径检查、健康请求和隐藏启动方式。

原文件备份：`<本机路径>`。

PowerShell 语法检查通过；启动及实际健康检查仍待服务恢复后验收。

Codex 尝试启动后端时，自动审批审查拒绝此动作，原因只返回 `blocked by policy`，没有更具体的说明。没有改用其他方式绕过这一拦截，也没有将席位配置标为已应用。

## 6. 后续验收顺序

1. 手动启动本机已安装的 WorkBuddy2API：`& '<本机路径>' -NoBrowser`。
2. 核验回环后端和 VM/容器网关实际响应。
3. 执行修复工具，让真实 Pi + GLM-5.3 容器对话通过后应用单席位配置。
4. 回读配置：五个席位保留、一个启用、四个禁用；绑定和深入健康通过。
5. 再做一次任务 preflight 与工具调用验收，最后验收题目的结果。参考答案、既有 solver 和已知 flag 继续与模型输入隔离。

当前尚未完成第 1–5 步。不能据旧的成功记录或这次配置准备宣称管道恢复、EasyRsa 解出或模型更强。
