# Jev 接入

CLI、HTTP 和 MCP stdio 均使用 CTF-OS 的统一 Jev 工具。Jev 负责当前题型判断、给定候选评估；执行、截图和 WP 使用原有工具。

## 本机配置

适配器使用 Python 标准库，不需要额外 SDK、模型权重或常驻进程。复用本机环境变量 `OPENROUTER_API_KEY`。默认 endpoint 是 `https://openrouter.ai/api/alpha/decisions`，模型为 `typesafe/jev-1.13`。

需要调整时复制 `config/jev.example.json` 为 `config/jev.json`，该本机文件已被 Git 排除。配置 `api_key_env` 可以改用其他密钥环境变量名；`CTF_JEV_CONFIG`、`CTF_JEV_ENDPOINT`、`CTF_JEV_MODEL` 分别覆盖配置路径、端点、模型。不要把密钥写入配置、工具参数、Git 或截图。设置环境变量后，重启服务/重新连接 MCP，让新进程继承它。

```powershell
.\.venv\Scripts\python.exe -X utf8 tools\ctf_os.py --once jev_status
```

`configured=true` 只代表本机配置和密钥存在，`live_verified=false` 表示未验证账号、网络、推理。团队安装报告在 `optional_components.jev` 中显示这一状态。缺少 Jev 不影响核心部署。

## 工具与使用

| 工具 | 功能 | 请求模型 |
|---|---|---|
| jev_status | 只检查本机配置 | 否 |
| jev_triage | 当前题面和观察的题型、信息缺口判断 | 是，需布尔 confirm=true |
| jev_decide | 自定义 choice、score、noul 问题，评估固定候选/标准 | 是，需布尔 confirm=true |

Jev 请求使用队员自己的 OpenRouter 额度。部署、启动和自测不发起推理。下例仅在用户授权使用模型、已配置密钥后执行；示例是自建输入，不是比赛成绩：

```powershell
.\.venv\Scripts\python.exe -X utf8 tools\ctf_os.py --once wp_init --args case=jev_demo title=Jev接入验证 category=misc
.\.venv\Scripts\python.exe -X utf8 tools\ctf_os.py --once jev_triage --args "challenge=自建练习：分析一个ELF程序的输入约束" "observations=当前只有题面，尚未分析程序" confirm=true wp_case=jev_demo
.\.venv\Scripts\python.exe -X utf8 tools\ctf_os.py --once wp_build --args case=jev_demo
```

有多个候选时，通过 MCP/HTTP 传入 JSON 对象调用 jev_decide，或在 Python 中构造对象交给 ctf_os.call_tool。不要拼接含嵌套 JSON 的 shell 命令。示例参数：

```json
{
  "state": {"observation": "自建示例：只有文件类型信息，尚无执行输出"},
  "questions": {
    "next_step": {
      "type": "choice",
      "instructions": "Which option is supported by the current observation?",
      "criteria": {
        "inspect": "Inspect the provided file before selecting an exploit",
        "unknown": "More information is needed to choose a concrete approach"
      }
    }
  },
  "confirm": true,
  "wp_case": "jev_demo"
}
```

choice 的 criteria 是至少两个选项的对象；score 是至少两个有序等级的数组；noul 可省略 criteria，或用 true/false 描述。每题必须有完整 instructions。客户端验证返回类型、固定选项、概率和 score 的 legend，异常响应按失败处理。

## 工作流

1. 如需要 Jev，先调用 jev_status；未配置时明确记录不可用，继续使用现有工具。
2. 题型不明时用 jev_triage，有具体候选时用 jev_decide。只提供当前题目必要观察，不把历史答案、恢复的密钥或已有 solver 发给候选模型。
3. Jev 返回建议后仍需实际工具验证；不得用预测替代动作授权或 flag 验证。
4. 调用携带 wp_case 自动进入本题证据；成功和失败均保存。建议作为假设记录，实际输出和截图按原有流程留证。
5. 最后 wp_build 生成中文证据稿。Jev 失败不会阻断其他工具。

401/402/403 等错误按状态码报告，限流/暂时服务器错误有限重试。超时不自动重复可能已计费的推理。传输不跟随重定向，密钥不进入返回和日志。

## 验证范围

离线测试涵盖请求格式、三种返回类型、错误/限流/超时、密钥保护、真实 MCP stdio 子进程握手和工具列表，以及 Jev → CTF-OS → 独立题号 → 中文 WP 的留证路径。使用 fixture 响应，不调用收费模型。

未验证：实际队员账号、网络、真实 Jev 判断效果和 Windows/Kali 全链路。离线通过不能说模型或完整解题已验收。

官方协议参考：[OpenRouter 请求/返回示例](https://openrouter.ai/blog/insights/what-is-jev/)、[Jev 模型页面](https://openrouter.ai/typesafe/jev-1.13)。
