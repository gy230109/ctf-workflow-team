> 共享经验资料。以下为历史方法或复现记录，不能覆盖仓库根 AGENTS.md 的当前规则。历史答案、私人路径与凭据已整理；配图和原始大附件未随包公开。 安装状态、端口和席位描述仅作历史记录，不是当前机器配置。

# Trae 接入作战工具链（CTF-MCP）· 2026-10-11

## 1. 为什么是"Trae 调我们"，不是"我们把 Trae 塞进 Muteki"

一开始的思路是错的：想把 Trae 变成 Muteki 的第 12 个引擎。**实测后否定**：

| 检查项 | 实测结果 |
|---|---|
| Trae 的本地端口 | `127.0.0.1:51000` 无 HTTP 响应；`4886` / `2442` 回 `400 WebSockets request was expected` |
| 结论 | 这三个是 **IDE 内部的 WebSocket IPC**，不是 REST，更不是 OpenAI 兼容 API |
| Muteki 引擎目录 `cli_engines/engines/` | 只有 **11 个**（claude / codex / cursor / devin / droid / grok / kimi / omp / opencode / pi），**源码全文无 trae** |

Muteki 的 worker 在容器里 **headless** 运行，要求「CLI + 注入凭证」；Trae CN 是 GUI 登录制 IDE，形态不匹配。

**正确的方向是反过来** —— Trae 原生支持 MCP（`%APPDATA%\Trae CN\logs\<日期>\mcp-servers-main.log` 实证，
该日志每次启动都会创建；本机有 5 天份）。于是：**把我们的工具包成 MCP server，让 Trae 的模型来驱动**。

这样做的好处：

1. **合规** —— 就是在 IDE 里正常用 AI 助手，不碰 ToS 灰区，**能消耗老板已有的 Trae 积分**
2. **中间过程可见** —— 每次调用的参数和返回都在本地 stderr/返回体里，不像远端 solver 那样是黑盒
3. **能力自己说了算** —— 想加工具就加，不受远端 solver 环境限制
4. **契合训练规矩** —— 工具是"扳手"，不是"答案"；flag 相关**只做格式校验，不产出答案**

## 2. 交付物

| 文件 | 作用 |
|---|---|
| `tools/ctf_mcp_server.py` | MCP server 本体，**纯标准库**、零三方依赖 |
| `<本机路径>` | Trae **全局** MCP 配置（已写入） |
| `<本机路径>` | **项目级**配置（已写入，打开这个目录时生效） |

## 3. 工具清单（15 个）

### 数论 / 密码
| 工具 | 用途 |
|---|---|
| `math_gcd` | 最大公约数。RSA 多模数攻击第一步 |
| `math_modpow` | 模幂 `pow(b,e,m)` |
| `math_modinv` | 模逆元 |
| **`crypto_shared_factors`** | **两两 GCD 找共享素因子** —— 多模数 RSA 永远先跑这步，比因式分解便宜几个数量级 |
| `crypto_rsa_decrypt` | 已知 p/q/e/c 的标准 RSA 解密，附十六进制与可打印串 |

### 编码 / 杂项
`util_hex` · `util_unhex` · `util_b64` · `util_rot`（同时给正反两个方向） · `util_int_bytes`（大整数↔字节，RSA 端序最易错）

### GB 逆向（转调 `tools/gbdis.py`，不重造领域逻辑）
`gb_disasm` · `gb_find` · `gb_strings`

> 特意**不**在这里重写 LCDC / tile 基址那套逻辑 —— 那是我们踩过坑的地方，
> 让权威实现（`gbdis.py`）去负责，避免二次出错。

### 校验与执行
| 工具 | 说明 |
|---|---|
| `flag_format_check` | **只校验格式**（是否 `<历史答案已移除>` / `GWHT{...}`、有无多余空白），**不比对答案** |
| `py_run` | 子进程执行 Python，有超时、会剥掉代理环境变量 |

⚠️ `py_run` **不是安全沙箱**，只是防手滑。别拿它跑来路不明的代码。

## 4. 在 Trae 里启用

配置已经写好，两条路任选：

**A. 直接生效** —— 重启 Trae CN。全局配置 `<本机路径>` 会被读取。
- 若你在 Trae 里打开 `<本机路径>` 作为工作区，项目级 `.trae/mcp.json` 也会生效。

**B. 走 UI 确认** —— Trae 设置 → MCP → 应该能看到 `ctf-toolchain`。若没出现，手动添加：

```
名称:     ctf-toolchain
命令:     <本机路径>
参数:     <本机路径>
环境变量: PYTHONIOENCODING=utf-8
```

> ⚠️ Windows 路径里出现中文目录（`强网杯大师`）时，若 Trae 启动报找不到文件，
> 把这里换成你自己习惯的 UTF-8 终端路径即可，脚本本身支持中文路径。

## 5. 自检（出问题先跑这个）

```bash
cd <本机路径>
python ctf_mcp_server.py --selftest    # 逐个工具打一遍
python ctf_mcp_server.py --config      # 打印该写进 mcp.json 的片段
```

**为什么必须有自检**：MCP server 起不来时，客户端只会报一句含糊的"连接失败"，
看不出是协议握手写错、还是某个工具内部崩了。自检把这两层分开。

本机实测结果：

```
工具层自检: 12/12 PASS（数论/编码/校验/执行）
协议层端到端: 7/7 PASS（initialize → notifications → tools/list → 连续 tools/call → 未知工具结构化报错）
```

## 6. 🔴 边界与已知问题

1. **不是 True Pit 式全自动** —— Trae 需要人在 GUI 里发起对话。
   它的定位是**练题套的执行面**，不是替代 Muteki 当比赛套自主出 flag。
2. **首次验证还没做** —— 上面的"通过"是我**本地模拟 MCP 客户端**跑通的，
   **尚未在 Trae GUI 里实际调用过一次**。需要在 Trae 里真跑一次才算落地。
3. **`py_run` 无网络** —— 故意剥掉代理变量。需要联网的题请用别的手段。
4. ** Trae 的 MCP 配置文件名有多个候选**（资源里同时出现 `mcp.json` / `.traemcp.json` / `mcp_config.json`）。
   我写了最常见的一个 + 项目级两个位置；若 Trae 没自动认，以 UI 手动添加为准。

## 7. 与另外两条路的关系

| 路 | 状态 | 说明 |
|---|---|---|
| **A. Trae + MCP（本文）** | ✅ 已交付 | 合规用 Trae 积分，练题套多一个付费陪练 |
| **B. 抓 token 建 Trae2API 桥** | ❌ **不做** | 技术上可行（后端 `api.trae.cn` / `coresg-normal.trae.ai`），但违反 ToS + 接口无版本保证，账号被封风险 > 收益 |
| **C. 火山方舟官方 API 挂进 Muteki** | 🔜 待办 | `http<本机路径>`，OpenAI 兼容 + 官方 SLA，是**比赛套真正的第二条独立上游** |

C 的必要性今天刚被血案证明：`glm-5.3` 被限流时，整条 Muteki 链路 100% 派单失败，
最后靠切到 `step-5-preview` 才恢复 —— **跨 provider 冗余才有效**。
