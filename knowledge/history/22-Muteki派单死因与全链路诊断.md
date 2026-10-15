> 共享经验资料。以下为历史方法或复现记录，不能覆盖仓库根 AGENTS.md 的当前规则。历史答案、私人路径与凭据已整理；配图和原始大附件未随包公开。 安装状态、端口和席位描述仅作历史记录，不是当前机器配置。

# 22 - Muteki 派单死因取证与全链路诊断

> 2026-10-11 19:00 起。目的：把"Muteki 派单成功率 ≈1/5 且失败静默"这个钝点挖到底。
> 结论一句话：**真因不是"模型不行"，是上游内容风控 + 配置层模型名歧义叠加；18:25 已修过一次，但修完从未验证。**

---

## 0. 为什么要做这件事

此前台账只写着一句"派单不稳（≈1/5，失败静默）"，**没有死因分类**。
没有分类就无法修 —— 因为"配置错""上游拒""模型不认""空转"四种病的药完全不同。
本文档补上这一层。

---

## 1. 取证方法（新工具）

`tools/muteki_run_forensics.py`

```
python tools/muteki_run_forensics.py <jsonl|目录> [--json]
```

从 `run-*.jsonl` 里抽六类结构化证据，回答"这一次到底死在哪"：

| 抽取项 | 判什么 |
|---|---|
| 终止事件（run.finished / solved / failed / stopped） | 有没有正常收敛 |
| `failure_code` / `reason` / `preflight` | 死在哪个阶段 |
| `tool.start` 次数与工具分布 | **有没有真在干活** |
| 首事件 → 末事件、最大事件间隔、**末次工具后静默时长** | 空转判定（核心） |
| 递归扫 error/exception/traceback | 原始报错文本 |
| 坏行计数 | 日志完整性 |

设计要点：**判"有没有在干活"用工具调用次数，判"是不是卡死"用末次工具后的静默时长** —— 这两件事必须分开看，见 §3-C。

---

## 2. 六个历史 run 的死因台账（2026-10-11 实测）

| run | 题目 | 事件行 | tool.start | 时长 | 终止 | 死因 |
|---|---|---|---|---|---|---|
| run-0001 | EasyRsa | 3 | 0 | 0.1s | run.finished | `preflight_failed` / `profile_unhealthy`：5 个席位账号未登记 |
| run-0006 | EasyRsa | 578 | 12 | 97.1s | run.finished | ✅ **solved**，`GWHT{...}` |
| run-0586 | GameBoy-音频 | 116 | 18 | 373.9s | run.finished | `planner_unavailable`（重试 3 次后放弃） |
| run-0704 | GameBoy-FlappyPig-v2 | 259 | 66 | 876.9s | ❌ **无** | planner draft 无效 + 上游 503 账号池空 |
| run-0705 | GameBoy-FlappyPig-v3 | 651 | 107 | 3985.9s | ❌ **无** | 末次工具后**静默 1969s（32.8 分钟）** |
| run-0889 | GameBoy-FlappyPig-v4 | 457 | 54 | 3398.2s | ❌ **无** | 见 §5（**它其实已经解出来了**） |

> ⚠️ 本表修正了两处旧记忆错误：
> ① 台账此前漏记了 `run-0586`；
> ② run-0889 曾被记为"空转死"，实为"已挖到答案但被外部打断"，见 §5。

---

## 3. 死因分类（三类，药不同）

### A. 配置层 —— planner 通道
**症状**：`planner_unavailable` / `planner draft 无效` / `Pi Decide process exited with code 1`

**根因**（源码级）：planner 的 account_id 取自 `llm_profiles.planner.endpoint_id`。
该字段为空时，Pi 只拿到**裸模型名** `deepseek-v4-pro`；而这个名字在 Pi 的 5+ 个 provider 下同时存在 →
`Model "deepseek-v4-pro" is ambiguous across providers` → 进程 exit 1 → 整个 run 判 `runtime_failure`。

**药**：把 planner 绑到一个**唯一可解析**的端点。已在 18:25 改成
`endpoint:ctf-planner-c2api`（账户 `_secrets/accounts/ctf-planner-c2api`，`BASE_URL=htt<本机路径>`，
`PROVIDER=openai`，`DEFAULT_MODEL=glm-5.3`）。

### B. 上游层 —— 凭据池 / 内容风控
**症状**：`503 no_healthy_account` / `no_healthy_credential`

**两条独立上游链路**（别混）：
```
链路1  Muteki planner ─→ <本机服务地址>:8090 (docker-proxy)
                       ─→ 容器 coding2api (ghcr.io/robbsluo/coding2api:v0.4.1)
                       ─→ CODEBUDDY_API_ENDPOINT = http<本机路径>
                       ─→ 凭证 cred_bd0b483789f84be6

链路2  Windows WorkBuddy2API @ 127.0.0.1:7863  （独立，/healthz 返回 healthy:1,total:1）
```

**证据（coding2api 容器日志）**：
```
18:10:27  quota probe failed for cred_bd0b483789f84be6
18:56:52  上游 codebuddy 错误: upstream http 400:
          {"code":11128,"msg":"first message is not system prompt",
           "zh":"请求被安全策略拦截，请稍后重试或联系支持。"}
17:36~17:44  出站消息命中伪装客户端指纹，已中和 1 处（上游 11128 内容风控）  ×数十条
```
**`code:11128` = 内容风控**。coding2api 在伪装 CodeBuddy 官方客户端指纹，且**持续被风控识别**。

### C. 观测层 —— 无 watchdog
**症状**：run 挂在半路，UI 上仍显示"进行中"，人不知道它已经死了。

**关键判据（实测校正）**：
> 🔴 **"有没有在调工具"和"是不是卡死了"是两件事，必须分开判。**
> run-0889 调了 **54** 次工具（比成功的 run-0006 的 12 次多 4 倍），但**最后一次之后静默 36.9 分钟**。
> → 判据是「**距上次 tool.start 过了多久**」，不是「有没有 tool.start」。
> 工具：`tools/muteki_stall_probe.py`

---

## 4. 决定性对照实验（§3-B 的定性）

对 `ctf-planner-c2api` 端点直打两次，只差一个 system 消息：

| 请求 | 结果 |
|---|---|
| `messages=[{system},{user}]` | **HTTP 200**，9.53s，正常返回 |
| `messages=[{user}]` | **HTTP 503**，0.73s，`no_healthy_credential` |

**结论**：coding2api → codebuddy.ai 这条链路**是通的、凭证是健康的**；
"缺 system 消息"确实会被上游 400 拒并被代理翻译成 `no_healthy_credential`。

**但同时必须承认一个反转**：Muteki 自己的 planner **本来就带 system**
（`muteki/solver/reason.py:276-278`，`REASON_SYSTEM` 作为 messages[0]）。
所以这个 400 **不是 Muteki planner 会踩的坑**，是我探测方式引入的。
它的真实价值是：**解释清了"503"这个错误码背后的多种成因**，
以及**指明了 coding2api 的失败翻译逻辑**（上游 400 → 一律说成"凭证不可用"，非常误导排查）。

---

## 5. run-0889 的真相（推翻旧结论）

旧记忆：**"run-0889 = 36.9 分钟零调用 = 空转死"**。

实测：它提交过这条黑板事实 ——
```
submit-fact 'FlappyPig 隐藏串 PS03R49UE576R421RE8 的调用点与代码结构'
  'ROM 0x1C92 处内联 19 个 tile 序列（游戏字体读出为 PS03R49UE576R421RE8），前后为 tile 0x8A/0x8B'
```
**这正是我们本地手工解出的那个字符串。它自己挖出来了。**
它没走到 `submit-flag`，而是当 `submit-fact` 交了。

它被终结的真实原因（三个叠加）：
1. `Pi did not commit a valid planner draft`（§3-A，planner 已废）
2. `503 no_healthy_account`（§3-B）
3. **`operator paused the swarm`** —— 人工暂停

**所以 Muteki 的能力上限被低估了。** 它在这类题上"想得出来"，缺的是"收得回"（把结论落成 flag 交付）。

---

## 6. 配置现状（2026-10-11 18:25 后，实测）

| 项 | 值 |
|---|---|
| engines | `["c2api-claude-glm53-local"]`（**只跑一个**） |
| 席位 enabled | 2 / 8：`c2api-claude-glm53-local`(claude+glm-5.3)、`c2api-claude-dsv41flash-local`(claude+deepseek-v4.1-flash) |
| 其余 6 席位 | 全 `enabled=false`（含原先的 `seat_*_main` —— run-0001 报"未登记"的那批已下线） |
| max_workers / start_workers | 1 / 1 |
| dispatch_mode | fixed ✅（CTF 必须） |
| planner | `endpoint:ctf-planner-c2api`，model `glm-5.3`，provider `openai` |

**席位模型测试状态**（`_worker_model_test_status.json`）：
- `c2api-claude-glm53-local` → **ok:true**（"worker 容器内模型可用"）
- `seat_pi_b710d8` → ok:false（"模型无回复：Pi CLI 已结束任务，但没返回助手消息"）
- `c2api-codex-dsv41flash-local` → ok:false（"Selected model is at capacity"）

---

## 7. 分区交付

### ✅ 已验证事实
- 六个 run 的死因分类（§2），全部来自 jsonl 原始事件，可复算
- 全链路拓扑（§3-B）经 `docker inspect` / 容器日志 / 对照实验确认
- `coding2api → codebuddy.ai` 链路当前**可用**（带 system 请求 200）
- planner 代码确实带 system（`reason.py:276-278`）
- run-0889 已产出正确答案串但未落成 flag（§5）
- Windows 7863 `healthy:1, total:1`

### ⚠️ 未验证假设
- **18:25 的修复是否真的让端到端跑通** —— 修复后从未跑过（本文档写作时正在跑 `run-1817`，结果见文末）
- `528/quota probe failed` 是否为**周期性**现象（只在特定时段限流），未做时间序列
- `11128 内容风控`的触发阈值（题面里哪些词会被拦），未测

### ❌ 未完成步骤（2026-10-11 19:15 更新）
- ~~把 stall probe 接成自动判死 + 自动重派~~ → ✅ 已建 `tools/muteki_autopilot.py`，见 §9
- ~~清理残留容器~~ → ✅ 已删 3 个 run 遗留容器（0704/0705/0889），**保留 `coding2api`**（planner 依赖它）
- ~~单题连续回归~~ → ✅ EasyRsa **5/5**，见 §9
- [ ] **跨题型**（pwn / web / re）的连续回归 —— 仍未做
- [ ] `528 / quota probe failed` 是否为**周期性**现象，未做时间序列

---

## 8. 认知差（可迁移）

1. **"失败"和"失败原因"是两个工程问题。**
   台账写"不稳"没有用，必须分布到`配置/上游/观测`三类，否则药是错的。
   → 可迁移：任何"时好时坏"的系统，先建**死因分类表**，再谈修。

2. **错误码会撒谎。**
   coding2api 把"上游 400 格式不符"统一报成 `no_healthy_credential`，
   一旦信了字面意思，就会去查凭证池 —— 方向全错。
   → 可迁移：**看错误码之外，一定去看它上游的原始日志**。

3. **"没在调工具" ≠ "卡死了"；"在调工具" ≠ "在收敛"。**
   run-0889 调了 54 次却静默 37 分钟；run-0006 只调 12 次就解完。
   → 可迁移：判活要盯**时间间隔**，判进展要盯**产出物**，两者都要看。

---

## 附：run-1817 回归结果 —— ✅ 修复有效，端到端跑通

**派发**：2026-10-11 19:01，同题（EasyRsa）、同 prompt（复用 run-0006 的原始 787B 描述）、同 flag 格式、
附件为**干净副本**（仅 task.py + output.txt，经 `grep GWHT{|flag{` 确认无答案泄漏）。

**日志**：`run.preparing×1 → run.started×1 → tool.start×5 → run.finished×1`
（**无** `failure_code`，**无** `planner_unavailable`，**无** 503）

**终态**：
```json
{"flag": "GWHT{gixkJl7SJTcpLOL9zqwo}", "expected_flags": 1, "multi_flag": false,
 "solved": true, "reason": "solved", "backend": "container", "network": "bridge",
 "container_scope": "run", "worker_privilege": "default", "runtime_degraded": []}
```
→ `solved:true`，且 `runtime_degraded` **为空**（无任何降级）。

**与历史最佳对比**：

| 指标 | run-0006（修前最佳） | run-1817（修后） | 变化 |
|---|---|---|---|
| tool.start | 12 | **5** | ↓ 58% |
| 耗时 | 97.1s | **≈60s** | ↓ 38% |
| 事件流长度(stream_seq) | 577 | **58** | **↓ 90%** |
| 附带错误 | `planner_unavailable` | **无** | — |
| solved | true | **true** | 一致 |

**结论**：18:25 的那次修复（planner 改 `endpoint:ctf-planner-c2api` + 下线 6 个坏席位 + 只留单一健康引擎）
**确实解决了 §3-A 的配置层死因**。事件流从 577 瘦到 58，说明**没有再把额度烧在报错重试上**。

**但本次通过 ≠ 稳定**：§7 未完成项仍然成立（单题通过、探针未自动化、未做多题连续回归）。
按 §8 的规矩，一次成功只算"点验证通过"，要判定"稳定"至少需要 **连续 5 次 ≥4 次通过**。

---

## 9. 自动重派与稳定性验证（2026-10-11 19:15）

### 9.1 新工具 `tools/muteki_autopilot.py`

把 §3-C 的「判死」从**人看**变成**自动动作**：

```
派单 → SSE 盯守（Tracker 判活）→ 判死 / 超时 → 停止该 run → 重派
  → 直到拿到 N 个 solved，或达重试上限 / 总时长上限
```

- **复用**：`muteki_client.submit_run / stop_run / get_run / login` + `muteki_stall_probe.Tracker`
- **不重写任何 API 逻辑** —— 为此把 `muteki_client.py` 的派单逻辑抽成 `submit_run()`，CLI 与 autopilot 共用一份实现
- **安全阀**（无人值守时防无限烧共享额度）：`--max-attempts`(5) / `--per-attempt`(1500s) /
  `--total-budget`(7200s) / `--goal`(1) / `--backoff`(20s)
- 每轮结果写台账 json，含 `outcome / tool_starts / duration_s / since_last_tool_s / final_status`

### 9.2 连续 5 次回归 —— ✅ 5/5，达标

命令：`muteki_autopilot.py --name EasyRsa --max-attempts 5 --goal 5`

| # | run_id | tool.start | 时长 | 结果 |
|---|---|---|---|---|
| 1 | run-1878 | 6 | 64.6s | ✅ solved |
| 2 | run-1937 | 5 | 46.1s | ✅ solved |
| 3 | run-1991 | 6 | 105.7s | ✅ solved |
| 4 | run-2057 | 6 | 46.9s | ✅ solved |
| 5 | run-2121 | 5 | 34.5s | ✅ solved |

- **`pass_rate = 1.0`（5/5）**，总耗时 361.8s（含每次 15s backoff）
- 全部 `solved` / `reason=solved`；单次 **34.5~105.7s，中位 ≈47s**
- 工具调用稳定在 **5~6 次**（修前 run-0006 为 12 次）
- 台账：`dataset/autopilot-easyrsa-5x.json`

**判据达成**：此前立的规矩「连续 5 次 ≥4 次通过才算稳定」→ **5/5，达标**。

### 9.3 这个结论的边界（别过度外推）

它验证的是**「配置层修复是否生效」**，只覆盖：
**同一道 crypto 题 × 同一环境 × 连续 5 次**。

**不能**由此推出「Muteki 已全面稳定」，因为还没验证：
- 上游 codebuddy.ai 风控**是否会再次收紧**（§3-B 是外部变量，随时可能变）
- **跨题型**（pwn / web / re）是否同样稳
- planner 之外的**席位轮换**（`c2api-claude-dsv41flash-local` 目前 enabled 但未参与本轮）


---

## 10. 🔥 追加：19:42 起「全线 preflight_failed」—— 第四类死因：**上游限流**

§1–§9 讲的是死的三种死法：配置层 / 上游层 / 观测层。本轮补充的是**第四类**，
也是最容易被误判成 Muteki bug 的一类：**上游账号被限流 → 全链路集体失能**。

### 10.1 现象与初步（错误）判断

| 时间 | 事件 |
|---|---|
| 19:15 | 5/5 回归全绿（`pass_rate=1.0`） |
| 19:34:59 | 最后一次 solved（AB-longprompt，66.6s） |
| **19:42 起** | **所有派单开始失败**，不分题型/附件/提示长度 |
| 19:49 / 19:51 | 用同一道 EasyRsa（crypto）做对照组，**同样失败** |

失败特征高度一致：

```json
{"reason":"preflight_failed","failure_code":"profile_unhealthy","failure_phase":"preflight",
 "detail":"Worker 预检失败（1 个 Profile）",
 "profile_failures":[{"profile_id":"c2api-claude-glm53-local","engine":"claude","model":"glm-5.3",
   "backend":"container","code":"preflight_model_failed",
   "detail":"模型测试退出 137：[claude-code:unrecognized_model] {\"model\":\"glm-5.3\",\"query_source\":\"sdk\"}"}]}
```

- **每次恰好 ~121s** → 正对 `_HELLO_TIMEOUT = 120`（`muteki/solver/cli_engines/base.py:227`）
- `tool.start = 0`，`exit 137` = SIGKILL

### 10.2 走过的弯路（**记录下来，别重复烧时间**）

| 假设 | 验证方式 | 结论 |
|---|---|---|
| 僵尸容器占着唯一 worker 槽 | 查 `_run_summaries.json` → `run-2319` 未终结，`docker rm -f` | ❌ 清了仍然失败 |
| 附件太大导致预检超时 | 只传 32KB `game.gb` | ❌ 单独传也失败 |
| `category=misc` 有问题 | 改回 crypto 重跑 | ❌ crypto 也失败（**这一枪很关键**） |
| 提示词太长 | 缩短后重跑 | ❌ 仍失败 |
| Planner 端点配错 | 直连探针 HTTP 200 | ❌ 端点正常 |
| worker 容器到上游的链路断了 | **在 worker 容器里 curl 三个上游** | ❌ **全 200**，链路正常 |

最后一条是关键反证：

```
容器内实测（ghcr.io/fishcodetech/muteki-worker:v0.4.2）
htt<本机路径>       -> 200   coding2api 可达
htt<本机路径>  -> 200   WorkBuddy2API 可达
http<本机路径>         -> 200   上游直连可达
```

### 10.3 ✅ 真根因：coding2api 原始日志里只有两条错误

```
19:36:56 上游 codebuddy 错误（凭证 cred_bd0b483789f84be6，kind=model）: upstream http 429
         {"code":6004,"msg":"usage exceeds frequency limit ... reset at 2026-10-11 22:15:37 UTC+8,
          alternatively, you can switch to the other models to continue using it."}
19:47:03 上游 codebuddy 错误（凭证 cred_bd0b483789f84be6，kind=credit）: upstream http 429
         {"error":{"data":{"code":14018,"msg":"Credits exhausted. ... purchase add-on packs"}}}
```

**结构性错误**：同一个代理 `<本机服务地址>:8090`（coding2api）承载了
**planner + titler + worker 席位 + reviewer 的全部流量**。
上游一限流，四个角色同时死 —— 这就是"为什么所有题都失败"的机制。

🔴 **错误码会撒谎（第二次应验）**：Muteki/coding2api 转译出来的是
`unrecognized_model`（听起来像"模型名配错了"），真实原因是**上游 429 限流**。
判上游唯一可靠的做法是**直接问 provider**，不能信过渡层的转译。

### 10.4 交叉体检：上游不是全死，是**只有两个模型被限流**

上游自己的提示「switch to the other models」是可信线索。实测：

| 凭证 | provider | base_url | 模型 | 结果 |
|---|---|---|---|---|
| `account:c2api-claude` | anthropic | `<本机服务地址>:8090` | glm-5.3 | ❌ 模型测试超时 |
| `account:c2api-ds-claude` | anthropic | 同上 | deepseek-v4.1-flash | ❌ 模型测试超时 |
| **`account:c2api-step`** | anthropic | 同上 | **step-5-preview** | ✅ **可用，模型与配置一致** |
| `account:workbuddy-glm` | workbuddy | `<本机服务地址>:7863/v1` | global:glm-5.3 / -flash | ❌ Pi CLI 无助手消息 |

→ **`step-5-preview` 是当时唯一可用的模型**，且席位表里已有现成席位
`c2api-claude-step5p-local`（此前 `enabled=False`），无需新建。

### 10.5 ✅ 恢复：一键故障转移

新增 `tools/muteki_switch_upstream.py`（快照 → 切换 → 回读断言 → 可回滚）。

**源码级接口要点**（这三点花了不少时间挖，别再试错）：

1. 席位/凭证写成 **`PUT /api/settings/identity`**，body `{"seats","credentials","worker_backend","worker_network"}`
   —— 该路由 **GET 是 405**，所以"读"必须走 `GET /api/settings/workers`
2. engines / `llm_profiles` / `stage_policy` 写 `PUT /api/settings/workers`
3. **改席位必须同时改 `engines`**，否则派发仍指向旧席位

执行结果：

```
PUT /api/settings/identity -> 200
PUT /api/settings/workers  -> 200
  PASS engines 指向目标席位        PASS dispatch_mode 仍 fixed
  PASS race_engines 指向目标席位   PASS review 引擎指向目标席位
  PASS 目标席位 enabled            PASS 旧席位 c2api-claude-glm53-local 已停用
  PASS 目标席位 model 正确         PASS planner/titler endpoint_id + model 均已切
== 11/11 PASS ==
```

端到端验证：

| run_id | 结果 | 时长 | 工具调用 |
|---|---|---|---|
| `run-2710` | ✅ `solved=True` `GWHT{gixkJl7SJTcpLOL9zqwo}` | 72.7s | 6 |

flag 与 EasyRsa 已知正确答案**逐字符一致**。

### 10.6 这次事故换来的一条能力 + 一条认知

**能力**：`muteki_upstream_probe.py`（**不派单**的上游体检）。
以后凡是"全线 preflight_failed"，**第一步不是派单重试，而是跑体检**：

```bash
python muteki_upstream_probe.py test account:c2api-step --model step-5-preview
```

坑：这个端点**必须显式传 `--model`**，不给会回 HTTP 200 但 `ok=false`
「请选择一个候选模型后执行真实测试」—— **别误读成凭证挂了**。

**认知**：§3-B 说"上游是外部变量"，这次给出了它的**失效模式**——
不是彻底宕机，而是**按模型逐个限流**。所以冗余的方向不是"备份同一个 provider 的同一个模型"，
而是**跨 provider / 跨模型的独立链路**。

### 10.7 ⚠️ 边界（别过度外推）

- `run-2710` 只证明 **step-5-preview 能解 EasyRsa**，**不等于**它在新模型下的能力等价于 glm-5.3。
- **19:15 那份 5/5 基线已经作废**（那是 glm-5.3 的成绩）。换模型后必须**重跑回归**建新基线。
- §9.3 列的未验证项（跨题型、偏难怪的能力）**依然一个都没验证**。

---

## 11. 附：Trae CN 能否并入装备（2026-10-11 实查）

老板问「Trae 不能为我们所用吗」。实地查证结论 —— **不能当比赛套引擎**：

| 事实 | 证据 |
|---|---|
| 装在 `<本机路径> CN\Trae CN.exe`，23 个进程在跑 | tasklist + 路径搜索 |
| 只监听 **3 个本地端口**：`127.0.0.1:51000 / 4886 / 2442` | `Get-NetTCPConnection` 按 PID 交叉比对 |
| 这些是 **IDE 内部 IPC / 语言服务端口，不是模型 API** | 非 OpenAI 兼容，无法当 provider 挂 |
| Muteki 引擎目录只有 **11 个**：claude / codex / cursor / devin / droid / grok / kimi / omp / opencode / pi | `muteki/solver/cli_engines/engines/` |
| **源码全文无 trae** | 全仓 grep 只命中 TS 无关串 |

**判断**：Muteki 的 worker 在容器里 headless 运行，要求「CLI + 注入凭证」。
Trae CN 是 GUI 登录制 IDE，两者形态不匹配；要接就得自己写 adapter，而它没有可编程的模型入口。

**练题套能用吗？** 能，但增量有限 —— 我已经有文件系统 / 命令执行 / Python，
Trae 的价值主要在多文件 diff 的编辑体验，属于手感而非能力。

**真正该做的冗余**：Muteki 已有 10 个引擎槽位空着，且`(10.4)`证明跨 provider 才有效。
方向是**填槽位 + 加第二个独立凭证**，不是加 Trae。
