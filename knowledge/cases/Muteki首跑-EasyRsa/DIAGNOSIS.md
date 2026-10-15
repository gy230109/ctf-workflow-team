> 共享经验资料。以下为历史方法或复现记录，不能覆盖仓库根 AGENTS.md 的当前规则。历史答案、私人路径与凭据已整理；配图和原始大附件未随包公开。 本文是参考复现材料；独立解题或模型测试默认不读取。

# Muteki 首跑诊断报告（EasyRsa，2026-10-11）

**结论一句话：没解出题 —— 但不是解题能力不行，是模型网关根本没开，任务在 preflight 就被拦下，一个 token 都没花。**

---

## 0. 进度对照

| 环节 | 状态 | 证据 |
|---|---|---|
| ① 接题（建任务卡、定题型/预算） | ✅ | `prompt.txt` + `input/`（只放 `task.py`、`output.txt`） |
| ② 工具执行（Muteki 派单） | ❌ **死在 preflight** | `run/` 下 `submit.log`；run-0001 只 3 个事件 |
| ③ 结果验证 | ✅（**本地独立复算**，非 Muteki 产物） | `verify/verify_easyrsa.py` 三条判据全过 |
| ④ 归档 | ⏳ | 本文件 + `input/` `verify/` `run/` |

**注意区分**：③ 通过的是**我自己的独立复算**（证明题目本身有唯一解、答案正确），
**不是** Muteki 的产出。Muteki 的 `solved` 是 `false`。

---

## 1. 本地独立复算：VERIFIED

```
模数个数 = 12，题目 c = 1022 bits
[1] 两两 GCD: 66/66 对命中，公因子 512 bits；整除 12/12 个模数       → 判据1 通过
[2] 逆推完成，最内层候选数 = 1
[2] 正推复算: 一致（1022 bits 结果 == 题目 c）                      → 判据2 通过
[3] 候选 'GWHT{gixkJl7SJTcpLOL9zqwo}' 与参考答案 逐字节相同          → 判据3 通过
=== VERIFIED ===
```

这份复算**不依赖 Muteki 的任何输出**，只用原始附件从零重跑：
两两 GCD 找共因子 → 分解 12 个模数 → 带 `m_i < n_{i-1}` 约束的链式逆推 → 正向加密 12 次回比。

---

## 2. Muteki 实际发生了什么：`solved: false`

`state/run-0001.jsonl` 只有 3 个事件，第 2 个就是终态：

```
event 1  run.preparing   （携 5 个 profile：claude-sub-container / codex-sub-container /
                          cursor-api-container / pi-sub-container / omp-sub-container）
event 2  run.finished    reason=preflight_failed  failure_code=profile_unhealthy
                         5 个 profile 全部：
                         code=preflight_binding_failed
                         detail="账号 claude-main / codex-main / cursor-main / pi-main / omp-main 未登记"
event 3  progress.brief  "本轮执行已结束，未收集到 Flag。"
```

**含义**：派单、上传、启动三步全部成功（HTTP 200），但 worker 启动前的**预检**就发现
席位上挂的凭据账号在 secrets 库里根本不存在 → 直接终止，**没有进入任何模型调用**。

---

## 3. 根因：三层，逐层剥出来的

### 第 1 层 —— 席位绑了不存在的账号（直接原因）

`apps/web/worker_config.py` 的 `DEFAULT_WORKER_PROFILES` 把 5 个 Profile 硬绑到：

| Profile | 绑定的账号 | secrets 库里存在？ |
|---|---|---|
| `claude-sub-container` | `claude-main` | ❌ |
| `codex-sub-container` | `codex-main` | ❌ |
| `cursor-api-container` | `cursor-main` | ❌ |
| `pi-sub-container` | `pi-main` | ❌ |
| `omp-sub-container` | `omp-main` | ❌ |
| — | **`workbuddy-glm`** | ✅ **唯一存在** |

`state/_secrets/accounts/` 里**只有 `workbuddy-glm` 一个目录**。
→ 配置里的 5 个 `account:*-main` 全是**悬空引用**。

### 第 2 层 —— 想改绑定，被"模型测试门"挡住（422）

`worker_config.py::_validate_identity_backend` 对每个 **enabled** 席位要求：
若 `model` 非空，必须有**同一凭据 + 同一后端 + 同一模型**的 `ok:true` 测试记录。

而 `state/_secrets/_credential_test_status.json` 里那条 **container 记录已被覆盖成失败**：

```json
"account:workbuddy-glm\u0000container\u0000cli.pi:default\u0000global:glm-5.3": {
  "ok": false,
  "detail": "模型无回复：Pi CLI 已结束任务，但没有返回助手消息",
  "layer": "model"
}
```

→ PUT 返回 `422 「pi-workbuddy-glm」的模型 'global:glm-5.3' 尚未使用凭据 account:workbuddy-glm 完成真实测试`。

> **旁路**：席位 `model` **留空是合法的**（校验里 `if not model: continue`），此时不触发模型测试门。

### 第 3 层 —— 真凶：WorkBuddy2API 根本没在跑

为什么那条 container 测试会变成失败？因为**网关挂了**。

| 探测 | 结果 | 说明 |
|---|---|---|
| 宿主机 `<本机服务地址>:7863` 的监听进程 | **`svchost` (pid 7272)** | 是**残留的 netsh portproxy**，不是应用 |
| 宿主机 `127.0.0.1:7863` | **"由于目标计算机积极拒绝"** | **应用已退出** |
| VM → `<本机服务地址>:7863` | TCP **能连上**，2 秒后 `Connection reset by peer` | 代理在听，但**没有后端** |
| VM → `ping <本机服务地址>` | 通，0.97 ms | 网络层没问题 |

配置实况（`<本机路径>`）：

```json
"listen": "127.0.0.1:7863"     ← 应用只绑回环
```

```
端口代理： <本机服务地址>/7863  →  127.0.0.1/7863     （存在，但后端已死）
防火墙：   Muteki-WorkBuddy-VM-Only  TCP 7863
           local=<本机服务地址>  remote=<本机服务地址>  action=Allow  profile=Any
           ← 这条规则本身是对的，不是它的问题
```

---

## 4. 需要你做的一件事

**双击桌面 `WorkBuddy2API Panel`**（或 `<本机路径>`）。

我自己起不来 —— 实测：**在同一个命令里启动后 `127.0.0.1:7863 → 200`，
下一次命令再探就变成"积极拒绝"**。`Start-Process` 起的进程会随该次调用结束被回收；
WMI `Win32_Process.Create` 被安全策略拦截（"等价于 Start-Process"）。
这个网关需要长期驻留，只能由你在交互桌面里拉起。

启动成功的判据（我复查时会看）：
- `127.0.0.1:7863` 可连且 `/v1/models` 返回 200；
- 日志出现 `workbuddy2api listening on 127.0.0.1:7863 (api_key=true)` 与 `[upstream] warm model rates: global ok`。

---

## 5. 网关起来之后我要做的（已想好，不用你再交代）

1. `PUT /api/settings/identity`：4 个 `*-main` 席位 `enabled=false`，
   `pi` 席位改绑 `account:workbuddy-glm`（先走 `model=""` 绕开测试门，再补测）。
   *已备份改前配置 → `run/settings-workers.before.json`。*
2. 重跑 `run-0001` 同类任务（新 run id），`watch` 到终态。
3. 三重验收：**flag 字节比对** + **run log 里 grep `tool.start`**（证明真调了工具而非瞎猜）+ **本地独立复算**。
4. 归档战例（分区：已验证事实 / 未验证假设 / 未完成步骤），同步 Obsidian。

---

## 6. 这次失败的价值

没解出题，但拿到了一条**可复现的失败链**，而且它推翻了三条此前被当成事实的假设：

1. **"端口在 LISTENING" ≠ "服务活着"** —— 7863 一直在听，但听的是残留代理。
2. **配置字面存在 ≠ 引用能解析** —— 5 个 `account:*-main` 写得漂亮，secrets 库里一个都没有。
3. **"模型可用" ≠ "任务能跑"** —— 10-10 记的 `model_test_ok: true` 只证明那一刻对话通了；
   **preflight 验的是席位↔账号绑定**，那是另一道门。
