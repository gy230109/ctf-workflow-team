> 共享经验资料。以下为历史方法或复现记录，不能覆盖仓库根 AGENTS.md 的当前规则。历史答案、私人路径与凭据已整理；配图和原始大附件未随包公开。

# 07 · CyLab Security Academy (pwn.college) 解题工作流

> 平台全名 **CyLab Security Academy** = **`pwn.college`**（ASU CyLab 的 CTF 教学平台）。
> 底层是 CTFd + 自定义 dojo 插件，题目跑在每人一个的 Docker 容器里。
> 本篇是**流水线**：找题 → 起环境 → 捞附件 → 交接 Kali → 提交 → 复盘。
> 2026-10-10 建立（工具在 `tools/pwncollege/`）。

---

## 一、平台机制（先搞清这四条，不然会白折腾）

| 事实 | 说明 |
|---|---|
| **flag 在 `/flag`** | 只有 root 可读；你以 `hacker`(uid 1000) 运行 |
| **`/challenge` 里有 SUID 程序** | 它们以 root 跑，是拿到 flag 的唯一入口 |
| **一题一容器** | 每人同时只有**一个**活动挑战；起新题会**先杀掉旧的** |
| **首页持久** | `/home/<用户>` 是持久的（跨题目保留），所以脚本可以囤在那儿 |

> ⚠️ `start_challenge()` 第一件事就是 `remove_container(user)` —— **起新题 = 旧容器被删**。
> 所以"换题前先把要留的产物捞下来"。

### 1.1 两条通道，别混

| 通道 | 干什么 | 怎么走 |
|---|---|---|
| **HTTP API** | 找题、起环境、提交 flag、注册 SSH 公钥 | `http<本机路径>`（要登录态） |
| **SSH / SFTP** | 捞 `/challenge`、在容器里跑命令 | `hacker@dojo.pwn.college`（要注册公钥） |

**关键洞察**：HTTP 侧**必须一直带着 Flask session cookie**（见 §3.5，`token` 模式实测无效）；
SSH 侧用 **paramiko**（纯 Python）—— 本机 Windows 的 `scp.exe`/`sftp.exe` 是坏的（`04-踩坑` F1），
paramiko 正好绕开它。

> ⚠️ 2026-10-10 实测推翻了原先"签长期 token 就不需要浏览器"的设计前提：
> **`/pwncollege_api/v1/*` 只认 Flask session，`Authorization: Token` 一律 302 跳登录页。**

---

## 二、五步流水线

```
① 找题    pc_flow.py find          未完成的题，按 模块顺序 → 挑战顺序
② 起环境  pc_flow.py pull          启动容器 + 捞 /challenge + 抓题面 + 交接 Kali
③ 解题    写脚本 → kali.ps1 python → fetch 产物        （Windows 侧做 .NET/PE 专用分析）
④ 提交    pc_flow.py submit        提交 flag
⑤ 复盘    战例库/pwn.college/<dojo>/<module>__<challenge>.md → 同步 Obsidian
```

### ① 找题（按模块顺序扫未完成）

```bash
VENV=<本机路径>
cd <本机路径>
"$VENV" pc_flow.py find                    # 所有可见 dojo
"$VENV" pc_flow.py find --dojo intro-to-cybersecurity --limit 40
"$VENV" pc_flow.py find --all               # 连非 required 的也列
```

原理：`GET /dojos/<dojo>/modules` 拿模块+挑战（服务端已排好序），
`GET /dojos/<dojo>/solves` 拿已解决集合，**求差集**即为"未完成"，天然按模块顺序。

### ② 起环境 + 捞附件 + 交接（一条龙）

```bash
"$VENV" pc_flow.py pull --dojo intro-to-cybersecurity --module linux-luminari --challenge level-1
"$VENV" pc_flow.py pull ... --practice       # practice 模式：有 sudo，但 flag 是假的（调试用）
"$VENV" pc_flow.py pull ... --no-kali        # 只下载，不交接
```

它会做五件事：
1. `POST /docker` 启动
2. 轮询 `GET /docker` 直到 `challenge` 对得上
3. SFTP 递归把 `/challenge` 捞到 `题目库/pwn.college/<dojo>/<module>/<challenge>/`
4. 抓题面存 `description.md`，算 SHA256 写 `manifest.json`
5. 把文件摊平后 `put` 到 Kali（case = `<dojo>_<module>_<challenge>`）

### ③ 解题

```powershell
$K = "<本机路径>"
powershell.exe -NoProfile -File $K status
powershell.exe -NoProfile -File $K python <case> <你的脚本.py>
powershell.exe -NoProfile -File $K fetch  <case> work/<产物>
```

⚠️ **`/challenge` 里的 SUID 程序要在题目容器里跑，不是在 Kali 里跑。**
Kali 只负责"需要 Linux 工具链的计算/分析"，真正的 exploit 在容器里执行 —— 两条路：
- 用 `pc_lib.run_remote(cmd)`（走 SSH 直接进容器执行）；
- 或者把 Kali 上编好的 exploit 传回容器再跑。

### ④ 提交

```bash
"$VENV" pc_flow.py submit --dojo X --module M --challenge C --flag "pwn.college{...}"
```

`POST /dojos/<dojo>/<module>/<challenge>/solve`，body `{"submission": "..."}`。
返回 `status` 为 `solved` / `already_solved` / `incorrect` / `ratelimited`。
**每分钟提交次数有上限**（服务端 `incorrect_submissions_per_min`，默认 10）。

### ⑤ 复盘

写到 `战例库\pwn.college\<dojo>\<module>__<challenge>.md`，
内容是：知识点 / 卡点 / 别人的最优解 vs 我的解 / 新增 SOP 条目。
**按常驻规则同步 Obsidian。**

---

## 三、登录态：只需要开一次浏览器

### 3.1 为什么这么绕

| 障碍 | 实测结论 |
|---|---|
| Edge ≥136 **禁止对默认 profile 开远程调试端口** | 不能直接 attach 你日常那个 Edge |
| Cookies 库在浏览器运行时**独占锁** | 普通复制 / `FILE_SHARE_READ\|WRITE\|DELETE` / `robocopy /B` **三种全失败** |
| Chrome 系 **App-Bound 加密(v20)** | 从磁盘解 cookie 走不通 |

**所以**：独立 profile 启动带调试端口的 Edge → 走 **CDP** 取内存里的明文 cookie → 存成 cookie jar。

> ⛔ **不要再走"签长期 token"那条路了** —— 实测 `POST /users/me/tokens` 能签出 token
> （`ctfd_...`，默认 30 天有效期），但这个 API **不认它**：
> `Authorization: Token <值>` 和 `Bearer <值>` 对 `/users/me`、`/docker` **一律 302 跳登录页**。
> 因为 `authed_only` 只读 Flask `session["id"]`。
> **`pc_lib.py` 里那段"有 token 就用 token"的逻辑是有害的** ——
> 一旦 config 里有 token，所有请求都会变成未登录。**配置里只保留 `cookies` 一项即可。**

### 3.2 ⛔「复制你现有 Edge 配置」这条路**已被证明无效**（2026-10-10 实测）

原本的计划是 `copy` 5 个文件（`Local State` + `Default/Network/Cookies` + `Preferences` +
`Secure Preferences` + `Login Data`）继承登录态。**实测失败，且是硬失败：**

- 复制本身能成功（Edge 全关时，`Cookies` 655360 B 与源一致）；
- Edge 用这个 profile 也能正常启动，日志里连 `edge_auth/oneauth` 都出来了；
- **但 CDP `Storage.getCookies` 只返回 18 条 cookie**（640 KB 的库），
  且全是 `msn.cn` 之类的新 cookie + 一条**自动化浏览器自己访问 pwn.college 生成的匿名 `session`**；
- 拿这条 `session` 请求 `/users/me` → **302 跳 `/login`**；
  让**浏览器自己** `fetch` 一次 → 同样 302（`redirect:'manual'` 表现为 status 0）。

**结论：换了 `user-data-dir` 之后，App-Bound 加密的 cookie 连 Edge 自己都解不开，
会被直接丢掉。** 所以复制过来的 profile 是"空壳"，继承不到任何登录态。

> 顺带排除的误判：`/dojos` 未登录也能返回 **200 JSON**（是公开接口），
> 别拿它当"登录成功"的证据。**判据要用 `/users/me`**。

**✅ 正确做法：`up --fresh`，在弹出来的窗口里登录一次。**
登录态留在独立 profile 里，然后立刻换成长期 token，**从此不需要浏览器**。

### 3.3 命令

```bash
"$VENV" pc_login.py check                  # Edge 是否在跑 / profile / 端口 / 当前登录态
"$VENV" pc_login.py up --fresh --wait 900  # ⭐ 直接用空 profile 启动 + 轮询等你登录 + 存盘
"$VENV" pc_login.py harvest                # 只重取登录态
"$VENV" pc_login.py keypair                # 生成并注册专用 ed25519 公钥（一次性）
```

- `--fresh` **跳过复制**（复制那条路已废，见 3.2），弹出一个独立窗口，你在里面登录一次即可。
- **别关那个窗口**，直到它在终端打印出"登录态已就绪"（轮询每 5 秒一次）。
- 它和平时的 Edge 用的是**不同 profile**，互不影响，不用关你日常的 Edge。
- ⚠️ **`up` 那个进程同时负责让浏览器活着** —— 它一被中断，Edge 窗口会跟着一起关闭
  （窗口是它的子进程）。所以等待期间**不要去停那个后台任务**，否则窗口消失、得重来。
- 浏览器**活着的这段时间不需要很长**：登记/登录一次 → 立刻换长期 token → 之后纯 HTTP。

### 3.4 三个把这条路卡死过的坑（都已修，别再踩）

| # | 症状 | 真因 | 修法 |
|---|---|---|---|
| 1 | `CDP 取 cookie 失败: Handshake status 403 ... Rejected an incoming WebSocket connection from the htt<本机路径> origin` | Edge 默认拒绝带 `Origin` 头的 CDP WebSocket | 启动加 `--remote-allow-origins=*`；**并且** `create_connection(..., suppress_origin=True)`（不发 Origin，对已在跑的实例也立刻生效） |
| 2 | `CDP 取 cookie 失败: Expecting value: line 1 column 1 (char 0)` | 本机代理 `HTTP_PROXY=htt<本机路径>` **把发往 `127.0.0.1:9222` 的请求也吞了**，返回空 body | CDP 的请求必须 `Session.trust_env = False` |
| 3 | `UnicodeDecodeError: 'utf-8' codec can't decode byte 0xd0` | 中文 Windows 的 `tasklist` 输出是 GBK，Python 在 UTF-8 模式下用 utf-8 解码 | `subprocess.run(..., errors="replace")` |
| 4 | cookie 模式的 POST 全部 **403** | CSRF nonce 的取法写错了 | 见下 |

**坑 4 · CSRF nonce 的正确取法**（2026-10-10 实测）：

- ❌ **`/csrf` 这个端点根本不存在**（404）—— 之前文档里写的那个路径是错的。
- ✅ nonce 在**任意页面 HTML** 的那坨 JS 里，**连 404 页面都带**：
  ```html
  <script>var init = { 'urlRoot': "", 'csrfNonce': "ce23a48a...(64 hex)", 'userId': 237142, ... }</script>
  ```
  所以从 `/dojos` 的 HTML 里正则抠 `'csrfNonce'\s*:\s*"([^"]+)"` 就行。
- ✅ 头名**必须是 `CSRF-Token`**。实测 `X-CSRF-Token` 是 403，把 nonce 放进 JSON body 也是 403。

> ⚠️ 坑 1、2、4 都会**伪装成"浏览器没起来 / 一直等到超时 / 登录态不对"**，非常费时间。**先查这三条。**

### 3.5 落盘位置（**不要**放进知识库）

```
<本机路径>    cookie / token / 用户名
<本机路径>   专用 SSH 密钥
<本机路径>        dojo 主机公钥（首次连接自动落盘）
<本机路径>                    自动化用 Edge profile（独立，别删）
```

> **敏感**：token 等同于账号权限。放在用户目录专用目录，**不进 `<本机路径>`**，
> 也就不会被 Obsidian 同步出去。

### 3.6 还是失败就人工兜底

在浏览器里手动 `设置 → SSH Key` 粘贴 `pc_ed25519.pub`；
再手动在页面点 `Start`，然后直接跑 `pc_lib.download_challenge()` 捞文件。

### 3.7 注册（还没有账号时）—— ⚠️ 中文界面有个坑

`http<本机路径>` 要求手打一句"承诺"，**完全匹配**才解锁提交按钮
（提交按钮初始是 `btn-disabled`，校验通过才把 `#commitment-verified` 置为 `verified`）。

**🔴 坑：界面切到中文时，提示显示的是中文，但校验用的原文写死在 JS 里、是英文的。**

```js
const commitmentText = "I have read the ground rules and commit to not publish pwn.college writeups on the internet.";
function normalizeText(text) {
  return text.toLowerCase().replace(/[^a-z]/g, '').split('').sort().join('');
}
```

`normalizeText` 会**转小写 → 只留 `a-z` → 按字符排序**（所以不怕大小写和标点）。
但中文那句话被剥完只剩 `pwn.college` 的 **10 个字母**（`ceegllnopw`），
而英文原文归一化后是 **75 个字母** —— **中文怎么打都不可能通过**。

**✅ 解决办法：原样粘贴这句英文**（大小写和标点其实无所谓）：

```
I have read the ground rules and commit to not publish pwn.college writeups on the internet.
```

> 也就是说：**中文界面下按中文提示打字是永远注册不上的**，报错文案是
> `请按照上面所示输入承诺` / `Please type the commitment as shown above`。
> 这属于上游的本地化 bug，遇到直接贴英文即可。

---

## 四、完整 API 速查（前缀 `/pwncollege_api/v1`）

> ⚠️ 命名空间前缀以 `site/dojo/api/__init__.py` 的 `add_namespace()` 为准。
> **是 `/users` 和 `/ssh_key`，不是 `/user` 和 `/keys`** —— 我按直觉猜过一次，404。

| 用途 | 方法 | 路径 | 备注 |
|---|---|---|---|
| 当前用户 | GET | `/users/me` | 也用来探登录态 |
| **签发长期 token** | POST | `/users/me/tokens` | body `{"expiration":"YYYY-MM-DD"}`（可省） |
| 列出 dojo | GET | `/dojos` | |
| 模块+挑战 | GET | `/dojos/<dojo>/modules` | 含 `required` |
| 已解决 | GET | `/dojos/<dojo>/solves` | `module_id` + `challenge_id` |
| 题面 | GET | `/dojos/<dojo>/<m>/<c>/description` | 返回渲染后的 HTML |
| **提交 flag** | POST | `/dojos/<dojo>/<m>/<c>/solve` | body `{"submission":...}` |
| **启动** | POST | `/docker` | `{dojo,module,challenge,practice,home}` |
| 当前/终止 | GET/DELETE | `/docker` | |
| 下一题 | GET | `/docker/next` | 模块内推进 |
| **注册 SSH 公钥** | POST | `/ssh_key` | body `{"ssh_key":"ssh-ed25519 ..."}` |

**鉴权**：`authed_only` 只看 Flask session（`session["id"]`），**不认 CTFd token**；
但 dojo 部署在 CTFd 上，`Authorization: Token <值>` 仍可能被 CTFd 的请求钩子转成 session ——
`pc_lib` 两种都支持、自动择优，**以实测为准**。
**CSRF**：cookie 模式的 POST 必须带 `CSRF-Token` 头，值从 `GET /csrf` 的 `csrfNonce` 取。

---

## 五、踩坑与纪律

### 5.1 平台侧

- **A1** 起新题会**删除旧容器** —— 换题前先捞产物、先 `git`/备份脚本。
- **A2** 提交有**频率限制**（默认 10 次/分钟）→ 别拿脚本暴力试 flag，会被 `429`。
- **A3** 容器**空闲 6 小时**回收；`/home/<用户>` 持久，`/challenge` 不持久。
- **A4** `practice` 模式给的是**假 flag**（内容就是 `practice`），只用来调试 exploit。
- **A5** 部分内核题需要虚拟机：容器里有 `vm` 命令（KVM 已透传）。

### 5.2 本机侧

- **B1** 本机 `scp.exe`/`sftp.exe` 坏（`pipe: Unknown error`）→ **一律走 paramiko**。
- **B2** 调桥接**不要用 Bash 调 powershell**（被安全策略拦）；`pc_flow.py` 里是直接
  `python kali_bridge.py`，绕开这一层。
- **B3** Bash 里出现 `csc.exe` 字样也会被拦。
- **B4** Kali 只剩约 595 MiB，**不要往 Kali 上装东西**；Kali 侧脚本只准 stdlib + openssl + sympy。

### 5.3 纪律（沿用 `00-训练总纲`）

- flag 必须**实际提交成功**才算解出；本地"看起来像 flag"不算。
- 每题的**卡点**要单独记 —— 那是训练数据里 `dpo.rejected` / `trace.why_waste` 的来源。
- 只跑**授权范围**内的东西：本工作流只碰你自己的 pwn.college 账号与题目容器。

---

## 六、目录布局

```
<本机路径>
├── tools\pwncollege\
│   ├── pc_lib.py        客户端核心（API + SFTP）
│   ├── pc_login.py      一次性登录（CDP 取 cookie + 签 token + 注册公钥）
│   └── pc_flow.py       编排：find / pull / submit / status / stop
├── 题目库\pwn.college\<dojo>\<module>\<challenge>\
│   ├── <原始附件…>        从 /challenge 捞下来的
│   ├── description.md   题面
│   ├── manifest.json    dojo/module/challenge + 每个文件的 SHA256
│   └── _flat\           摊平副本（给 Kali 桥接用，桥接只收平铺文件名）
└── 战例库\pwn.college\<dojo>\<module>__<challenge>.md      复盘
```

---

## 七、TODO

- [ ] `pc_flow.py auto --dojo X`：find → pull → 出题面 → 交给模型，真正的"一键下一题"
- [ ] `pc_flow.py report`：从 `manifest.json` + 会话记录自动生成复盘骨架
- [ ] 把"起新题会删旧容器"做成 `pull` 前的**强制确认**（现在只打日志）
- [ ] 支持 `access_code`（部分 dojo 需要）—— 接口已留参数，未实测
- [ ] 与 `dataset/` 打通：解出一题自动 +1 SFT / +1 DPO / +1 trace
