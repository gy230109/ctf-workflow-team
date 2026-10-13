# 解题 AI 的精确引导

每次新会话先读这份文件。训练目标是独立分析真实题面和公开附件，保存可复现证据；题目目录可生成于 `bank.py prepare`。

1. 题库维护者负责抽题、确认题面完整、准备环境与独立判题。解题者只读取分配目录的 `task.json`、`README.md` 和 `attachments/`。管理员的来源目录、原始仓库 WP、参考答案和既有战例不作为本题输入；不从题名搜索解答。
2. 读取 `task.json` 的类别、文件摘要、环境状态。运行环境尚未验收时先报告缺项。实例 URL/端口只用维护者明确提供的本地目标或本人平台实例；旧比赛域名不是当前目标。
3. 复用本机已经部署的 CTF-OS、已开机 Kali 与现有 SSH 桥。使用已信任的连接配置，不重装、不替换、不猜测凭据。先 `wp_init`，独立 case 名可用 `train_<题目ID>`。
4. 调用 `ctf_profile`，参数 `category=web|pwn|reverse|crypto|misc|forensics`。所有后续分析调用带同一个 `wp_case`；需要 `case` 的工具令它与 `wp_case` 一致。`file_path` 使用当前附件的本机绝对路径。
5. 未知附件先 `file_triage`。下表工具名来自当前已导出的增强模块，不能把名字当成已安装、已可用或解题正确的证明。

| 方向 | 现有起手工具 | 后续验证 |
|---|---|---|
| Web | `web_inspect`、`web_capture`、`web_jwt_decode` | 本地实例验证请求、登录态和实际漏洞链；截真实网页画面 |
| Pwn | `pwn_checksec`、`pwn_cyclic`、`pwn_cyclic_find`、`pwn_rop_gadgets` | 用现有 `local_gdb` / `kali_run` 核对真实崩溃、地址和利用结果 |
| Reverse | `reverse_binary_info`、`reverse_disasm`、`reverse_symbolic` | 按需已有 REA/Ghidra/x64dbg；候选输入必须过真实程序 |
| Crypto | `crypto_factor`、`crypto_crt`、`crypto_lll`、`crypto_constraints`、`crypto_aes_decrypt` | 验算同余、重加密或平台提交；分解未完成要明确标注 |
| Forensics | `file_triage`、`forensics_image`、`forensics_pcap`、`forensics_volatility` | 保留提取链；内存符号、镜像格式与包截断分别验收 |
| Misc | `file_triage`、现有 `util_*`、需要时组合其他 profile | 按实际魔数/结构选路线，不能假设自动万能解码 |

6. `wp_note` 区分 observed/hypothesis/todo；观察引用真实证据步骤。关键画面用 `web_capture` 或 `wp_capture`；生成的日志图不能冒充截图。
7. 结束调用 `wp_build`。WP 生成成功不代表解题成功。记录预算、阻塞原因、工具失败与独立判题结果；不要把参考 flag 填进公共训练笔记。
8. 普通抽题默认避开 holdout 与跨源别名。保留评测由维护者另外准备，禁止先读参考 WP；本次没有运行评测。个人经验可在完成后归纳，但不能把上一题的 flag/答案当下一题证据。

现有源码核对值：

```text
tools/ctf_specialists.py  ab56d1718b1a83864ef69e5f76fa42f85b460af9b568b3b54230fb07e2d6c593
tools/ctf_specialist_worker.py  d34334ddd3588a2c03976a86a0a8c9573aca6a396ebb25c61ccbda912e876335
```

本包未改这两个模块，也未改本机配置。只有本机实际工具返回值才能证明该机器的状态。
