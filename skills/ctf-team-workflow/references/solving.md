# 六类题型的证据路线与工具参数

## 共用起点

先读题面与允许使用 AI 的比赛规则；保留附件摘要。明确题型后调用 `ctf_profile category=<类别>`，再 `ctf_specialist_status`。普通二进制先 file/strings/结构，源码题先读源码。工具选择随实际证据调整，路线不是强制把每个工具都跑一遍。

专项工具使用 `local_file` 上传 Windows 附件或 `target` 指定同题 Kali 文件，二者择一；显式 `case/wp_case` 必须相同。超时默认 60 秒、桥上限 600 秒，必要时给合理预算。下面 JSON 仅为自建样例，不是比赛答案。实际参数以当前目录为准。

## Web

`web_http_inspect` 读取明确 URL 的头、受限正文摘要和 HTML；`web_html_parse` 解析已有 HTML；`web_jwt_decode` 只解码，不验证签名、不认证 role；`web_browser_capture` 用 Kali Chromium 采真实画面。

网络与截图工具必须 `confirm:true`。截图默认仅允许同源，第三方静态资源按题明确列 `allow_origins`；保持浏览器沙箱和 TLS 校验。PNG 经摘要回收后可自动记入同题 WP，导出前仍检查像素。

```json
{"url":"http://127.0.0.1:8000/","confirm":true,"timeout":60}
```

根据源码、状态码、表单、认证和数据流提出具体假设，再在题目靶场验证。泛化扫描/自动 sqlmap/ffuf 不是读完题面后的固定动作。

## Pwn

`pwn_elf_info` 看架构、保护、符号；`pwn_cyclic` 生成模式或根据真实崩溃值定位；`pwn_rop_search` 有界检索 gadget。随后在题目 VM/服务实际验证，不把 gadget 发现当利用完成。

```json
{"action":"find","value":"62616161","n":4,"max_length":4096}
```

`value` 的十六进制以字符串保留，避免 CLI 将它当十进制整数。n、端序和崩溃字段要与目标一致；ASLR/PIE 基址取实际运行值。缺服务、libc 或 loader 时记录环境缺项，不宣称本地已拿到比赛 flag。

## Reverse / Android / Windows

`reverse_binary_info` 用 LIEF 看 PE/ELF 结构；`reverse_disassemble` 指定架构、文件偏移/字节区段；`reverse_symbolic` 对明确成功地址或输出作有界探索。

```json
{"code_hex":"b82a000000c3","arch":"x64","address":4096,"limit":8}
```

符号候选标 `candidate_verified=false`，必须送入真实程序复现目标条件。复杂反调试或路径爆炸及时改路线，不能无限增大状态数。

Windows 原生 PE 用 REA/Ghidra 静态分析，x64dbg 动态验证；文件 VA 和 ASLR 后运行地址不能直接比较，RVA=文件VA−ImageBase，运行地址=实际模块基址+RVA。加载后的系统断点通常不是入口，入口由 PE RVA 和实际模块基址计算。同一架构单控制者，超时不代表目标已停止。

Android 先 jadx/Apktool 静态，ADB/JEB/设备动作只有本机实际已部署并在用户范围内才用，REA operation 列表不等于手机已授权。

## Crypto / 经典密码

RSA 多模数先 GCD/shared factors，未知算法先辨结构。`crypto_factor` 区分完整与部分分解并验乘积；`crypto_crt` 逐项验同余；`crypto_lll` 验变换矩阵；`crypto_z3` 支持结构化表达式与 SMT-LIB2；`crypto_aes_decrypt` 使用明确密钥的 ECB/CBC/GCM，GCM 标签失败不能当明文成功。

```json
{"variables":{"x":"int","y":"int"},"constraints":["x+y==13","x-y==3"]}
```

经典密码先 `crypto_diagnose` 查看 IC、列 IC、字符集、长度结构。统计排名是线索，不是严格排除定理。`crypto_selfcheck` 用通用已知样例测求解器，`crypto_attack` 才搜索候选；未通过自检的阴性结果仅是未测出。

默认 n-gram 语料来自本机通用 HackTricks 英文正文，至少需满足代码的语料量；无语料时先安装通用知识库或提供 `corpus`。语料不含本批题答案、solver 或私人 flag；缓存仅用自己生成的本机文件，不从题目包加载 pickle。诊断不依赖语料，搜索/自检需要语料与预算。自检通过也不保证覆盖所有短密文。

## Misc

`misc_file_inspect` 查看摘要/魔数/熵/字符串；`misc_archive_list` 只列成员并提示越界路径，不自动解压；`misc_image_inspect` 查看元数据和格式尾部。图片元数据检查不是完整隐写搜索。

依据文件真实格式再选择 exiftool/binwalk/音频频谱/编码路线。解压前检查成员路径和体积，保存原附件；未知二进制不在宿主机自动运行。

## Forensics

`forensics_pcap_summary` 离线有界读 PCAP，输出协议、流、DNS 与载荷片段；需要完整会话时再用 tshark/重组脚本，摘要不等于所有 TCP 数据。

`forensics_volatility plugin=help` 只验证入口；真实镜像分析需要明确插件、镜像、匹配符号。不要将帮助成功写成内存镜像已分析。保留原始证据摘要，分析产物与原件分开。

## 收敛与复核

每次调用要解决一个明确的不确定点，记录假设、实际输出、耗时和下一步。无进展时先检查输入/参数/环境/自检覆盖，再更换路线。复核者使用原附件与真实结果独立检查结论，不能把两个模型互相赞同当验证。
