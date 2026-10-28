# CTF 系统 × 破甲（Purge）融合说明

上游：`kingcharleslzy-ai/dsh-purge` 1.6.60 @ `27919a326b6615b1968661a3e749760cec3a2e07`
融合契约：`FUSION-CONTRACT.md`　评分说明：`..\..\docs\purge-redteam-scoring.md`

## 一、融合后长什么样

一套 MCP 服务、两族工具、同一份 case 隔离：

- `ctf_*`：原 CTF 系统全部保留（`ctf_os.ALL_TOOLS` 现共 202 个工具）
- `redteam_*`：破甲红队 **56 个独立工具**（各自 schema，不再是 2 个泛化入口）
- `ctf_redteam_*`：12 个桥接/语义工具（8 个原兼容入口 + 4 个语义只读入口）

catalogue 来源：runtime:list (cached)
降级标记：False（true = 运行时未就绪时从 schema.js 提取，参数骨架可用、执行需运行时）

## 二、目录

```
D:\强网杯大师\
  integrations\purge-redteam\
    upstream\            完整上游：lib/redteam（18 模块，含 tools.js）、presets/redteam、skills/redteam
    runtime\             redteam-mcp.mjs（执行运行时）+ ctx-shim.mjs + catalogue.json
    references\          23 篇 playbook（人读）
    bridge.mjs           旧桥（55 store 操作，保留兼容）
    FUSION-CONTRACT.md   架构契约
  tools\
    ctf_redteam.py             8 个兼容工具
    ctf_redteam_fusion.py      56 个 redteam_* 注册 + 运行时调用
    ctf_redteam_semantics.py   技能/预设/评分/角色 4 个只读工具
  skills\redteam-*\SKILL.md    23 个红队技能（+ redteam-index.json）
  config\purge-redteam-preset.md   红队 persona/纪律（只读参考）
  docs\purge-redteam-scoring.md    红队评分与 WP 并存规则
  AGENTS.md                    末尾 PURGE-REDTEAM 段
```

## 三、56 个红队工具对照

| 工具 | 说明（上游摘录） | 主要参数 |
|---|---|---|
| `redteam_access_add` | 记录一次成功获得的访问会话（横向移动起点）。method 例如 vnc/rdp/ssh/web-shell/webshell/db；privilege 例如 admin/user/ | engagement,host,username,method,privilege,asset_id |
| `redteam_access_list` | 列出已获得的访问会话。 | engagement,host |
| `redteam_agent_slot` | 【主会话派活前后用】执行智能体的并发闸门：同一靶标**最多同时 3 个**在跑（可用 REDTEAM_MAX_AGENTS 配置）。action=status 看还剩几个名额与谁在 | action,label,key |
| `redteam_asset_add` | 把一个资产及其端口/服务/指纹写入资产库（幂等 upsert）。每条发现必须标注 provenance：被动收集填 passive，主动探测填 active，并填写 tool（数据 | engagement,ip,state,primary_name,provenance,tool |
| `redteam_asset_assess` | 给资产做「易打性评估」：预期能拿下哪些成果（账号权限/RCE/服务器权限/数据库权限/敏感数据/边界突破）、优先级多高、判断理由。信息收集收口时对每个资产调用一次，供指挥者按性价比 | engagement,asset_id,ip,priority,potential,reason |
| `redteam_asset_get` | 取单个资产的完整详情：全部端口与服务、指纹、采集溯源时间线、关系边。用于深入分析某个目标。 | engagement,id |
| `redteam_asset_graph` | 导出资产图谱（C 段 → 资产 → 开放端口，含域名解析边），用于拓扑推理与横向移动路径规划。节点数超过上限时按 C 段缩小范围。 | engagement,cidr,maxNodes |
| `redteam_asset_link` | 在资产库中写入一条关系边（图谱与后续横向分析共用）。relation 例如 resolves / exposes / contains / trusts / shares_cert | engagement,src_kind,src_id,dst_kind,dst_id,relation |
| `redteam_asset_query` | 检索资产库。支持按 C 段、端口、服务、指纹、来源、内外网维度（scope）、排序（sort）、关键词（全文，覆盖 IP/域名/banner/服务/指纹）过滤。返回紧凑结果，含每个 | engagement,cidr,port,service,fingerprint,provenance |
| `redteam_asset_stats` | 资产测绘概览：C 段数、资产数（存活）、开放端口、服务、指纹、被动/主动溯源条数，以及各 C 段的明细。 | engagement |
| `redteam_asset_test` | 记录对某个资产的测试情况：本次做了什么测试（`test`，追加式）、还剩什么攻击面（`surface`，覆盖式）、当前测试状态、是否被 WAF 封禁。**每个资产开始测之前先调一次 | engagement,asset_id,ip,status,test,notes |
| `redteam_asset_timeline` | 资产「发现时间」视图：按天聚合"哪天收了多少资产"（区分内网/外网），并列出最近发现的资产。用于回答"这个资产是什么时候发现的"、检查信息收集有没有断层，也用于本轮收集的收口核对。 | engagement,limit |
| `redteam_attack_chain` | 攻击链：按攻击面位置串起来的五个阶段 —— ① 信息收集（互联网侧）→ ② 互联网资产权限 → ③ 边界突破（搭隧道）→ ④ 内网资产权限 → ⑤ 靶标权限。返回每阶段的阶段目标、 | engagement |
| `redteam_attack_file_add` | 保存一个**实际生效**的攻击文件（脚本/POC/EXP/字典）到目标文件夹，供复用与交付。目录结构：attack-files/<IP|URL主机|C段>/<文件名>。eviden | engagement,target,name,kind,description,evidence |
| `redteam_attack_file_list` | 列出已保存的攻击文件（按目标文件夹分组）。开始打某个目标前先看这里，避免重复造轮子。 | engagement,target |
| `redteam_attack_path` | 导出攻击图谱：资产拓扑 + 漏洞节点 + 已控制资产（meta.owned）。用于横向移动路径规划与战果汇报。节点过多时用 cidr 缩小范围。 | engagement,cidr,maxNodes |
| `redteam_chain` | 读取完整攻击链（按步骤顺序），用于汇报与检查链路是否闭合（入口 → 权限 → 内网突破）。 | engagement |
| `redteam_chain_add` | 记录一个攻击链步骤。**报告里「这一步怎么来的」完全靠这条记录**：账号密码怎么来的、冰蝎马怎么上的、隧道怎么搭的，都要在这里用 `tool`（实际命令原文）+ `detail`（ | engagement,agent,stage,title,detail,tool |
| `redteam_credential_add` | 记录一条凭据（漏洞利用/内网渗透角色）。**必须把口令/密钥明文写进 secret_value**——面板要直接显示明文供随时复用；同时用 secret_ref 指向 runs/  | engagement,agent,host,username,secret_type,secret_value |
| `redteam_credential_list` | 列出已收集的凭据（含明文 secret_value），用于凭据复用与横向移动。 | engagement,host,username |
| `redteam_domain_index` | 按域名维度聚合资产：每个域名关联了哪些 IP/资产。用于梳理主域名、子域与 C 段的关系。 | engagement |
| `redteam_engagement_open` | 打开或创建一次攻防演练靶标（按单位名称），并把**当前会话**绑定到该靶标（子智能体会自动继承）。后续所有资产工具默认作用于它。若靶标已存在则复用其资产库。写入的是本会话的绑定，不 | target,scope |
| `redteam_http_evidence_add` | 保存一条 HTTP 证据：原始请求与响应。报告会把它渲染成可粘贴进 Burp Suite / Yakit 的原始报文，因此 request 必须是完整可重放的原始请求（含请求行、H | engagement,vuln_id,asset_id,label,method,url |
| `redteam_poc_add` | 把**通用可复用**的 POC/EXP 落进知识库（跨靶标共享）。从互联网拿到的、自己手搓的、或已经调通验证过的都往这里放——只收录真正有效的，并写清来源与验证证据。判断标准：** | title,kind,category,cve,component,versions |
| `redteam_poc_get` | 取一条知识库 POC/EXP 的**完整内容**（正文 + 用法 + 验证记录 + 落盘路径），可直接照用或改造成目标专用脚本。不传 id 时可用 code（redteam_poc | id,code |
| `redteam_poc_list` | 列出知识库里的 POC/EXP（可按 kind/source/component/verified 过滤，不带条件就是全部）。用于盘点"我们手上已经有哪些现成武器"，避免重复搜集。 | kind,source,component,verified,limit |
| `redteam_poc_search` | 【打 Nday/1day 前的第一步】先查"现成的"两层：① **知识库**（本机沉淀的通用 POC/EXP，跨靶标共享，按"已验证 → 复用次数"排序）② **本机 nuclei | q,cve,component,kind,category,engagement |
| `redteam_poc_update` | 更新知识库条目：补验证结论（verified + verified_note）、修正影响版本、补用法或正文、改标签。**在真实目标上验证通过后，一定要回来把 verified 置  | id,code,patch,verified,verified_note |
| `redteam_poc_use` | 记一次知识库 POC/EXP 的复用（用在哪个靶标/目标）。复用次数高的条目会排前面，方便后来者优先选经过实战的武器。 | id,code,used_on |
| `redteam_preflight` | 【开工前必须跑一次】平台技能与资源自检：逐个检查红队技能的必需环境变量（如 FOFA 测绘的 FOFA_KEY）、本机工具与二进制（suo5 / fscan / gogo / fr | include |
| `redteam_report` | 【已弃用，改用 redteam_score_report】生成成果报告（Markdown）：只收录**已验证/已利用且中危以上**的成果漏洞（每条附可粘贴进 Burp/Yakit  | engagement |
| `redteam_report_targets` | 【已弃用，改用 redteam_score_report】按目标查看成果报告（每个 IP / URL / C 段一份）：成果漏洞（含可粘贴进 Burp/Yakit 的原始请求）、已 | engagement,target |
| `redteam_role_prompt` | 取出某个红队角色当前生效的系统提示词，只供查看。派活时不要把全文抄进任务；在 subagent 的 prompt 第一行写 redteamRole: <code>，角色稿会进入子会 | engagement,role |
| `redteam_role_prompt_reset` | 把角色系统提示词恢复为内置默认（新版模板）。老靶标想用上最新版角色提示词时用它；省略 role 则四个角色全部重置。 | engagement,role |
| `redteam_roles` | 列出红队角色及其职责标题（信息收集 / 漏洞检测 / 漏洞利用 / 内网渗透）。 |  |
| `redteam_score_hit` | 记录一次得分。得分规则已按《突破入侵类得分规则（合并版）》重构为 **25 项**（一、获取权限 21 项 + 二、突破网络边界 4 项，共 8 个类别），另有 8 条通用规则 G | engagement,code,point_id,point_name,points,target |
| `redteam_score_list` | 查看得分目标面板：所有得分点（名称/分类/分值/是否已拿下/命中证据）与总分进度。**每次规划下一步之前先看这里**，按分值高低决定先打什么。 | engagement |
| `redteam_score_point_save` | 新增或修改得分点（分值/名称/分类/说明/启用）。用户也会在界面上编辑；智能体只在必要时用（例如发现规则里还有未被记录的得分项）。带 id 为修改，不带 id 为新增。 | engagement,id,name,code,category,points |
| `redteam_score_report` | 攻击得分链路复现报告：只收录"拿到了分"的成果（没得分的漏洞不进报告），每一项都尽量附上可直接粘贴进 Yakit Repeater 复现的原始请求。需要交付报告时用这个，而不是 r | engagement,limit,markdown |
| `redteam_session_bind` | 把一个**已经存在**的靶标绑定到当前会话（多会话并行时用：每个会话绑自己的靶标，互不串写）。可用靶标 id 或单位名称，省略则列出可绑定的靶标。 | engagement |
| `redteam_session_check` | 实测所有 WebShell 与隧道的连通性（由 host 侧真实发起 HTTP / TCP 连接），并把在线/离线状态回写数据库。开工前和长时间任务后各跑一次。 | engagement,timeoutMs |
| `redteam_session_info` | 查看**当前会话绑定的是哪个靶标**（会话 id、父会话、根会话、绑定链）。多会话同时开工时，先跑它确认自己没串到别人的靶标上。 |  |
| `redteam_sessions` | 【每次决策前后都要看】一屏总览当前所有可复用入口：已上线的 WebShell、可用的内网隧道（含监听地址与可达网段）、凭据、访问会话，并给出在线/离线统计。打内网前先看这里，不要重 | engagement |
| `redteam_shot_add` | 登记一张证据截图：把图片拷进靶标目录并关联到得分点/命中（面板展开得分点即可看图，报告里也会嵌入）。批量得分点（如终端权限）每个得分点最多展示 3 张代表图，不必逐台截图。 | engagement,agent,path,data_base64,label,kind |
| `redteam_shot_delete` | 删除一张证据截图（连同磁盘文件）。 | engagement,id |
| `redteam_shot_list` | 列出已登记的证据截图（含所属得分点、目标、类型、落盘文件）。 | engagement,point_code,hit_id,asset_id |
| `redteam_tunnel_add` | 登记一条内网隧道。**打进内网必须先用技能 suo5-tunnel 通过 WebShell/HTTP 建 socks5（kind=suo5）**；没有隧道就不要手搓内网探测脚本。l | engagement,agent,kind,listen,entry,reach |
| `redteam_tunnel_list` | 列出已登记的内网隧道（含状态、监听地址、可达网段、entry_kind 与 legit 判定）。**legit=false 表示只在自己 VPS/自建服务器上开的通道，不算跨越靶标 | engagement,status |
| `redteam_tunnel_update` | 更新隧道状态（关闭/失效/更换监听地址）或补 entry_kind 判定。用完隧道务必标为 down 并说明，避免后续误用。**老记录没声明入口归属的（legit=null，界面显 | engagement,id,status,listen,reach,entry |
| `redteam_vuln_add` | 记录一条漏洞发现（漏洞检测角色）。带 cve 时按 (asset_id, cve, target) 幂等更新。severity：critical|high|medium|low|i | engagement,agent,asset_id,cve,title,severity |
| `redteam_vuln_query` | 检索漏洞库：按严重级、状态、CVE、资产、C 段或关键词过滤。用于挑选待利用目标或核对误报。 | engagement,severity,status,cve,asset_id,cidr |
| `redteam_vuln_update` | 更新漏洞状态/严重级/证据（例如验证后置为 confirmed、利用成功后置为 exploited、误报置为 false-positive）。 | engagement,id,status,severity,evidence,confidence |
| `redteam_web_list` | 列出 Web 资产（含可直接访问的 URL 与页面标题）。做 Web 渗透前先看这里，优先从接口入手。 | engagement,cidr,limit |
| `redteam_webshell_add` | 登记一个已上线的 WebShell。**必须上传冰蝎马（behinder）或哥斯拉马（godzilla）的加密马**——用户在控制台要用对应客户端直连，一句话马/自研马/MemSh | engagement,agent,url,shell_type,pass_key,privilege |
| `redteam_webshell_list` | 列出已登记的 WebShell（含在线状态与最后检查时间）。 | engagement,status,asset_id |
| `redteam_webshell_update` | 更新 WebShell 状态（被删/掉线/权限变化）或补充说明。 | engagement,id,status,privilege,note,check_note |

## 四、兼容与语义工具

| 工具 | 作用 |
|---|---|
| `ctf_redteam_capabilities` | 融合模块的功能映射与已注册工具清单 |
| `ctf_redteam_plan` | 按题型生成红队协同与证据路线 |
| `ctf_redteam_query` | 上游 store 只读操作（55 个 op 白名单） |
| `ctf_redteam_record` | 上游 store 写入操作（带 `source_step` 证据校验） |
| `ctf_redteam_report` | 同题红队成果补充材料 |
| `ctf_redteam_playbook` | 按行读取 23 篇 playbook |
| `ctf_redteam_session_check` | 已记录会话连通性检查（需 confirm=true） |
| `ctf_redteam_schema` | 查询源工具原始参数定义 |
| `ctf_redteam_skills` | 23 技能清单 + 依赖探针（probe 级） |
| `ctf_redteam_preset` | 红队 persona/规则段原文（只读） |
| `ctf_redteam_score_rules` | 评分维度与权重（node import 优先） |
| `ctf_redteam_roles` | 红队角色清单 |

## 五、纪律（融合后不变）

1. 工具注册 ≠ 依赖已装；技能可用性只到 probe 级证据。
2. `source_step` 必须指向真实执行步骤，`ctf_redteam_*` 自身记录不能当执行证据。
3. `case` 必须是 `ctf-[a-f0-9]{16}` 且任务已存在；一题一个 engagement。
4. 不联网、不自动装依赖、不改宿主审批与网络范围。
5. 答案验证仍只认平台/验证器回执。

## 六、回滚

```powershell
# 1) 摘掉 Python 接入（工具数回落，CTF 系统其余功能不受影响）
Remove-Item D:\强网杯大师\tools\ctf_redteam_fusion.py, D:\强网杯大师\tools\ctf_redteam_semantics.py -Force
# 2) 还原 ctf_os.py 的接入两行（用 ctf_os.py.bak-fusion-* 覆盖）
# 3) 技能与文档可留可删：skills\redteam-*、config\purge-redteam-preset.md、docs\purge-redteam-scoring.md
# 4) 数据保留：.local\purge-redteam\engagements 不删
```
