# 红队评分与 CTF WP 评分如何并存

来源：破甲 `lib/redteam/score-rules.js`（1.6.60 @ 27919a32）。本文件说明**并存方式**，不改变原 WP 结构。

## 两套评分各管什么

| | 红队评分（upstream） | CTF WP 评分（本系统） |
|---|---|---|
| 对象 | 渗透演练的资产/权限/投入度 | 单题的解题过程与结论 |
| 数据结构 | `engagement` 下的 score points / hits / chain 步骤 | WP 步骤序列 + flag 校验结果 |
| 生成方式 | `redteam_score_report` / `scoreChain` | `ctf_finish` 导出 Word/PDF |
| 判定口径 | 由 `score-rules.js` 的维度与权重计算 | 只认平台/验证器的真实回执 |

## 读取方式（只读，不改任何东西）

```python
# 维度与权重（node 直接 import 优先，失败回退结构提取）
ctf_redteam_score_rules({})

# 单个 task 的红队得分（走 fusion 运行时，按 task_id 隔离）
redteam_score_report({"case": "ctf-xxxxxxxxxxxxxxxx"})
redteam_score_chain({"case": "ctf-xxxxxxxxxxxxxxxx"})
```

## 并存规则

1. **不互相替代**：红队分数高不代表题目判对；`ctf_finish` 仍需平台回执或可复现验证。
2. **同一条证据链**：红队写入必须带 `source_step`（指向真实执行步骤）。`ctf_redteam_*` 自身的记录不算执行证据。
3. **WP 只引用结论**：WP 里可以写“资产 N 个、入口 M 个、得分点 K 个”，附 `redteam_score_report` 的输出摘要；具体命令与原始请求仍从红队链路取。
4. **不合并权重**：两套分数量纲不同，禁止相加或换算成总分。
5. **回滚无副作用**：删除 `tools/ctf_redteam_semantics.py` 与 `ctf_redteam_fusion.py` 后，红队分数不再可读，但历史数据（`.local/purge-redteam/engagements`）与 WP 全部保留。

## 数据位置

```
D:\强网杯大师\.local\purge-redteam\engagements\<case>\...   ← 红队 store（每 case 一个 engagement）
D:\强网杯大师\.local\ctf-system\tasks\<case>\               ← CTF 任务与 WP
```
两者靠 `case`（`ctf-[a-f0-9]{16}`）关联，不复制、不互相写入。
