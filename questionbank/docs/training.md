# 六人团队第一轮训练

六天共 36 道不同题目，每人每天一题、轮换六类。A–F 是占位成员编号，按你们团队分配。选题来自附件已完整下载的首批材料；**开始前仍须确认实际运行环境**。

| 天 | A | B | C | D | E | F |
|---|---|---|---|---|---|---|
| 1 | web · philtered | pwn · downunderflow | reverse · number mashing | crypto · complementary | misc · tldr please summarise | forensics · Retro! |
| 2 | pwn · one byte | reverse · zeus | crypto · randomly chosen | misc · Intercepted Transmissions | forensics · doxme | web · actually-proxed |
| 3 | reverse · masked squares flag checker | crypto · flag art | misc · As per my last email... | forensics · Bad Policies | web · grades_grades_grades | pwn · confusing |
| 4 | crypto · shufflebox | misc · kick the bucket | forensics · How to pronounce GIF | web · sniffy | pwn · vector overflow | reverse · jmp flag |
| 5 | misc · Down To Modulate Frequencies! | forensics · Do the loop! | web · co2 | pwn · corporate-cliche | reverse · rusty vault | crypto · hungry-hungry-caterpillar |
| 6 | forensics · ZFS 文件恢复 | web · mini-me | pwn · safe calculator | reverse · skippy | crypto · apbq rsa i | misc · Wacky Recipe |

具体 ID、难度与题族见 `data/team-curriculum.json`。优先选原始标注 beginner/easy 的条目；unknown 保留未知，不根据分值伪造难度。

维护者执行 `python bank.py prepare <ID> --out <该成员独立目录>`。每人只拿分配目录，以免看到其他人的 WP。缺少完整题面时该命令会拒绝，维护者核对原题后才可使用 `--allow-incomplete`。

## 一道题的完成标准

1. 记录题面与附件摘要，并验收所用平台/本地实例。Web/Pwn 等服务题先部署到各自隔离环境；本次没有部署挑战。
2. 独立分析、保留真实工具返回，关键步骤同步截图与思路记录。建议先设 45–90 分钟预算，超时要记录最后一条可复现证据。
3. 输出候选答案或利用结果，由平台或维护者独立判题。单靠工具 `ok`、正则匹配、候选模型输出、WP 生成均不能判作成功。
4. 完成后复盘：题型、关键假设、有效证据、失败工具、环境成本、最终验收。再由团队共享通用方法；原答案单独保管。

## 统计方式

分别统计环境通过率、已验收任务的正确率、时间中位数、工具阻塞率、WP 证据完整率；不要把题面缺失和环境不启动混成解题失败。`bank.py record` 仅保存自报结果，需独立证据才能升级为正确。

第二轮针对第一轮失败最多的知识点选题，而非只加总题数；随后才使用维护者补齐的 holdout。相同题族、同份附件和同比赛复刻应在同一侧，防止用训练题测自己。

## 优先补齐的方向

当前完整附件首批为 Web/Pwn/Reverse/Crypto/Misc 各 12 题、Forensics 6 题。取证目录 53 条包含保留评测与大型数据集；应继续优先补齐 PCAP、Windows 事件日志、磁盘恢复、内存分析，再逐步增加大型镜像。本包不会自动下载数 GB 镜像或自动安装新环境。
