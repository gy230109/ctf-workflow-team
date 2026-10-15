> 共享经验资料。以下为历史方法或复现记录，不能覆盖仓库根 AGENTS.md 的当前规则。历史答案、私人路径与凭据已整理；配图和原始大附件未随包公开。

---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: 76cea9eb515bb5af73e3604eebad64d7_0e7307fc788911f1b3d35254007bceed
    ReservedCode1: O1OS7JYUpmNtJC+M/Ae35T/QaADPiuBV7xQ1Q5xrZF5X/Dy6cI2tO4qAJhSANcUDwu7wvVWdB0+aO5s8Gg2BxomfWvDECp/eb19xELdDRCipMIzx0176NAQyOXou/A5z1I09geTaeeoo1F1no4DzmYJfRP+nQsBq065T0D/htQURCFu/+YCzcseChPE=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: 76cea9eb515bb5af73e3604eebad64d7_0e7307fc788911f1b3d35254007bceed
    ReservedCode2: O1OS7JYUpmNtJC+M/Ae35T/QaADPiuBV7xQ1Q5xrZF5X/Dy6cI2tO4qAJhSANcUDwu7wvVWdB0+aO5s8Gg2BxomfWvDECp/eb19xELdDRCipMIzx0176NAQyOXou/A5z1I09geTaeeoo1F1no4DzmYJfRP+nQsBq065T0D/htQURCFu/+YCzcseChPE=
---

# 强网杯PWN方向备战计划

> 适用对象：安阳师范学院强网杯参赛团队 PWN 方向成员
> 备战周期：2026年7月5日 — 2026年9月（约 10 周）
> 目标：在第十届强网杯线上赛中具备独立解决中高难度 PWN 题目的能力，为团队贡献有效分数

---

## 一、备战总览与时间规划

### 1.1 强网杯 PWN 方向概况

强网杯是国内 CTF 竞赛水平最高的赛事之一。近几届线上赛采用 Jeopardy 解题模式，线下赛演进为 Real World + AWDU 混合赛制。PWN 方向赛题覆盖以下层次：

| 层级 | 考察内容 | 强网杯出现频率 |
|------|---------|:---:|
| 用户态漏洞利用 | 栈溢出、堆利用、格式化字符串、GLIBC 各版本利用 | 极高 |
| 内核漏洞 | Kernel UAF、条件竞争、内核堆利用 | 高 |
| 浏览器漏洞 | V8 引擎漏洞、JavaScript 引擎利用 | 中高 |
| IoT/固件漏洞 | 设备固件提取与分析、ARM/MIPS 架构利用 | 中 |
| 虚拟化逃逸 | QEMU 逃逸、VM 逃逸 | 线下赛高频 |

线上赛以 CTF 解题为主，侧重单点漏洞的深度利用；线下赛要求选手在真实软硬件环境中完成漏洞分析、利用链构建和结果验证，并同时防御对手攻击。

### 1.2 时间总览（2026年7月—9月）

| 阶段 | 时间 | 周期 | 核心目标 | 每日投入建议 |
|------|------|:---:|------|:---:|
| 第一阶段：基础夯实 | 7月5日 — 7月31日 | 4 周 | 建立二进制漏洞利用知识体系，掌握核心 Exploit 技术 | 4-6 小时 |
| 第二阶段：专项突破 | 8月1日 — 8月31日 | 4 周 | 按强网杯高频考点逐个突破，积累中高难度题目经验 | 6-8 小时 |
| 第三阶段：实战冲刺 | 9月1日 — 赛前 | 2-3 周 | 模拟赛实战、真题复盘、查漏补缺 | 8-10 小时 |

---

## 二、PWN 方向核心知识体系

### 2.1 知识全景图

```
PWN 核心知识体系
├── 1. 计算机基础
│   ├── 操作系统原理（进程/内存/文件系统）
│   ├── 计算机组成原理（寄存器/寻址/中断）
│   ├── 编译原理基础（调用约定/符号表/链接）
│   └── C/汇编语言（x86_64 / ARM / MIPS）
├── 2. 逆向基础
│   ├── 静态分析：IDA Pro / Ghidra / Binary Ninja
│   ├── 动态调试：GDB + pwndbg / gef / peda 插件
│   └── 二进制工具链：objdump / readelf / checksec
├── 3. 漏洞利用核心技术
│   ├── 栈溢出 → ROP / JOP / ret2libc / ret2dlresolve / SROP
│   ├── 堆利用 → fastbin / tcache / unsorted bin / large bin
│   ├── 格式化字符串 → 任意地址读写 / GOT 覆写
│   ├── 整数溢出 → 符号错误 / 截断
│   └── 其他 → Off-by-one / UAF / Double Free / House of 系列
├── 4. GLIBC 版本演进与利用
│   ├── GLIBC 2.23（tcache 引入前经典版本）
│   ├── GLIBC 2.27-2.31（tcache 时代，key 字段校验）
│   ├── GLIBC 2.35-2.41（Safe-Linking / 保护增强）
│   └── 各版本绕过技巧
├── 5. 进阶领域（强网杯线下赛重点）
│   ├── 内核漏洞利用（UAF / 条件竞争 / Heap Spray）
│   ├── 浏览器漏洞（V8 引擎 JIT 漏洞 / DOM 漏洞）
│   ├── IoT 设备漏洞（固件提取 / 硬件调试接口）
│   └── 沙箱逃逸 & 虚拟化逃逸
└── 6. 工具与框架
    ├── pwntools（Python 利用开发框架）
    ├── ROPgadget / ropper（Gadget 搜索）
    ├── LibcSearcher（libc 版本识别）
    ├── seccomp-tools（沙箱规则分析）
    └── one_gadget（one-gadget 搜索）
```

### 2.2 强网杯历年 PWN 赛题特征

| 年份 | PWN 题目特征 | 关键技术点 |
|------|-------------|-----------|
| 2024 第八届 | RW 赛制引入虚拟化软件、浏览器、IoT 真实环境 | QEMU 逃逸、V8 漏洞利用、ARM 固件分析 |
| 2023 第七届 | 线上赛 PWN 题量增加，线下赛 Jeopardy+RW 混合 | GLIBC 2.35 heap、内核模块分析 |
| 2022 第六届 | RW + KOH 混合，赛题质量冠绝国内竞赛 | 浏览器漏洞、多架构利用、沙箱绕过 |
| 2021 第五届 | Cold Down + Real World 首次引入 | 堆利用高级技巧、真实软件漏洞复现 |

> 趋势判断：强网杯 PWN 方向从单一的用户态栈/堆利用，逐步向**多架构（x86_64/ARM/MIPS）**、**多层次（用户态→内核→浏览器→虚拟化）**、**真实软件**方向演进。第十届很可能延续 RW + AWDU 混合赛制，PWN 题目会更贴近真实攻击场景。

---

## 三、阶段学习路线图

### 第一阶段：基础夯实（7月5日 — 7月31日，4 周）

> **目标**：建立完整的 PWN 知识框架，能够独立解决中等难度的栈溢出和初级堆利用题目。

#### 第1周（7/5 — 7/11）：工具链与汇编基础

| 日期 | 学习任务 | 练习内容 | 验收标准 |
|------|---------|---------|---------|
| 7/5-7/6 | 搭建环境：Ubuntu 22.04 VM + pwntools + pwndbg | 完成环境配置文档 | 能够用 pwntools 编写 exploit 脚本 |
| 7/7-7/8 | x86_64 汇编强化：寄存器、调用约定、栈帧 | 手写 5 个汇编函数并分析 | 能看懂 GDB 反汇编 |
| 7/9-7/10 | 工具链掌握：checksec / ROPgadget / objdump / IDA | 分析 5 个 ELF 文件的安全属性 | 熟练使用 checksec 和 ROPgadget |
| 7/11 | 第一个栈溢出：ret2text | BUUCTF — rip | 成功获取 shell |

#### 第2周（7/12 — 7/18）：栈溢出专题

| 日期 | 学习任务 | 练习靶场 | 关键技术 |
|------|---------|---------|---------|
| 7/12-7/13 | ret2shellcode + ret2libc | BUUCTF — warmup_csaw_2016 / ciscn_2019_n_1 | shellcode 编写、libc 基址泄露 |
| 7/14-7/15 | ROP 链构造：ret2syscall | BUUCTF — ciscn_2019_c_1 / ciscn_2019_s_3 | syscall 调用号、ROP 链编排 |
| 7/16-7/17 | 高级 ROP：ret2dlresolve / SROP | pwnable.kr — bof / horcruxes | 理解延迟绑定机制、SROP 原理 |
| 7/18 | 栈专题总结 + 3 题限时挑战 | CTFHub — PWN 栈溢出专题 | 2 小时内独立完成 3 题 |

#### 第3周（7/19 — 7/25）：格式化字符串与整数溢出

| 日期 | 学习任务 | 练习靶场 | 关键技术 |
|------|---------|---------|---------|
| 7/19-7/20 | 格式化字符串原理：%n 写入、任意地址读写 | BUUCTF — inndy_echo / axb_2019_fmt64 | printf 格式串利用 |
| 7/21-7/22 | 格式化字符串进阶：GOT 覆写、栈地址泄露 | pwnable.tw — dubblesort | .fini_array 劫持 |
| 7/23-7/24 | 整数溢出：sign error / truncation | BUUCTF — babyfengshui / cmcc_simplerop | 有符号/无符号转换漏洞 |
| 7/25 | 格式串 + 整数溢出综合练习 | CTFHub 对应专题 | 限时 3 题 |

#### 第4周（7/26 — 7/31）：堆利用入门

| 日期 | 学习任务 | 练习靶场 | 关键技术 |
|------|---------|---------|---------|
| 7/26-7/27 | 堆基础：chunk 结构、bins 机制、ptmalloc 分配流程 | 阅读 GLIBC 2.23 源码 + 画图 | 能画出 malloc/free 流程 |
| 7/28-7/29 | tcache attack：tcache poisoning / tcache dup | BUUCTF — hitcon2018_children_tcache | tcache 机制、double free |
| 7/30-7/31 | fastbin attack：fastbin dup / fastbin double free | BUUCTF — babyheap_0ctf_2017（简化版） | fastbin 单链表利用 |

### 第二阶段：专项突破（8月1日 — 8月31日，4 周）

> **目标**：掌握堆利用高级技巧，接触内核、浏览器、IoT 等进阶方向，能够解决强网杯中等难度 PWN 题目。

#### 第5周（8/1 — 8/7）：堆利用进阶（一）

| 日期 | 学习任务 | 练习靶场 | 关键技术 |
|------|---------|---------|---------|
| 8/1-8/2 | unsorted bin attack + large bin attack | BUUCTF — hitcontraining_magicheap | unsorted bin 机制 |
| 8/3-8/4 | House of 系列：House of Force / House of Spirit | how2heap 仓库 | 伪造 chunk、top chunk 修改 |
| 8/5-8/6 | House of Orange / House of Einherjar | BUUCTF — houseoforange_hitcon_2016 | _IO_FILE 利用、合并机制 |
| 8/7 | 堆利用专项测试 | CTFHub PWN 堆专题 | 限时 4 题，正确率 ≥ 75% |

#### 第6周（8/8 — 8/14）：堆利用进阶（二）+ GLIBC 版本对抗

| 日期 | 学习任务 | 练习靶场 | 关键技术 |
|------|---------|---------|---------|
| 8/8-8/9 | tcache key 校验绕过（GLIBC 2.31+） | BUUCTF — ciscn_2021 系列 | tcache key 域、safe-linking |
| 8/10-8/11 | GLIBC 2.35 新防护与绕过 | 复现 2023-2024 强网杯真题 | 指针保护、加密链表 |
| 8/12-8/13 | House of Apple / House of Banana | 阅读 CTF-Wiki 对应章节 + 练习 | FSOP、_IO_FILE 高级利用 |
| 8/14 | 堆利用综合测试 | pwnable.tw — 3-4 道 heap 题 | 独立完成，不依赖 Writeup |

#### 第7周（8/15 — 8/21）：内核漏洞利用

| 日期 | 学习任务 | 练习靶场 | 关键技术 |
|------|---------|---------|---------|
| 8/15-8/16 | Linux 内核基础：LKM 模块、ioctl、copy_from_user | 编写简单内核模块 | 内核模块开发基础 |
| 8/17-8/18 | 内核 UAF + 条件竞争 | 搭建 kernel-rop 环境（qemu+busybox） | SLUB/SLAB 分配器、modprobe_path |
| 8/19-8/20 | ret2usr、内核 ROP、KPTI 绕过 | CTF-Wiki 内核 PWN 章节 | SMEP/SMAP/KPTI 绕过 |
| 8/21 | 内核漏洞总结 | 复现 1 道强网杯内核真题 | 独立完成内核 Exploit |

#### 第8周（8/22 — 8/31）：浏览器 + IoT 与综合强化

| 日期 | 学习任务 | 练习靶场 | 关键技术 |
|------|---------|---------|---------|
| 8/22-8/23 | V8 基础：JavaScript 引擎架构、JIT 编译 | 阅读 V8 源码导读 | TurboFan 流水线 |
| 8/24-8/25 | V8 漏洞类型：类型混淆、OOB 访问 | 搭建 V8 调试环境（d8 + GDB） | JIT 漏洞利用 |
| 8/26-8/27 | IoT 固件分析：binwalk / firmware-mod-kit | 分析一个真实路由器固件 | 固件提取、文件系统解包 |
| 8/28-8/29 | ARM/MIPS 汇编与利用 | ARM 架构 ROP 练习 | 多架构 Gadget 搜索 |
| 8/30-8/31 | 第二阶段总结 + 全真模拟 | 从 BUUCTF 选题组卷 | 模拟比赛环境，8 小时连续解题 |

### 第三阶段：实战冲刺（9月1日 — 赛前，约 2-3 周）

> **目标**：真题攻坚、模拟实战、查漏补缺，调整至最佳竞技状态。

#### 第9-10周（9/1 — 赛前）

| 任务 | 具体内容 | 频率 |
|------|---------|:--:|
| 强网杯真题复盘 | 精做 2021-2025 年强网杯 PWN 真题，每题至少写完整 Exploit 和题解笔记 | 每天 1-2 题 |
| 模拟赛 | 每周组织 2 次 4 小时模拟赛，选题覆盖用户态/内核/浏览器等 | 每周 2 次 |
| Writeup 库建设 | 整理所有已做 PWN 题目的解题笔记，按知识点分类归档 | 持续 |
| 专项补漏 | 针对模拟赛中暴露的薄弱环节，集中 2-3 天突击 | 按需 |
| AWDU 对抗模拟 | 使用 AWDU 平台进行 2-3 场攻防对抗模拟（如条件允许） | 至少 2 场 |
| 心态调整 | 赛前 2-3 天减少高强度训练，回顾笔记、整理工具脚本库 | 赛前 2-3 天 |

**第三阶段关键指标**：

- 能够在 2 小时内独立完成一道中等难度 PWN 题
- 真题复现覆盖率 ≥ 10 道
- 工具脚本库完善（模板 exploit、常用 gadget、libc 数据库）
- AWDU 模拟中能完成至少一次完整的攻击-修复-再攻击循环

---

## 四、推荐训练平台与资源

### 4.1 训练平台

| 平台 | 地址 | PWN 题量 | 难度范围 | 推荐指数 |
|------|------|:---:|------|:---:|
| **BUUCTF** | buuoj.cn | 200+ | 入门—困难 | ★★★★★ |
| **CTFHub** | ctfhub.com | 100+ | 入门—中等 | ★★★★☆ |
| **pwnable.tw** | pwnable.tw | 30+ | 中等—困难 | ★★★★★ |
| **pwnable.kr** | pwnable.kr | 40+ | 入门—困难 | ★★★★☆ |
| **攻防世界** | adworld.xctf.org.cn | 150+ | 入门—困难 | ★★★★☆ |
| **CTFtime** | ctftime.org | 历年真题 | 各难度 | ★★★★☆ |
| **NSSCTF** | nssctf.cn | 300+ | 入门—困难 | ★★★★☆ |
| **how2heap** | github.com/shellphish/how2heap | 示例代码 | 教学专用 | ★★★★★ |

### 4.2 核心工具

| 工具 | 用途 | 必备程度 |
|------|------|:---:|
| pwntools | Python 利用开发框架 | 必备 |
| GDB + pwndbg | 动态调试 | 必备 |
| IDA Pro / Ghidra | 静态逆向分析 | 必备 |
| ROPgadget / ropper | ROP Gadget 搜索 | 必备 |
| one_gadget | one-gadget 地址搜索 | 必备 |
| LibcSearcher | libc 版本识别 | 必备 |
| seccomp-tools | 沙箱规则分析 | 推荐 |
| patchelf | ELF 文件 patch（更换 libc/ld） | 推荐 |
| checksec | 安全属性检查 | 必备 |
| QEMU | 多架构模拟 / 内核调试 | 进阶必备 |

### 4.3 在线学习资源

| 资源 | 说明 |
|------|------|
| **CTF-Wiki** (ctf-wiki.org/pwn) | PWN 方向最全面的中文教程，必读 |
| **CTF-All-In-One** | 系列化的 CTF 入门教程 |
| **星盟安全团队 Blog** | 大量强网杯/国赛真题 Writeup |
| **Nu1L 战队 Blog** | 顶级战队的技术分享 |
| **p4nda's blog** | 高质量内核 PWN 教程 |
| **VXRL 实验室** | 浏览器漏洞分析专题 |

---

## 五、推荐书单

| 序号 | 书名 | 作者 | 推荐理由 | 阅读阶段 |
|:---:|------|------|------|:---:|
| 1 | **《CTF竞赛权威指南(PWN篇)》** | 杨超 | CTF PWN 方向最系统的中文教材，覆盖从入门到进阶的完整知识体系，配套大量实战题目 | 第一阶段 |
| 2 | **《深入理解计算机系统（CSAPP）》** | Bryant & O'Hallaron | 构建计算机系统底层认知的基石，第3章（汇编）、第7章（链接）、第9章（虚拟内存）是 PWN 必读 | 第一阶段 |
| 3 | **《0day安全：软件漏洞分析技术（第2版）》** | 王清 | 国内漏洞分析经典教材，系统讲解栈溢出、堆溢出、格式化字符串等核心漏洞 | 第一/二阶段 |
| 4 | **《程序员的自我修养——链接、装载与库》** | 俞甲子等 | 深入理解 ELF 文件格式、动态链接、内存布局，是理解 ret2dlresolve、GOT 覆写等技术的理论基础 | 第一阶段 |
| 5 | **《漏洞战争：软件漏洞分析精要》** | 林桠泉 | 基于真实 CVE 案例的漏洞分析实战，帮助建立从漏洞发现到利用的完整思维链 | 第二阶段 |
| 6 | **《Glibc内存管理：ptmalloc2源代码分析》** | 华庭 | 逐行分析 ptmalloc2 源码，深入理解堆管理机制，是堆利用的"内功心法" | 第二阶段 |
| 7 | **《The Art of Exploitation》** | Jon Erickson | 英文经典，从底层原理到漏洞利用的完整路径，含大量手工 Exploit 示例 | 第一阶段（英文） |
| 8 | **《Linux Kernel Exploitation》** | 内核安全研究相关论文集 | 系统学习内核漏洞利用，涵盖 Heap Spray、UAF、Race Condition 等核心方向 | 第二阶段 |
| 9 | **《The Shellcoder's Handbook》** | Chris Anley 等 | 覆盖多种平台（x86/ARM/MIPS）的漏洞利用技术，多架构利用的参考手册 | 第二阶段 |
| 10 | **《Browser Security Handbook》** | Michal Zalewski | 浏览器安全架构与常见漏洞分析，理解浏览器沙箱、同源策略等核心机制 | 第二阶段 |

> **阅读建议**：前4本为必读，在第一阶段完成；第5-7本在第二阶段精读；第8-10本按实际需要选读。切忌泛泛浏览——每本书的核心章节建议配合题目实操同步进行。

---

## 附录：关键命令速查

```bash
# 环境配置
sudo apt install python3-pip gdb -y
pip3 install pwntools

# 安全属性检查
checksec ./binary

# ROP Gadget 搜索
ROPgadget --binary ./binary --ropchain
ropper -f ./binary --search "pop rdi"

# libc 版本识别
LibcSearcher

# one-gadget
one_gadget /lib/x86_64-linux-gnu/libc.so.6

# 内核调试环境
qemu-system-x86_64 -kernel bzImage -initrd initramfs.cpio.gz -s -S

# ELF patch（更换 libc）
patchelf --set-interpreter ./ld-2.31.so ./binary
patchelf --replace-needed libc.so.6 ./libc-2.31.so ./binary
```

---

> **最后提醒**：PWN 是 CTF 中门槛最高、回报也最高的方向之一。两个月的时间紧凑但足够建立从入门到中级的完整能力。请严格执行每日计划，确保每周目标不拖欠。遇到瓶颈时参考 CTF-Wiki 和 Writeup，但务必先独立思考至少 30 分钟。预祝在第十届强网杯中斩获佳绩！
*（内容由AI生成，仅供参考）*
