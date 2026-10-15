> 共享经验资料。以下为历史方法或复现记录，不能覆盖仓库根 AGENTS.md 的当前规则。历史答案、私人路径与凭据已整理；配图和原始大附件未随包公开。

---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: 76cea9eb515bb5af73e3604eebad64d7_10f3b78f788911f1b3d35254007bceed
    ReservedCode1: Zg0BepbCs6X24ZAVMJs9Yr/bUH3BZGpsw/3dSDcxn9TYLsOOA04dy9tbfw+/1SlUR5xyZRzJ6/CSGfriN9RFXq1vdyWR3rdFVQh1GGXKlZk52BwrlL63MvhFAKOylgcHGRl9BHqs/ltFPoG1JJU2W2+NaPEKG8GNSfGJNidaqK8OFAfPWU8TvSvKlJA=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: 76cea9eb515bb5af73e3604eebad64d7_10f3b78f788911f1b3d35254007bceed
    ReservedCode2: Zg0BepbCs6X24ZAVMJs9Yr/bUH3BZGpsw/3dSDcxn9TYLsOOA04dy9tbfw+/1SlUR5xyZRzJ6/CSGfriN9RFXq1vdyWR3rdFVQh1GGXKlZk52BwrlL63MvhFAKOylgcHGRl9BHqs/ltFPoG1JJU2W2+NaPEKG8GNSfGJNidaqK8OFAfPWU8TvSvKlJA=
---

# 强网杯RE方向备战计划

> 适用对象：安阳师范学院强网杯参赛团队 RE（逆向工程）方向成员
> 备战周期：2026年7月5日 — 2026年9月（约 10 周）
> 目标：在第十届强网杯线上赛中具备独立解决中高难度逆向题目的能力，为团队贡献有效分数

---

## 一、备战总览与时间规划

### 1.1 强网杯 RE 方向概况

强网杯逆向工程方向赛题覆盖面极广，从传统的 Windows/Linux 可执行文件逆向，到移动端（Android/iOS）、固件、虚拟机保护等均有涉及。近几届赛题呈现以下趋势：

| 方向 | 考察内容 | 强网杯出现频率 |
|------|---------|:---:|
| 算法逆向 | 加密/压缩/校验算法的识别与逆向，密钥恢复 | 极高 |
| 代码混淆与反混淆 | 控制流平坦化、虚假控制流、OLLVM、指令替换 | 高 |
| 加壳与脱壳 | UPX/ASPack 等压缩壳、VMProtect/Themida 等保护壳 | 中高 |
| 虚拟机保护 (VMP) | 自定义 VM 字节码分析、Handler 还原、字节码逆向 | 高 |
| 移动端逆向 | Android APK（Java/SO层）、iOS IPA | 中 |
| 固件/嵌入式逆向 | ARM/MIPS 架构固件分析 | 中 |
| 游戏逆向 | Unity/IL2CPP、网络协议逆向 | 中 |

强网杯 RE 题目的典型特征：**考点复合化**——一道题往往同时涉及反混淆 + 算法逆向 + VM 分析，对选手的综合能力要求极高。

### 1.2 时间总览（2026年7月—9月）

| 阶段 | 时间 | 周期 | 核心目标 | 每日投入建议 |
|------|------|:---:|------|:---:|
| 第一阶段：基础夯实 | 7月5日 — 7月31日 | 4 周 | 建立逆向工程完整知识体系，熟练使用核心工具链 | 4-6 小时 |
| 第二阶段：专项突破 | 8月1日 — 8月31日 | 4 周 | 攻克混淆/VM/移动端等强网杯高频难点 | 6-8 小时 |
| 第三阶段：实战冲刺 | 9月1日 — 赛前 | 2-3 周 | 真题攻坚、模拟赛实战、查漏补缺 | 8-10 小时 |

---

## 二、RE 方向核心知识体系

### 2.1 知识全景图

```
RE 核心知识体系
├── 1. 基础理论
│   ├── 汇编语言：x86/x86_64 / ARM / MIPS
│   ├── PE/ELF/Mach-O 文件格式
│   ├── 编译原理：编译器优化、内联、去虚拟化
│   ├── 操作系统原理：进程内存布局、动态链接
│   └── 密码学基础：对称/非对称加密、哈希、编码
├── 2. 静态分析工具链
│   ├── IDA Pro：反汇编/反编译、脚本开发（IDAPython）
│   ├── Ghidra：NSA 开源逆向工具、支持多架构
│   ├── Binary Ninja：现代化逆向平台
│   ├── radare2 / rizin：命令行逆向工具
│   └── 反编译引擎：Hex-Rays / Ghidra Decompiler
├── 3. 动态分析工具链
│   ├── x64dbg / OllyDbg：Windows 平台调试
│   ├── GDB + pwndbg：Linux 平台调试
│   ├── Frida：跨平台动态插桩框架
│   ├── Unicorn Engine：CPU 模拟器
│   └── strace / ltrace：系统调用/库函数追踪
├── 4. 代码混淆与反混淆
│   ├── OLLVM 混淆框架：控制流平坦化/虚假控制流/指令替换
│   ├── 反混淆技术：符号执行、D810 插件、模式匹配
│   └── 去平坦化：angr / Miasm 脚本化还原
├── 5. 加壳与脱壳
│   ├── 压缩壳：UPX / ASPack / FSG
│   ├── 保护壳：VMProtect / Themida / Safengine
│   └── 脱壳技术：ESP 定律、内存 dump、ScyllaHide
├── 6. 虚拟机保护 (VMP) 分析
│   ├── VM 架构识别：Handler 分发器、VM Context
│   ├── Handler 语义还原：加/减/异或/移位等逻辑操作
│   └── VM 字节码逆向：将自定义字节码翻译回高级逻辑
├── 7. 移动端逆向
│   ├── Android：APK 解包、Dalvik/ART 字节码、Native SO 分析
│   ├── iOS：IPA 解包、Mach-O 分析、Objective-C/Swift
│   └── 框架：jadx / apktool / objection / Hopper
└── 8. 固件分析
    ├── 固件提取：SPI Flash / UART / JTAG
    └── 文件系统分析：binwalk / firmware-mod-kit / FACT
```

### 2.2 强网杯历年 RE 赛题特征

| 年份 | RE 题目特征 | 关键技术点 |
|------|-------------|-----------|
| 2024 第八届 | 多架构混合、VMP 保护增多 | ARM64 + OLLVM 混合、自写 VM |
| 2023 第七届 | 算法逆向为主，Android RE 出现 | AES/RC4 变种算法识别、Unity IL2CPP |
| 2022 第六届 | VMP 与混淆题量大，难度较高 | 自写 VM 模拟器、符号执行自动化 |
| 2021 第五届 | 传统逆向 + WannaCry 风格勒索软件分析 | 流量分析 + 逆向结合 |

> 趋势判断：强网杯 RE 方向正从"静态分析单一二进制"向"动态插桩 + 自动化分析 + 多架构协同"演进。VMP 保护、OLLVM 混淆、移动端逆向已成为稳定考点。第十届预期会延续这一趋势，并可能在 WASM/区块链智能合约逆向等新兴方向出题。

---

## 三、阶段学习路线图

### 第一阶段：基础夯实（7月5日 — 7月31日，4 周）

> **目标**：建立完整的逆向分析能力，熟练使用 IDA/Ghidra/x64dbg/GDB 等核心工具，能够独立完成中等难度逆向题目。

#### 第1周（7/5 — 7/11）：环境搭建与汇编强化

| 日期 | 学习任务 | 练习内容 | 验收标准 |
|------|---------|---------|---------|
| 7/5-7/6 | 环境搭建：IDA Pro 7.7+ / Ghidra / x64dbg / GDB+peda | 配置 IDAPython 环境、安装常用插件 | 所有工具可正常运行 |
| 7/7-7/8 | x86_64 汇编深度复习：调用约定、SIMD 指令 | 手写汇编代码并用工具反向分析 | 能准确还原反汇编为伪代码 |
| 7/9-7/10 | ARM 汇编入门 + MIPS 汇编入门 | 编译简单 C 程序到 ARM/MIPS 并分析 | 能看懂基本 ARM/MIPS 汇编 |
| 7/11 | 工具实战：静态分析 3 个 CrackMe | BUUCTF — reverse 入门题 | 2 小时内独立完成 3 题 |

#### 第2周（7/12 — 7/18）：静态分析深度训练

| 日期 | 学习任务 | 练习靶场 | 关键技术 |
|------|---------|---------|---------|
| 7/12-7/13 | IDA Pro 进阶：FLIRT 签名、类型恢复、结构体定义 | BUUCTF — simpleRev / Java逆向解密 | 函数签名库、结构体逆向 |
| 7/14-7/15 | Ghidra 深度使用：脚本开发、交叉引用分析 | 攻防世界 — RE 进阶题 | Ghidra Script（Java/Python） |
| 7/16-7/17 | ELF/PE 文件格式深入分析 | 用 010 Editor 手工解析 ELF/PE 结构 | 能手工定位 Section/Import 表 |
| 7/18 | 静态分析专题测试 | CTFHub — RE 入门+进阶 | 限时 5 题，正确率 ≥ 80% |

#### 第3周（7/19 — 7/25）：动态分析与算法逆向

| 日期 | 学习任务 | 练习靶场 | 关键技术 |
|------|---------|---------|---------|
| 7/19-7/20 | 动态调试：GDB 条件断点、内存监视、trace | BUUCTF — re1 / game | 调试技巧、寄存器监控 |
| 7/21-7/22 | x64dbg 实战：补丁、内存修改、ScyllaHide | 攻防世界 Windows RE 题 | 反反调试、进程注入 |
| 7/23-7/24 | 算法逆向（一）：常见加密算法识别 | BUUCTF — CrackRTF / findKey | MD5/AES/DES/RC4 特征识别 |
| 7/25 | 算法逆向（二）：自写算法还原 | BUUCTF — 相册 / 刮开有奖 | 自定义编码/加密还原 |

#### 第4周（7/26 — 7/31）：Python 逆向与自动化

| 日期 | 学习任务 | 练习靶场 | 关键技术 |
|------|---------|---------|---------|
| 7/26-7/27 | Python 逆向：pyc 反编译、PyInstaller 解包 | BUUCTF — pyre / 简单注册器 | uncompyle6、pyinstxtractor |
| 7/28-7/29 | angr 符号执行入门 | angr 官方示例 + BUUCTF | 自动路径探索、约束求解 |
| 7/30-7/31 | 第一阶段总结 + 综合测试 | 从 BUUCTF 选题组卷 | 6 小时模拟测试，≥ 6/10 题 |

### 第二阶段：专项突破（8月1日 — 8月31日，4 周）

> **目标**：攻克 OLLVM 反混淆、VMP 虚拟机分析、移动端逆向三大高难度领域，具备解决强网杯中高难度 RE 题目的能力。

#### 第5周（8/1 — 8/7）：反混淆技术（一）

| 日期 | 学习任务 | 练习靶场 | 关键技术 |
|------|---------|---------|---------|
| 8/1-8/2 | OLLVM 混淆原理：控制流平坦化、虚假控制流 | 自己编译 OLLVM 样本并分析 | 理解 OLLVM Pass 的工作机制 |
| 8/3-8/4 | IDA 反混淆插件：D810、HexRaysPyTools | 攻防世界 OLLVM 专题 | 自动模式匹配去混淆 |
| 8/5-8/6 | angr 脚本化反混淆：去平坦化 | 手写 angr 脚本恢复控制流 | 符号执行还原真实控制流 |
| 8/7 | 反混淆综合训练 | BUUCTF — OLLVM 相关题目 | 独立完成 3 道 OLLVM 题 |

#### 第6周（8/8 — 8/14）：反混淆技术（二）+ 加壳脱壳

| 日期 | 学习任务 | 练习靶场 | 关键技术 |
|------|---------|---------|---------|
| 8/8-8/9 | 指令替换 + 字符串混淆还原 | 复现强网杯 2022-2024 RE 混淆题 | Miasm 中间表示分析 |
| 8/10-8/11 | 压缩壳检测与脱壳：UPX / ASPack | 手动脱壳 + 工具脱壳 | ESP 定律、内存 dump、IAT 修复 |
| 8/12-8/13 | 保护壳分析：VMProtect 入门 | 分析 VMP 保护样本的入口特征 | VMP 段定位、反调试绕过 |
| 8/14 | 脱壳专题总结 | 攻防世界 Windows RE 脱壳题 | 独立脱 5 种不同壳 |

#### 第7周（8/15 — 8/21）：虚拟机保护 (VMP) 深度分析

| 日期 | 学习任务 | 练习靶场 | 关键技术 |
|------|---------|---------|---------|
| 8/15-8/16 | VM 架构分析：Handler 分发器定位 | 复现 CTF 中的简单 VM 题 | VM 入口/出口、Handler 表定位 |
| 8/17-8/18 | Handler 语义还原：逐条分析 VM 指令 | 手工逆向 Handler 逻辑 | 加减乘除/异或/移位等操作识别 |
| 8/19-8/20 | VM 字节码翻译：写模拟器执行 | 编写 Python 脚本模拟 VM | 将 VM 字节码还原为可读逻辑 |
| 8/21 | VMP 专题总结 | BUUCTF VM 保护专题 | 独立完成 2-3 道 VM 题 |

#### 第8周（8/22 — 8/31）：移动端逆向与综合强化

| 日期 | 学习任务 | 练习靶场 | 关键技术 |
|------|---------|---------|---------|
| 8/22-8/23 | Android 逆向基础：APK 结构、Smali 语法 | jadx + apktool 分析 APK | Dalvik 字节码、AndroidManifest |
| 8/24-8/25 | Android Native SO 逆向 + Frida 动态插桩 | 攻防世界 Android 题 | JNI 函数 Hook、native 层分析 |
| 8/26-8/27 | iOS 逆向基础（可选）：Mach-O 分析 | Hopper / lldb 调试 | Objective-C 消息分发 |
| 8/28-8/29 | 固件逆向：binwalk 提取 + 架构识别 | 分析一个 ARM 路由器固件 | 固件文件系统、启动脚本分析 |
| 8/30-8/31 | 第二阶段总结 + 全真模拟 | 选题覆盖混淆/VM/移动端/固件 | 8 小时连续解题，难度对标强网杯 |

### 第三阶段：实战冲刺（9月1日 — 赛前，约 2-3 周）

> **目标**：真题攻坚、模拟实战、查漏补缺，调整至最佳竞技状态。

#### 第9-10周（9/1 — 赛前）

| 任务 | 具体内容 | 频率 |
|------|---------|:--:|
| 强网杯真题复盘 | 精做 2021-2025 年强网杯 RE 真题，每题写完整分析笔记（含反混淆过程） | 每天 1-2 题 |
| 模拟赛 | 每周组织 2 次 4 小时 RE 专项模拟赛，选题覆盖 VMP/混淆/移动端/算法 | 每周 2 次 |
| Writeup 库建设 | 按算法类型/保护方式/平台分类整理所有 RE 题目笔记 | 持续 |
| IDAPython 工具库 | 整理常用 IDAPython 脚本：去混淆/特征搜索/自动化分析模板 | 持续 |
| 专项补漏 | 针对模拟赛中暴露的薄弱环节集中突击 | 按需 |
| 心态调整 | 赛前 2-3 天回顾笔记、整理常用脚本工具包 | 赛前 2-3 天 |

**第三阶段关键指标**：

- 能够在 3 小时内独立完成一道含 OLLVM 混淆的中等难度 RE 题
- 真题复现覆盖率 ≥ 8 道
- IDAPython / angr 脚本库完善
- 对 VMP/移动端/固件等高频考点有成熟分析流程

---

## 四、推荐训练平台与资源

### 4.1 训练平台

| 平台 | 地址 | RE 题量 | 难度范围 | 推荐指数 |
|------|------|:---:|------|:---:|
| **BUUCTF** | buuoj.cn | 200+ | 入门—困难 | ★★★★★ |
| **攻防世界** | adworld.xctf.org.cn | 150+ | 入门—困难 | ★★★★★ |
| **CTFHub** | ctfhub.com | 80+ | 入门—中等 | ★★★★☆ |
| **NSSCTF** | nssctf.cn | 200+ | 入门—困难 | ★★★★☆ |
| **Crackmes.one** | crackmes.one | 海量 | 入门—困难 | ★★★★☆ |
| **CTFtime** | ctftime.org | 历年真题 | 各难度 | ★★★★☆ |
| **看雪论坛** | bbs.pediy.com | 逆向专题 | 进阶 | ★★★★☆ |
| **Root-Me** | root-me.org | 100+ | 入门—困难 | ★★★★☆ |

### 4.2 核心工具

| 工具 | 用途 | 必备程度 |
|------|------|:---:|
| IDA Pro + Hex-Rays | 静态反汇编/反编译 | 必备 |
| Ghidra | 开源逆向平台，多架构支持 | 必备 |
| x64dbg | Windows 平台动态调试 | 必备 |
| GDB + pwndbg/peda | Linux 平台动态调试 | 必备 |
| Frida | 跨平台动态插桩 | 必备 |
| angr | 符号执行框架 | 必备 |
| jadx | Android APK 反编译 | 必备 |
| apktool | Android APK 解包/重打包 | 推荐 |
| Unicorn Engine | CPU 模拟器，VMP 分析利器 | 推荐 |
| D810 | IDA 反混淆插件 | 推荐 |
| binwalk | 固件分析 | 推荐 |
| Detect It Easy (DIE) | 查壳/编译器识别 | 必备 |

### 4.3 在线学习资源

| 资源 | 说明 |
|------|------|
| **CTF-Wiki** (ctf-wiki.org/reverse) | RE 方向最全面的中文教程 |
| **RE for Beginners** (beginners.re) | Dennis Yurichev 的经典逆向入门书 |
| **Corkami PE/ELF 海报** | 文件格式可视化速查 |
| **0xinfection ARM/MIPS 教程** | 多架构汇编入门 |
| **OALabs** (YouTube) | 恶意软件分析实战视频 |
| **星盟安全团队 Blog** | 强网杯真题 Writeup |

---

## 五、推荐书单

| 序号 | 书名 | 作者 | 推荐理由 | 阅读阶段 |
|:---:|------|------|------|:---:|
| 1 | **《加密与解密（第4版）》** | 段钢 | 国内逆向工程领域圣经级教材，覆盖 PE 格式、调试、脱壳、反混淆、算法逆向等全领域 | 第一阶段 |
| 2 | **《IDA Pro权威指南（第2版）》** | Chris Eagle | IDA Pro 使用方法的权威参考，含 IDAPython 脚本开发、插件编写等深度内容 | 第一阶段 |
| 3 | **《逆向工程核心原理》** | 李承远 | 系统讲解 Windows 平台逆向方法论，含 PE 格式、DLL 注入、API Hooking 等实战内容 | 第一阶段 |
| 4 | **《恶意代码分析实战》** | Sikorski & Honig | 动态/静态分析方法的完整训练体系，含大量动手实验，分析方法论同样适用于 CTF RE | 第一阶段 |
| 5 | **《x86/x64体系探索及编程》** | 邓志 | x86/x64 指令集与体系结构的完整参考，对理解编译器优化和 SIMD 指令至关重要 | 第一/二阶段 |
| 6 | **《Practical Binary Analysis》** | Dennis Andriesse | 二进制分析的全景式教材，含反汇编原理、符号执行、污点分析、动态插桩等进阶技巧 | 第二阶段 |
| 7 | **《Android软件安全与逆向分析》** | 丰生强（非虫） | Android 平台逆向的权威中文书，覆盖 Smali/ARM SO/Frida Hook 等完整内容 | 第二阶段 |
| 8 | **《Obfuscation and Anti-Reversing》** | 学术论文集 + CTF Writeup | 系统学习代码混淆技术，理解 OLLVM/Tigress 等混淆器的原理与绕过方法 | 第二阶段 |
| 9 | **《The IDA Pro Book》** | Chris Eagle | 同第2本（英文原版），内容更完整，适合深入阅读 | 第二阶段 |
| 10 | **《iOS应用逆向与安全》** | 相关技术博客合集 | iOS 逆向入门，覆盖 Mach-O 结构、Cycript、Theos 等工具 | 第二阶段（选读） |

> **阅读建议**：前4本为第一阶段必读，配合题目实操同步推进；第5-8本在第二阶段专项突破时精读对应章节；第9-10本按需选读。逆向工程是"做中学"的学科，每读完一章务必搭配 3-5 道题目实践。

---

## 附录：关键命令速查

```bash
# ===== IDA 常用操作 =====
# 导出函数列表
idapython -c "import idautils; [print(hex(ea), idc.get_func_name(ea)) for ea in idautils.Functions()]"

# ===== Ghidra 启动（无 GUI 模式） =====
./analyzeHeadless <project_dir> <project_name> -import <binary> -postScript <script.py>

# ===== Android 逆向工具链 =====
# APK 解包
apktool d target.apk -o output_dir
# 反编译为 Java
jadx -d output_dir target.apk

# ===== Frida 动态插桩 =====
# 附加进程
frida -U -l script.js com.example.app
# Hook 函数
frida-trace -U -i "open" com.example.app

# ===== angr 符号执行 =====
python3 -c "
import angr
proj = angr.Project('./binary')
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x401000, avoid=0x401200)
print(simgr.found[0].posix.dumps(0))
"

# ===== 固件分析 =====
# 固件提取
binwalk -Me firmware.bin
# 获取文件系统结构
binwalk -e firmware.bin

# ===== 编译 OLLVM 混淆样本 =====
clang -mllvm -fla -mllvm -bcf -mllvm -sub target.c -o target_obfuscated

# ===== DIE 查壳 =====
diec.exe -r target.exe
```

---

> **最后提醒**：逆向工程是 CTF 中对耐心和细致度要求最高的方向。遇到复杂混淆不要气馁——先静态分析确定整体逻辑，再用动态调试跟踪关键路径，最后用脚本自动化重复性分析。两个月内积累 80+ 道题目的经验是可行目标。预祝在第十届强网杯中斩获佳绩！
*（内容由AI生成，仅供参考）*
