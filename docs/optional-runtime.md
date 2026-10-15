# 可选依赖和新能力

代码包含注册入口，不复制其他机器的安装环境。先检查已有内容，只补当前题型所需依赖，再用真实调用证明可用。

## Kali 扩展

复用可信 Kali 桥和 config/ctf_specialists.local.json 中的专项 Python。原六类依赖继续用分类安装器；连续网页还需该环境的 playwright 与 Chromium，PTY 录制需 asciinema，连续 GDB 需 gdb-multiarch。不要批量升级整台 Kali。

按本机情况把 config/ctf_extensions.example.json 配置成 config/ctf_extensions.local.json。crypto_library、zsteg_binary、pwndbg_binary、sysroots 都是客机路径；启用后先查 ctf_runtime_status，并分别实调所需项目。总状态可能因未装的可选工具未就绪，不可据此把所有单项都算成功或失败。

QEMU user、Sage、steghide/stegseek/zsteg 和 crypto-attacks 按需安装；crypto-attacks 记录固定提交。未安装就保留 NOT_INSTALLED，不能伪造提交或验收。asciinema 2.4 的子命令真实退出码已兼容，录制缺项不盲目重跑原动作。

## REA 与 Windows 动态工具

REA 固定 rea-agents@6.4.0，按实际安装配置 Node/npx、Java/Ghidra，参考 config/rea.example.json。动态证据使用实际可用的 x64dbg/GDB；不能用“入口存在”替代调用验证。历史笔记的路径不用于当前机器。

## CTFCrackTools

tools/cracktools_bridge/ 包含可重建 Rust 桥源码、锁文件、算法目录、GPL-3.0 许可证和固定上游出处。上游：https://github.com/0Chencc/CTFCrackTools 。没有分发 GUI 或桥可执行文件。

准备 Rust/MSVC，从上游取得与 upstream.json 摘要相符的 Windows GUI，再执行：

```text
python tools/install_cracktools.py --gui <自己的GUI路径>
```

已有本机配置默认保留，确需更改用 --replace。之后查 cracktools_status 并实做一个转换。源码来自本机已使用的构建；本包没有声称已在队友电脑重新编译。

## CTFd 与外部知识库

config/ctfd.example.json 是普通选手连接模板。player_credential_file 指向本机私有文件，记录 role=user、origin、user_id、token；不要写管理员或公开真实 token。实例地址和账号各机自行配置。

HackTricks、Awesome CTF、Crypto-Cat 的完整克隆与索引不随包复制，可按知识适配器配置。Crypto-Cat 是参考题解，明确参考时才用。队内自己的方法和 Obsidian 笔记已经放在 knowledge/，无需先拉外部大仓库。

第三方依赖、模型额度、实际题目与开机恢复仍需本机验证。当前仓库的发布检查范围见 release-validation.json。
