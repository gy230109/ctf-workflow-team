# ctf-purge-fusion 1.1.1

构建标签：2026.10.30-wpboost1.1（完整文件清单与哈希见仓库内 bundle-manifest.json）

本版为 1.1.0 的增量修复，仅涉及专业分工 worker 的依赖诊断与 stdout 协议纯净性。

## 修复内容

- 依赖诊断输出重定向：新增 cli() 入口，在导入依赖前用 contextlib.redirect_stdout(sys.stderr) 接管 stdout，第三方库在导入期打印的告警落在 stderr，stdout 只输出一个 JSON 结果。此前部分依赖的导入期日志会污染 stdout，导致调用方按 JSON 解析失败。
- 精确依赖导入：pwn_elf 改用 pwnlib.elf.elf.ELF，pwn_cyclic 改用 pwnlib.util.cyclic.cyclic，不再经 pwn 顶层包，避免 pull 入整套 pwntools 初始化。
- 异常仍按原口径区分 dependency_missing（ImportError）与 operation_failed，退出码保持 0/1。

## 验证

- 专项自测 23 项通过；WP 回归 59 项通过（4 项可选检查跳过）；专业分工 14 项通过。
- 与 1.1.0 相比，仅 tools/ctf_specialist_worker.py 与 bundle-manifest.json 变更。

## 升级方式

- 已有 Git 安装：git pull --ff-only 更新代码后重连 MCP。
- 校验下载件：对照 SHA256SUMS-dist.txt（Get-FileHash / sha256sum -c）。
