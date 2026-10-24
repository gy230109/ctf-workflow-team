# CTF 系统统一接口升级包

这个版本把接题、流程、工具执行、证据和验证状态放在同一个 CTF 系统中。DeepSeek、GPT、Claude 等模型通过适配层使用这套接口；换模型时继续读取同一任务。模型仍负责分析和选择工具，执行过程通过系统完成。

## 在当前电脑安装

1. 解压整个压缩包，退出 DeepSeek Harness，等正在运行的题目操作结束。
2. 双击 `install.cmd`。默认升级 `D:\强网杯大师`，并在当前用户的 Harness desktop 配置中挂载路由插件。
3. 出现 `"ok": true`、`"applied": true` 后，重新打开 Harness，建立新会话，让 AI 调用 `ctf_system_status`，检查协议版本为 `ctf-system/1.1`。

安装器会先校验包内文件和原安装版本，备份本次替换的文件，再检查真实 MCP 入口能否返回新协议。遇到不同版本的源文件会停止，避免覆盖别的升级。运行检查失败会回滚。这个包用于升级已有系统，不包含 Kali、模型、账户或原系统依赖。

目前已完成代码和隔离验证，尚未覆盖本机 D 盘正式安装，也未加载到正在运行的 Harness 会话。以上安装动作由你在本机执行。

## 安装后怎么给 AI 说

> 用 CTF 系统处理这道题。新题先调用 ctf_start；继续已有题就先调用 ctf_progress。实际执行通过系统的 ctf_analyze 或 ctf_call，按返回的 workflow.required_next 继续。失败先读取原始错误并记录恢复决定；不能恢复就报告 blocked。使用当前模型，不额外派另一个模型代替系统接入。

另一个模型接手时，告诉它原来的 `task_id`，让它调用 `ctf_progress`。自动接续依赖两个客户端连接同一套安装和任务目录；两台电脑各自安装不会自动共享本机任务。

## 路由限制的范围

默认 `after_ctf_intake` 模式用于通用 Harness 配置：系统提示要求 CTF 新题首先接题；调用 `ctf_start` 或带任务编号的 `ctf_progress` 后，插件会拒绝该会话后续的原生 Shell、文件执行及其他系统外工具。第一步是否识别为 CTF 仍依赖模型遵循接题提示。

如果某个 Harness profile **只用于 CTF**，可运行下面的命令，从第一步就只允许八个 CTF 操作。`always` 会影响所选 profile 下的所有会话，所以不作为通用 desktop 配置的默认值。

```powershell
python -X utf8 upgrade.py install --apply --target 'D:\强网杯大师' --harness-profile "$env:USERPROFILE\.dsh\profiles\desktop\cordis.patch.yml" --route-mode always
```

换用其他 AI 客户端时，MCP 接口可以复用；客户端自身的工具限制需要对应客户端支持。这个服务端无法禁止其他客户端执行它自己的 Shell。

## 预览、其他安装路径和回滚

仅检查本机升级计划，不修改安装：

```powershell
python -X utf8 upgrade.py install --target 'D:\强网杯大师' --harness-profile "$env:USERPROFILE\.dsh\profiles\desktop\cordis.patch.yml"
```

只升级系统，不修改 Harness 配置：

```powershell
python -X utf8 upgrade.py install --apply --target '你的系统目录'
```

可以先设置 `CTF_PYTHON` 为 Python 3.11 及以上版本的解释器完整路径，再运行批处理。安装器不会更换 Harness 中的模型、账户或权限预设。原 MCP 连接需要已经存在并指向所选系统；新电脑应先安装原系统并配置连接。

成功安装会打印 `journal` 的完整路径，备份位于系统目录 `.local/ctf-upgrades/时间编号/`。退出 Harness 后，把对应的 `journal.json` 拖到 `rollback.cmd` 上即可回滚。回滚会核对当前文件；安装后被手动修改的文件会被保留，并报告冲突。题面、附件、任务、调用记录和 WP 不在回滚范围内。

## 本次修复与验证

- 统一八个公开操作，增加协议版本、接口摘要和服务端流程状态。
- 新题先分流；失败必须引用对应记录说明恢复决定；旧任务已有错误也会保留。
- 同一 `request_id` 重试返回原执行记录；结果不确定的动作不会自动重跑。
- 增加 MCP、OpenAI/DeepSeek 和 Anthropic 工具调用格式适配，保留原始错误及结构化结果。
- 增加 Harness 工具路由插件，限制接题后的执行路径。
- 修复 pwn 依赖输出混入 JSON 导致的解析失败，诊断信息保留在 stderr；未解除 Unicorn 的内存限制。
- 安装、重复安装、文件冲突、失败回滚、回滚冲突以及任务数据保留均有测试。

验证结果见 `verification/`。验证使用了真实本机 CTF 入口、109 项工具目录、实际算术、WP 记录和已安装 Harness 的 ToolRuntime；跨模型部分使用供应商工具调用格式，没有调用真实模型 API，也没有据此声称比赛题已解出。

开发接入和状态字段详见 `docs/UNIFIED_INTERFACE.md`。
