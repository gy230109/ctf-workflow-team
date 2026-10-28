# 发布与更新 Release（GitHub）

本仓库的发布物在 `release/`：

```
release/ctf-purge-fusion-<版本>.zip
release/ctf-purge-fusion-<版本>.tar.gz
release/SHA256SUMS-dist.txt
release/RELEASE-NOTES-<版本>.md      ← Release 正文的唯一来源
release/publish-notes.ps1            ← 用 UTF-8 更新/创建 Release 正文并回读比对
```

## 一、发新版（三步）

```bash
# 1. 打包（改 VERSION 后重跑，产物落 release/）
python ../build-fusion-package.py            # 维护者本地构建脚本

# 2. 提交
git add -A && git commit -m "release: ctf-purge-fusion <版本>" && git push origin main

# 3. 建 Release 并上传附件（网页或用 API；正文用脚本写，见下）
```

网页发 Release 时，正文直接从 `release/RELEASE-NOTES-<版本>.md` 复制粘贴即可（文件本身是 UTF-8）。
更稳的做法是用脚本创建/更新，避免手抖或编码问题。

## 二、更新已有 Release 的正文（UTF-8，带回读比对）

Release 正文曾因 PowerShell `Invoke-RestMethod` 默认编码把中文写成 `?`。用同目录脚本改，别手点网页：

```powershell
$env:GITHUB_TOKEN = 'ghp_xxx'                 # 或用 GH_TOKEN；不接受命令行明文令牌
.\release\publish-notes.ps1 -Tag v1.0.1
.\release\publish-notes.ps1 -Tag v1.0.1 -DryRun
.\release\publish-notes.ps1 -Tag v1.0.1 -Notes .\release\RELEASE-NOTES-1.0.1.md
.\release\publish-notes.ps1 -Tag v1.0.1 -Repo gy230109/ctf-workflow-team   # 不在仓库目录时
```

脚本行为：

1. 从 `release/RELEASE-NOTES-<tag 去掉 v>.md` 读正文（显式 UTF-8，CRLF 归一成 LF）；
2. 用 **UTF-8 字节** + `Content-Type: application/json; charset=utf-8` 写入（Release 存在则 PATCH，不存在则 POST 创建，tag 指向 `main`）；
3. 写完 **GET 回读**，与本地 Markdown 规范化后逐字比对，打印 `chars / cjk / question_marks / match`；
4. 不一致时打印首个差异位置与两侧片段，并以非零退出。

退出码：

| 码 | 含义 |
|---|---|
| 0 | 成功且回读一致 |
| 2 | 缺令牌（`GITHUB_TOKEN` / `GH_TOKEN`） |
| 3 | 找不到正文 Markdown |
| 4 | 仓库解析失败（`git` 不在 PATH 且未找到常见安装路径，或 remote 不是 GitHub） |
| 5 | 回读正文与本地不一致 |

## 三、校验下载件

```powershell
Get-FileHash .\ctf-purge-fusion-1.0.1.zip -Algorithm SHA256   # 与 SHA256SUMS-dist.txt 对照
```

```bash
sha256sum -c SHA256SUMS-dist.txt
```
