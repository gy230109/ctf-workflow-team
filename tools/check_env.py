#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Windows 侧一键自检（环境/依赖清单.md §四 TODO 的落地实现）。

检查项（与清单 §1.1/§1.2 对应）：
- 双解释器可用性：3.13.12（z3 所在）与隔离 venv（dnfile+pefile 所在）
- z3 / dnfile / pefile 真实可导入（子进程实测，不是看目录）
- openssl 在 PATH
- Git Bash 基础工具（ls/grep/file…）是否需要 PATH 修补
- Obsidian 库路径可读、同步目标可写（写入探针：创建并删除一个唯一命名临时文件）
- 已知坑位提示（坏 scp、Bash 调 PowerShell 被拦）——只提示，不测

只用标准库；每项检查永不抛异常（对齐 tools/kali_envcheck.py 的风格）。
结论存 环境/check_env.json，stdout 打"缺失清单"。

    python tools/check_env.py            # 直接跑
    import check_env; check_env.run()    # 被 ctf_envprep.py 转调
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
ENV_DIR = BASE / "环境"
CONFIG = BASE / "config" / "envprep.local.json"


def load_cfg():
    cfg = {}
    try:
        cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
    except Exception:
        pass
    home = Path(os.environ.get("USERPROFILE", ""))
    return {
        "python_313": cfg.get("python_313",
                              sys.executable),
        "python_venv": cfg.get("python_venv",
                               sys.executable),
        "obsidian_vault": cfg.get("obsidian_vault", str(home / "Documents" / "Obsidian Vault")),
        "obsidian_sync_target": cfg.get(
            "obsidian_sync_target",
            str(home / "Documents" / "Obsidian Vault" / "02_个人项目" / "强网杯备战" / "强网杯大师")),
    }


def sh(argv, timeout=60):
    """跑一条命令，永不抛异常；返回 (ok, 输出摘要)。"""
    try:
        r = subprocess.run(argv, capture_output=True, timeout=timeout,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        out = ((r.stdout or b"") + (r.stderr or b"")).decode("utf-8", "replace").strip()
        return r.returncode == 0, out[-400:]
    except Exception as exc:                                   # noqa: BLE001
        return False, "<<error: %s>>" % exc


def _item(name, ok, detail, fix=""):
    return {"name": name, "ok": bool(ok), "detail": detail, **({"fix": fix} if fix else {})}


def run(write_probe=True):
    cfg = load_cfg()
    items = []

    # ---- 1 双解释器 ----
    for key, label in (("python_313", "python-3.13.12（z3 所在）"),
                       ("python_venv", "python-venv（dnfile/pefile 所在）")):
        p = cfg[key]
        ok = Path(p).is_file()
        items.append(_item(label, ok, p if ok else "解释器不存在: %s" % p,
                           fix="" if ok else "检查 .workbuddy 托管解释器是否被移动/升级"))

    # ---- 2 z3 / dnfile / pefile 实测导入 ----
    ok, out = sh([cfg["python_313"], "-c", "import z3;print(z3.get_version_string())"])
    items.append(_item("z3（3.13.12 解释器）", ok and "." in out, out or "导入失败",
                       fix="在 3.13.12 解释器里安装 z3（依赖清单 §1.1 记录 5.1.0）"))
    ok, out = sh([cfg["python_venv"], "-c", "import dnfile,pefile;print('ok')"])
    items.append(_item("dnfile + pefile（隔离 venv）", ok, out or "导入失败",
                       fix="" if ok else "在隔离 venv 里 pip install dnfile pefile"))

    # ---- 3 openssl ----
    openssl = shutil.which("openssl")
    ok, out = sh(["openssl", "version"]) if openssl else (False, "PATH 中无 openssl")
    items.append(_item("openssl", ok, out or (openssl or "未找到"),
                       fix="确认 Git Bash / System32 的 openssl 在 PATH"))

    # ---- 4 Git Bash 基础工具（PATH 修补探测）----
    bash = shutil.which("bash")
    if bash:
        ok, out = sh([bash, "-c", "command -v ls >/dev/null 2>&1 && command -v grep >/dev/null 2>&1 && echo TOOLS_OK"])
        need_patch = not (ok and "TOOLS_OK" in out)
        items.append(_item(
            "Git Bash 基础工具（ls/grep…）", not need_patch,
            "需要 PATH 修补" if need_patch else "裸 PATH 下可用",
            fix="每条命令前加 export PATH=\"/usr/bin:/bin:/c/Windows/System32:$PATH\";" if need_patch else ""))
    else:
        items.append(_item("Git Bash", False, "PATH 中无 bash",
                           fix="确认 WorkBuddy PortableGit 是否在 PATH"))

    # ---- 5 Obsidian 库可读 / 同步目标可写 ----
    vault = Path(cfg["obsidian_vault"])
    target = Path(cfg["obsidian_sync_target"])
    items.append(_item("Obsidian 库路径可读", vault.is_dir(), str(vault),
                       fix="确认库路径（依赖清单 §二）" if not vault.is_dir() else ""))
    if target.is_dir():
        probe = target / ("check_env_write_probe_%d.tmp" % os.getpid())
        wok, wdetail = True, str(target)
        try:
            probe.write_bytes(b"")
            probe.unlink()
        except Exception as exc:                               # noqa: BLE001
            wok, wdetail = False, "写入探针失败: %r" % (exc,)
        items.append(_item("Obsidian 同步目标可写", wok, wdetail,
                           fix="检查目录权限或库是否被占用" if not wok else ""))
    else:
        items.append(_item("Obsidian 同步目标可写", False, "目录不存在: %s" % target,
                           fix="先在库里建 02_个人项目/强网杯备战/强网杯大师 目录"))

    # ---- 6 已知坑位（静态提示，不计入缺失）----
    notes = [
        "System32 的 scp.exe/sftp.exe 是坏的（pipe: Unknown error）——传文件走 Kali 桥接，不要手写 scp",
        "Bash 里调 powershell 会被安全策略拦——桥接命令用 PowerShell 工具执行",
        "Windows Python 的 /tmp 与 Git Bash 的 /tmp 不是同一目录——一律用绝对路径",
    ]

    missing = [x for x in items if not x["ok"]]
    result = {
        "checked_at": __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "config_used": CONFIG.name if CONFIG.is_file() else "(默认值，config/envprep.local.json 不存在)",
        "items": items, "notes": notes,
        "missing_count": len(missing), "missing": [x["name"] for x in missing],
        "all_ok": not missing,
    }

    # ---- 落盘 ----
    try:
        ENV_DIR.mkdir(parents=True, exist_ok=True)
        out_path = ENV_DIR / "check_env.json"
        out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        result["report_json"] = str(out_path)
    except Exception as exc:                                   # noqa: BLE001
        result["report_json_error"] = repr(exc)
    return result


def main():
    r = run()
    print(json.dumps(r, ensure_ascii=False, indent=2))
    if r["missing"]:
        print("\n缺失清单：")
        for name in r["missing"]:
            print("  - %s" % name)
    else:
        print("\n全部通过，无缺失项。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
