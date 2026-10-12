# -*- coding: utf-8 -*-
"""Team CTF workflow component. See README.md for configuration and verified scope."""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pc_lib import College, load_config, save_config  # noqa: E402

# 路径一律可用环境变量覆盖 —— 这台机器上的默认值只是「本机缺省」，
# 换机器不要改代码，设 CTF_KB / CTF_KALI_BRIDGE 即可。
KB = Path(os.environ.get("CTF_KB", str(Path(__file__).resolve().parents[2])))
POOL = KB / "题目库" / "pwn.college"
CASES = KB / "战例库" / "pwn.college"

BRIDGE_DIR = Path(os.environ.get(
    "CTF_KALI_BRIDGE_DIR", str(Path(__file__).resolve().parents[2] / "bridge")))
BRIDGE_PY_FILE = BRIDGE_DIR / "kali_bridge.py"
BRIDGE_CONFIG = BRIDGE_DIR / "config" / "kali.json"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def case_name(dojo, module, challenge):
    raw = "%s_%s_%s" % (dojo, module, challenge)
    return re.sub(r"[^A-Za-z0-9_-]", "-", raw)[:64]


def local_dir(dojo, module, challenge):
    d = POOL / dojo / module / challenge
    d.mkdir(parents=True, exist_ok=True)
    return d


# --------------------------------------------------------------------------- Kali 桥接

def kali(*args, timeout=300):
    """直接调用桥接（绕开 powershell.exe；桥接脚本本身用 uv 的 python 跑）。"""
    py = json.loads(BRIDGE_CONFIG.read_text(encoding="utf-8-sig"))["python"]
    r = subprocess.run([py, str(BRIDGE_PY_FILE), *args],
                       capture_output=True, text=True, timeout=timeout)
    out = (r.stdout or "").strip()
    try:
        return r.returncode, json.loads(out)
    except ValueError:
        return r.returncode, {"raw": out, "stderr": (r.stderr or "").strip()}


# --------------------------------------------------------------------------- 各步骤

def cmd_find(args):
    c = College()
    if not c.whoami():
        print("未登录，先跑 pc_login.py up")
        return 2
    dojos = [args.dojo] if args.dojo else [d["id"] for d in c.dojos()]
    total = 0
    for dojo in dojos:
        try:
            rows = c.unsolved(dojo, include_optional=args.all)
        except Exception as exc:
            print("  [跳过] %s: %s" % (dojo, exc))
            continue
        if not rows:
            continue
        print("\n== %s ==  未完成 %d 题" % (dojo, len(rows)))
        for r in rows[: args.limit]:
            print("   %-22s %-16s %s" % (r["module"], r["challenge"],
                                         (r["challenge_name"] or "")[:40]))
        if len(rows) > args.limit:
            print("   ... 还有 %d 题" % (len(rows) - args.limit))
        total += len(rows)
    print("\n合计未完成: %d" % total)
    return 0


def do_start(c, dojo, module, challenge, practice=False, wait=90):
    """启动挑战容器并等到可用。"""
    print("[1/5] 启动挑战 %s / %s / %s%s" % (dojo, module, challenge, "（practice）" if practice else ""))
    res = c.start(dojo, module, challenge, practice=practice)
    if not res.get("success"):
        print("   启动失败:", res)
        return False
    print("   已提交启动请求，等待容器就绪 ...")
    deadline = time.time() + wait
    while time.time() < deadline:
        try:
            cur = c.current()
        except Exception:
            cur = {}
        if cur.get("success") and cur.get("challenge") == challenge:
            print("   容器就绪: dojo=%s module=%s challenge=%s practice=%s" % (
                cur.get("dojo"), cur.get("module"), cur.get("challenge"), cur.get("practice")))
            return True
        time.sleep(3)
    print("   等待超时，但容器可能仍在启动，继续尝试下载")
    return True


def do_download(c, dojo, module, challenge):
    dest = local_dir(dojo, module, challenge)
    print("[2/5] 下载 /challenge -> %s" % dest)
    last = None
    for attempt in range(1, 6):
        try:
            files = c.download_challenge(dest)
            for f in files:
                print("   %-40s %8d B" % (f["path"], f["bytes"]))
            return files
        except Exception as exc:
            last = exc
            print("   第 %d 次失败: %s" % (attempt, exc))
            time.sleep(5)
    print("   下载最终失败:", last)
    return None


def do_meta(c, dojo, module, challenge, dest, files):
    print("[3/5] 抓题面 + 生成 manifest")
    try:
        desc = c.description(dojo, module, challenge)
        (dest / "description.md").write_text(desc, encoding="utf-8")
        print("   description.md %d B" % len(desc))
    except Exception as exc:
        desc = ""
        print("   题面抓取失败:", exc)
    manifest = {
        "platform": "pwn.college",
        "dojo": dojo, "module": module, "challenge": challenge,
        "pulled_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "case": case_name(dojo, module, challenge),
        "files": [{"path": f["path"], "bytes": f["bytes"],
                   "sha256": sha256(dest / f["path"])} for f in files],
    }
    (dest / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2),
                                        encoding="utf-8")
    return manifest


def do_handoff(case, dest):
    print("[4/5] 交接给 Kali（case=%s）" % case)
    # 桥接要求普通文件名（不含路径分隔符），先把嵌套文件摊平
    staged = []
    flat = dest / "_flat"
    flat.mkdir(exist_ok=True)
    for path in sorted(dest.rglob("*")):
        if not path.is_file() or flat in path.parents or path.name == "manifest.json":
            continue
        name = path.name
        i = 1
        while (flat / name).exists() and sha256(flat / name) != sha256(path):
            i += 1
            name = "%s_%d%s" % (path.stem, i, path.suffix)
        target = flat / name
        if not target.exists():
            target.write_bytes(path.read_bytes())
        staged.append(str(target))
    if not staged:
        print("   没有可交接的文件（只有任务描述类题目？）")
        return None
    rc, data = kali("put", case, *staged)
    print("   put rc=%d  verified=%s  files=%d" % (rc, data.get("verified"), len(staged)))
    if rc != 0:
        print("   桥接失败:", json.dumps(data, ensure_ascii=False)[:500])
        return None
    return data


def cmd_pull(args):
    c = College()
    if not c.whoami():
        print("未登录，先跑 pc_login.py up")
        return 2
    dojo, module, challenge = args.dojo, args.module, args.challenge
    if not do_start(c, dojo, module, challenge, practice=args.practice):
        return 1
    dest = local_dir(dojo, module, challenge)
    files = do_download(c, dojo, module, challenge)
    if files is None:
        return 1
    do_meta(c, dojo, module, challenge, dest, files)
    case = case_name(dojo, module, challenge)
    if not args.no_kali:
        do_handoff(case, dest)
    print("[5/5] 完成。")
    print("   写脚本 ->  Kali 执行： ")
    print("     powershell -NoProfile -File \"%s\\kali.ps1\" python %s <你的脚本.py>" % (BRIDGE_DIR, case))
    print("   取回产物：")
    print("     powershell -NoProfile -File \"%s\\kali.ps1\" fetch %s work/<产物>" % (BRIDGE_DIR, case))
    print("   提交 flag：")
    print("     python pc_flow.py submit --dojo %s --module %s --challenge %s --flag \"pwn.college{...}\""
          % (dojo, module, challenge))
    return 0


def cmd_submit(args):
    c = College()
    flag = args.flag.strip()
    if not flag.startswith("pwn.college{"):
        print("提醒: pwn.college 的 flag 形如 pwn.college{...}，你给的是:", flag)
    res = c.submit(args.dojo, args.module, args.challenge, flag)
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0 if res.get("success") else 1


def cmd_status(args):
    c = College()
    print("配置:", load_config().get("user") or "(未知用户)")
    try:
        print(json.dumps(c.current(), ensure_ascii=False, indent=2))
    except Exception as exc:
        print("查询失败:", exc)
    return 0


def cmd_stop(args):
    c = College()
    print(json.dumps(c.stop(), ensure_ascii=False, indent=2))
    return 0


def cmd_kali(a):
    """让 Kali 真正参与解题：上传脚本 -> 在 Kali 上跑 -> 取回产物。

    之前 `pull` 只做 `put`（把文件递过去），Kali 从头到尾没算过一次 ——
    这个子命令才是把它变成算力节点的那一步。
    """
    if not BRIDGE_PY_FILE.is_file():
        print("找不到 Kali 桥接:", BRIDGE_PY_FILE)
        return 2
    # 桥接的 --timeout 只允许 1..600（见 kali_bridge.py 的校验），
    # 而且它管的是「Kali 上脚本跑多久」；外层 timeout 必须 > 它 + 15。
    t = max(1, min(600, int(getattr(a, "timeout", 300) or 300)))
    if a.script:
        sp = Path(a.script)
        if not sp.is_file():
            print("脚本不存在:", sp)
            return 2
        rc, data = kali("put", a.case, str(sp))
        print("[put] rc=%d  %s" % (rc, json.dumps(data, ensure_ascii=False)[:300]))
        # 注意：桥接的 script 参数是「本地路径」（它自己 base64 后传过去），
        # 传远端文件名会报 WinError 2。
        rc, data = kali("python", "--timeout", str(t), a.case, str(sp),
                        timeout=t + 120)
        print("[run] rc=%d  timeout=%ds  timed_out=%s  returncode=%s"
              % (rc, t, data.get("timed_out"), data.get("returncode")))
        for key in ("stdout", "stderr"):
            v = (data.get(key) or "").strip()
            if v:
                print("--- %s ---" % key)
                print(v[:8000])
        print(json.dumps({k: v for k, v in data.items() if k not in ("stdout", "stderr")},
                         ensure_ascii=False, indent=2)[:3000])
    if a.fetch:
        rc, data = kali("fetch", a.case, a.fetch, timeout=600)
        print("[fetch] rc=%d" % rc)
        if a.out:
            Path(a.out).parent.mkdir(parents=True, exist_ok=True)
            Path(a.out).write_text(json.dumps(data, ensure_ascii=False, indent=2),
                                   encoding="utf-8")
            print("已写入:", a.out)
        else:
            print(json.dumps(data, ensure_ascii=False)[:6000])
    return 0


def cmd_run(a):
    """在挑战容器里跑命令。注意：**必须先有运行中的容器**（先 pull/start）。"""
    c = College()
    st = c._json("GET", "/docker", expect_ok=False)
    if not st.get("success"):
        print("没有运行中的容器，先跑 pc_flow.py pull ...")
        return 2
    print(f"目标: {st.get('dojo')}/{st.get('module')}/{st.get('challenge')}")
    rc, out, err = c.run_remote(a.command, timeout=a.timeout, stdin_data=a.stdin_data)
    print(f"rc={rc}")
    if out:
        print("--- stdout ---")
        print(out, end="" if out.endswith("\n") else "\n")
    if err.strip():
        print("--- stderr ---")
        print(err, end="" if err.endswith("\n") else "\n")
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("find"); f.set_defaults(func=cmd_find)
    f.add_argument("--dojo"); f.add_argument("--all", action="store_true")
    f.add_argument("--limit", type=int, default=20)

    for name in ("pull", "start"):
        s = sub.add_parser(name, help="启动挑战 + 下载 + 交接 Kali（start 与 pull 同义）")
        s.add_argument("--dojo", required=True)
        s.add_argument("--module", required=True)
        s.add_argument("--challenge", required=True)
        s.add_argument("--practice", action="store_true")
        s.add_argument("--no-kali", action="store_true")
        s.set_defaults(func=cmd_pull)

    sb = sub.add_parser("submit"); sb.set_defaults(func=cmd_submit)
    sb.add_argument("--dojo", required=True)
    sb.add_argument("--module", required=True)
    sb.add_argument("--challenge", required=True)
    sb.add_argument("--flag", required=True)

    k = sub.add_parser("kali", help="★ 让 Kali 真干活：上传脚本 -> 执行 -> 取回产物")
    k.set_defaults(func=cmd_kali)
    k.add_argument("--case", required=True, help="战例名，如 reversing-hell_welcome_flag0")
    k.add_argument("--script", help="要上传并执行的本地 .py 脚本")
    k.add_argument("--fetch", help="要取回的远端相对路径，如 work/out.json")
    k.add_argument("--out", help="取回后写到本地的路径")
    k.add_argument("--timeout", type=int, default=300,
                   help="Kali 上脚本的执行上限（1-600 秒，桥接硬限制）")

    rn = sub.add_parser("run", help="在已运行的挑战容器里跑一条命令")
    rn.set_defaults(func=cmd_run)
    rn.add_argument("command", nargs="?", default="ls -la /challenge")
    rn.add_argument("--stdin", dest="stdin_data", default=None,
                    help="喂给程序 stdin 的字符串（题目要 scanf 输入时用）")
    rn.add_argument("--timeout", type=int, default=60)

    sub.add_parser("status").set_defaults(func=cmd_status)
    sub.add_parser("stop").set_defaults(func=cmd_stop)

    a = p.parse_args()
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
