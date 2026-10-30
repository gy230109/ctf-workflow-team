#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""赛前环境体检（**纯只读**）—— 把 2026-10-24 羊城杯复盘暴露的短板变成一键检查。

背景：比赛当天 Defender 查杀赛题附件、Windows 更新抢带宽、Wi-Fi 两次掉线、
测试二进制直接跑在宿主机、环境最后一刻才就绪。本工具只**检查并报告**，
不替使用者改任何系统状态；每个非 ok 项都给"修复命令"，需要管理员权限的会标注。

检查组：
  deps            Windows 依赖自检（转调 tools/check_env.py，落实 依赖清单.md §四 TODO）
  defender        实时保护/病毒库、比赛目录排除项可见性、近期检出是否触及比赛目录
  windows_update  wuauserv 状态/启动类型、近 24h 下载安装事件、待重启标记、应用崩溃
  network         比赛平台 DNS+HTTPS、系统代理、本机 CTF-OS 服务在位
  vm              vmrun 在位、运行中虚拟机、配置 VMX 的快照数量（无快照告警）
  host_hygiene    盘余量、Downloads/Desktop 近 N 小时新增 exe/dll/sys

实现说明：
- PowerShell 仅用于 Defender 与事件日志查询（Get-Mp* / Get-WinEvent 输出受控、
  不受系统区域语言影响）；其余走 sc.exe / winreg / urllib / vmrun。
- 每组检查独立 try/except，永不因单项失败中断整体。
- 只读承诺：无写入、无服务变更、无 vmrun 状态操作；唯一例外是 check_env 的
  Obsidian 同步目标"写入探针"（创建并删除一个唯一命名 0 字节临时文件）。
"""
import ctypes
import json
import os
import re
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import winreg
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE / "config" / "envprep.local.json"
STARTUP = BASE / "config" / "startup.json"
CTF_OS_CFG = BASE / "config" / "ctf_os.json"
ENV_DIR = BASE / "环境"
PS = str(Path(os.environ.get("WINDIR", r"C:\Windows")) /
         "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")

OK, WARN, FAIL, NA = "ok", "warn", "fail", "na"
_ICON = {OK: "✅", WARN: "⚠️", FAIL: "❌", NA: "ℹ️"}


# ---------------------------------------------------------------- 基础设施

def _read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return {}


def _is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run(argv, timeout=30):
    try:
        r = subprocess.run(argv, capture_output=True, timeout=timeout,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return r.returncode, ((r.stdout or b"") + (r.stderr or b"")).decode("utf-8", "replace")
    except Exception as exc:                                    # noqa: BLE001
        return -1, "<<error: %s>>" % exc


def _ps(source, timeout=90):
    """跑 PowerShell（输出 UTF8），返回 stdout；失败抛 RuntimeError 由调用方接。"""
    rc, out = _run([PS, "-NoProfile", "-NonInteractive", "-Command",
                    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " + source],
                   timeout=timeout)
    if rc != 0:
        raise RuntimeError(out.strip()[-500:] or "powershell exit %d" % rc)
    return out


def _item(name, status, detail, fix="", cmd="", needs_admin=False):
    d = {"name": name, "status": status, "detail": detail}
    if fix:
        d["fix"] = fix
    if cmd:
        d["cmd"] = cmd
    if needs_admin:
        d["needs_admin"] = True
    return d


def _worst(items):
    """items 可以是 dict 列表或 dict-of-sections。"""
    levels = []
    for x in items:
        if isinstance(x, dict) and "status" in x:
            levels.append(x["status"])
    for bad in (FAIL, WARN, NA):
        if bad in levels:
            return bad
    return OK if levels and all(level == OK for level in levels) else NA


# ---------------------------------------------------------------- 配置

DEFAULT_CFG = {
    "competition_dirs": ["D:/羊城杯", "D:/强网杯大师"],
    "watch_dirs": ["~/Downloads", "~/Desktop"],
    "platform_urls": ["https://ycb-bk.dasctf.com"],
    "extra_vmx": [],
    "downloads_hours": 48,
}


def load_cfg():
    cfg = dict(DEFAULT_CFG)
    cfg.update(_read_json(CONFIG_PATH))
    cfg["watch_dirs"] = [str(Path(p).expanduser()) for p in cfg["watch_dirs"]]
    return cfg


def _default_vmx_list(args_vmx=None):
    startup = _read_json(STARTUP)
    vmx_list = []
    if args_vmx:
        vmx_list.append(args_vmx)
    muteki = (startup.get("muteki") or {}).get("vmx")
    if muteki:
        vmx_list.append(muteki)
    vmx_list.extend(_read_json(CONFIG_PATH).get("extra_vmx") or [])
    seen, out = set(), []
    for v in vmx_list:
        key = str(v).replace("/", "\\").lower()
        if key not in seen:
            seen.add(key)
            out.append(str(v))
    return out


def _find_vmrun():
    """复用 ctf_bootstrap 的解析链：config/ctf_os.json → kali_bridge → 同级 config/kali.json。"""
    bridge = _read_json(CTF_OS_CFG).get("kali_bridge")
    if bridge:
        kj = Path(bridge).parent / "config" / "kali.json"
        vmrun = _read_json(kj).get("vmrun")
        if vmrun and Path(vmrun).is_file():
            return vmrun, str(kj)
    found = shutil.which("vmrun")
    if found:
        return found, "PATH"
    for cand in (r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe",
                 r"C:\Program Files\VMware\VMware Workstation\vmrun.exe"):
        if Path(cand).is_file():
            return cand, "默认安装路径"
    return None, None


# ---------------------------------------------------------------- 各检查组

def check_deps(args, cfg):
    try:
        import check_env                                          # 同目录；ctf_os 启动时已注入 sys.path
        r = check_env.run()
    except Exception as exc:                                      # noqa: BLE001
        return {"status": NA, "items": [_item("依赖自检", NA, "check_env 执行失败: %r" % (exc,))]}
    items = []
    for it in r.get("items", []):
        items.append(_item(it["name"], OK if it["ok"] else FAIL,
                           it.get("detail", ""), fix=it.get("fix", "")))
    return {"status": _worst(items) if items else NA, "items": items,
            "notes": r.get("notes", []), "check_env_json": r.get("report_json")}


def check_defender(args, cfg):
    comp_dirs = [str(Path(p)).rstrip("\\").lower() for p in cfg["competition_dirs"]]
    try:
        raw = _ps(
            "$out=[ordered]@{};"
            "try{$s=Get-MpComputerStatus -ErrorAction Stop;"
            "$out.status=@{realtime=$s.RealTimeProtectionEnabled;"
            "avEnabled=$s.AntivirusEnabled;sigAgeDays=$s.AntivirusSignatureAge;"
            "sigUpdated=if($s.AntivirusSignatureLastUpdated){$s.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd')}else{$null}}}"
            "catch{$out.status_error=\"$_\"};"
            "try{$p=Get-MpPreference -ErrorAction Stop;"
            "$out.exclusionPath=$p.ExclusionPath;$out.exclusionProcess=$p.ExclusionProcess}"
            "catch{$out.pref_error=\"$_\"};"
            "try{$out.detections=@(Get-MpThreatDetection -ErrorAction Stop|"
            "Sort-Object InitialDetectionTime -Descending|Select-Object -First 30|"
            "ForEach-Object{@{threatId=$_.ThreatID;"
            "time=if($_.InitialDetectionTime){$_.InitialDetectionTime.ToString('yyyy-MM-dd HH:mm:ss')}else{$null};"
            "resources=@($_.Resources)}})}catch{$out.detect_error=\"$_\"};"
            "$out|ConvertTo-Json -Depth 4 -Compress")
        data = json.loads(raw)
    except Exception as exc:                                      # noqa: BLE001
        return {"status": NA, "items": [_item(
            "Defender 查询", NA, "Get-Mp* 不可用: %r" % (exc,),
            fix="以管理员运行 PowerShell 手动执行 Get-MpComputerStatus")]}

    items = []
    st = data.get("status") or {}
    if "status_error" in data:
        items.append(_item("Defender 状态", NA, str(data["status_error"])[:200]))
    else:
        rt = st.get("realtime")
        if rt is True:
            items.append(_item("实时保护", OK, "已开启"))
        elif rt is False:
            items.append(_item("实时保护", FAIL, "已关闭——赛题文件少了第一道防线，也更容易漏检真威胁",
                               fix="重新开启实时保护；误报问题用排除项解决，不要关防护",
                               cmd="powershell(管理员): Set-MpPreference -DisableRealtimeMonitoring $false",
                               needs_admin=True))
        else:
            items.append(_item("实时保护", NA, "状态未知: %r" % (rt,)))
        age = st.get("sigAgeDays")
        if isinstance(age, int) and age >= 7:
            items.append(_item("病毒库", WARN, "签名已 %d 天未更新（%s）" % (age, st.get("sigUpdated")),
                               fix="更新病毒库后再体检，旧库误报率高"))

    def _decode_resource(res):
        """Defender Resources 形如 'file:_C:\\Users\\...\\x.zip;'（特殊字符被换成 _）。"""
        s = str(res).strip().rstrip(";")
        if s.lower().startswith("file:"):
            s = s[5:]
        return s.replace("_", ":", 1).replace("/", "\\").lower()

    detections = data.get("detections") or []
    if "detect_error" in data:
        items.append(_item("近期检出记录", NA,
                           "Get-MpThreatDetection 不可用: %s" % str(data["detect_error"])[:150]))
    else:
        hits = []
        for det in detections:
            for res in (det.get("resources") or []):
                p = _decode_resource(res)
                if any(p.startswith(d) or d in p for d in comp_dirs):
                    hits.append(det)
                    break
        if hits:
            shown = "; ".join("%s @ %s" % (h.get("threatId"), h.get("time")) for h in hits[:3])
            items.append(_item("近期检出触及比赛目录", WARN,
                               "%d 条（最新: %s）" % (len(hits), shown),
                               fix="确认是误报后把目录加入排除项；来源不明的先在 VM 里分析"))
        else:
            items.append(_item("近期检出触及比赛目录", OK, "无（共 %d 条检出记录）" % len(detections)))

    # 排除项（非管理员时 Get-MpPreference 的排除字段返回哨兵字符串）
    excl = data.get("exclusionPath")
    if "pref_error" in data or (isinstance(excl, str) and excl.startswith("N/A")):
        items.append(_item("比赛目录排除项", NA,
                           "需管理员才能查看（当前%s管理员）。确认比赛目录已加白，避免赛中查杀中断"
                           % ("是" if _is_admin() else "非"),
                           fix="管理员 PowerShell 查看: Get-MpPreference | Select-Object ExclusionPath",
                           needs_admin=True))
    elif excl is not None:
        have = {str(x).rstrip("\\").lower() for x in (excl or []) if isinstance(x, str)}
        for d in cfg["competition_dirs"]:
            dd = str(Path(d)).rstrip("\\")
            if dd.lower() in have:
                items.append(_item("排除项含 %s" % d, OK, "已在白名单"))
            else:
                items.append(_item("排除项含 %s" % dd, WARN, "不在白名单——赛题附件可能被查杀中断",
                                   fix="比赛目录加入排除项（管理员）",
                                   cmd="powershell(管理员): Add-MpPreference -ExclusionPath '%s'" % dd,
                                   needs_admin=True))
    return {"status": _worst(items), "items": items}


def check_windows_update(args, cfg):
    items = []
    rc, out = _run(["sc", "query", "wuauserv"])
    running = rc == 0 and re.search(r"STATE\s*:\s*\d+\s+RUNNING", out) is not None
    rc2, out2 = _run(["sc", "qc", "wuauserv"])
    m = re.search(r"START_TYPE\s*:\s*\d+\s+(\w+)", out2)
    start_type = m.group(1) if m else "?"
    if rc != 0 or rc2 != 0:
        items.append(_item("wuauserv 服务", NA, "服务状态或启动类型查询失败；不能判断是否运行"))
    elif running:
        # wuauserv 空闲时会自动停止，"正在运行"本身会来回跳；是否告警交给下面的"近 24h 活动"项
        items.append(_item("wuauserv 服务", OK, "正在运行（启动类型 %s）——比赛前建议暂停" % start_type,
                           fix="赛前暂停（赛后恢复 demand 启动）",
                           cmd="管理员: sc config wuauserv start=disabled && net stop wuauserv ｜ "
                               "恢复: sc config wuauserv start=demand && net start wuauserv",
                           needs_admin=True))
    elif start_type == "DISABLED":
        items.append(_item("wuauserv 服务", OK, "已禁用（不会在赛中抢带宽）"))
    else:
        items.append(_item("wuauserv 服务", OK, "未运行（启动类型 %s）" % start_type))

    try:
        raw = _ps(
            "$out=[ordered]@{};"
            "$wu=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WindowsUpdateClient/Operational';"
            "Id=19,26,41,43;StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue);"
            "$out.wu_recent=@($wu|Select-Object -First 10|ForEach-Object{"
            "@{time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss');id=$_.Id}});"
            "$crash=@(Get-WinEvent -FilterHashtable @{LogName='Application';"
            "ProviderName='Application Error';StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue);"
            "$out.appcrash_24h=$crash.Count;"
            "$out.latest_crash=if($crash.Count){$crash[0].TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}else{$null};"
            "$out|ConvertTo-Json -Depth 4 -Compress")
        ev = json.loads(raw)
    except Exception as exc:                                      # noqa: BLE001
        items.append(_item("更新/崩溃事件", NA, "事件查询失败: %r" % (exc,)))
        return {"status": _worst(items), "items": items}

    wu = ev.get("wu_recent") or []
    if wu:
        items.append(_item("近 24h Windows 更新活动", WARN,
                           "%d 条（最近 %s id=%s）——比赛时段可能下载/安装"
                           % (len(wu), wu[0].get("time"), wu[0].get("id")),
                           fix="赛前暂停更新，赛后恢复"))
    else:
        items.append(_item("近 24h Windows 更新活动", OK, "无下载/安装记录"))

    reboot = []
    for path in (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing",
                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"):
        try:
            winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path + r"\RebootPending")
            reboot.append(path.rsplit("\\", 1)[-1])
        except OSError:
            pass
    items.append(_item("待重启", WARN if reboot else OK,
                       "系统挂着重启标记（%s）——赛前后安排重启" % ", ".join(reboot)
                       if reboot else "无"))

    crashes = ev.get("appcrash_24h") or 0
    items.append(_item("近 24h 应用崩溃", OK if not crashes else WARN,
                       "%d 次（最近 %s）" % (crashes, ev.get("latest_crash") or "-")))
    return {"status": _worst(items), "items": items}


def check_network(args, cfg):
    items = []
    urls = args.get("platform_urls") or cfg["platform_urls"]
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # 绕过系统代理
    for url in urls:
        host = urllib.parse.urlparse(url).hostname or url
        try:
            socket.getaddrinfo(host, 443)
            dns = "DNS 解析正常"
            dns_ok = True
        except OSError as exc:
            dns = "DNS 解析失败: %s" % exc
            dns_ok = False
        try:
            req = urllib.request.Request(url, method="HEAD",
                                         headers={"User-Agent": "ctf-envprep/1.0"})
            opener.open(req, timeout=6)
            http, http_ok = "HTTPS 可达", True
        except urllib.error.HTTPError as e:
            http, http_ok = "HTTPS 可达（HTTP %s）" % e.code, True
        except Exception as exc:                                # noqa: BLE001
            http, http_ok = "不可达: %r" % (exc,), False
        status = OK if (dns_ok and http_ok) else FAIL
        items.append(_item("比赛平台 %s" % url, status, "%s；%s" % (dns, http),
                           fix="检查 DNS/代理/网络；平台故障先离线做题再回来刷新"
                           if status == FAIL else ""))

    proxy = {"enable": False, "server": "", "pac": ""}
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                           r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
        proxy["enable"] = bool(winreg.QueryValueEx(k, "ProxyEnable")[0])
        for name, key in (("server", "ProxyServer"), ("pac", "AutoConfigURL")):
            try:
                proxy[name] = str(winreg.QueryValueEx(k, key)[0])
            except OSError:
                pass
    except OSError:
        pass
    items.append(_item("系统代理", OK,
                       "关闭" if not proxy["enable"] else
                       "开启: %s %s" % (proxy["server"], proxy["pac"]),
                       fix="确认代理不会拦比赛平台（本探测已绕过代理）" if proxy["enable"] else ""))

    server_url = _read_json(STARTUP).get("server_url") or "http://127.0.0.1:8787"
    try:
        # /status performs dependency probes and may exceed this health budget.
        with opener.open(server_url.rstrip('/') + "/version", timeout=4) as response:
            version = json.load(response)
        if not isinstance(version, dict) or not version.get('source_fingerprint'):
            raise ValueError('服务未返回有效版本信息')
        items.append(_item("CTF-OS 服务", OK, server_url + " 在位"))
    except Exception as exc:                                    # noqa: BLE001
        items.append(_item("CTF-OS 服务", WARN, "%s 不可达: %r" % (server_url, exc),
                           fix="启动 CTF 系统（桌面快捷方式，或 python tools/ctf_bootstrap.py --start）"))
    return {"status": _worst(items), "items": items}


def check_vm(args, cfg):
    items = []
    vmrun, src = _find_vmrun()
    if not vmrun:
        return {"status": WARN, "items": [_item(
            "vmrun", WARN, "未找到 vmrun.exe（kali.json 与常见安装路径都没有）",
            fix="确认 VMware Workstation 安装路径；在 .local/bridge-runtime/config/kali.json 补 vmrun 字段")]}
    items.append(_item("vmrun", OK, "%s（来源: %s）" % (vmrun, src)))

    rc, out = _run([vmrun, "-T", "ws", "list"], timeout=20)
    if rc == 0:
        rows = [x.strip() for x in out.splitlines()[1:] if x.strip()]
        items.append(_item("运行中虚拟机", OK if rows else WARN,
                           ("%d 台: %s" % (len(rows), "; ".join(rows)))
                           if rows else "无——赛题 VM 未开机",
                           fix="赛前把赛题 VM 开机或打完快照挂起，做题时秒恢复" if not rows else ""))
    else:
        items.append(_item("运行中虚拟机", NA, "vmrun list 失败: %s" % out.strip()[-200:]))

    for vmx in _default_vmx_list(args.get("vmx")):
        label = "快照 %s" % Path(vmx).name
        if not Path(vmx).is_file():
            items.append(_item(label, FAIL, "VMX 不存在: %s" % vmx))
            continue
        rc, out = _run([vmrun, "-T", "ws", "listSnapshots", vmx], timeout=20)
        if rc != 0:
            items.append(_item(label, NA, "查询失败: %s" % out.strip()[-200:]))
            continue
        m = re.search(r"Total snapshots:\s*(\d+)", out)
        if not m:
            items.append(_item(label, NA, "快照计数无法解析；不能据此认定没有快照"))
            continue
        count = int(m.group(1))
        names = [x.strip() for x in out.splitlines()
                 if x.strip() and not x.startswith(("Total", "Name:"))]
        dated = [n for n in names if re.search(r"\d{8}", n)]
        if count == 0:
            items.append(_item(label, WARN, "没有任何快照——赛题环境损坏只能重建",
                               fix="打一个赛前基线快照",
                               cmd='vmrun -T ws snapshot "%s" "赛前基线-%s"'
                                   % (vmx, time.strftime("%Y%m%d"))))
        elif not dated:
            items.append(_item(label, WARN, "%d 个快照，但名字都不含日期，无法判断新旧" % count,
                               fix="快照命名带日期（如 基线-20261024）"))
        else:
            items.append(_item(label, OK, "%d 个快照，含日期的: %s" % (count, "、".join(dated))))
    return {"status": _worst(items), "items": items}


def check_host_hygiene(args, cfg):
    items = []
    for drive in ("C:\\", str(Path(str(BASE)).anchor)):
        try:
            u = shutil.disk_usage(drive)
            pct = u.free / u.total * 100
            items.append(_item("磁盘余量 %s" % drive, OK if pct >= 15 else WARN,
                               "%.1f GB 可用（%.0f%%）" % (u.free / 1024 ** 3, pct),
                               fix="VM/附件会快速吃盘，建议保持 15% 以上" if pct < 15 else ""))
        except Exception as exc:                                # noqa: BLE001
            items.append(_item("磁盘余量 %s" % drive, NA, "%r" % (exc,)))

    hours = int(args.get("downloads_hours") or cfg.get("downloads_hours") or 48)
    now = time.time()
    bins = []
    for d in cfg["watch_dirs"]:
        p = Path(d)
        if not p.is_dir():
            continue
        try:
            for f in p.iterdir():
                if f.suffix.lower() in (".exe", ".dll", ".sys"):
                    mt = f.stat().st_mtime
                    if now - mt <= hours * 3600:
                        bins.append("%s（%s）" % (f.name,
                                     datetime.fromtimestamp(mt).strftime("%m-%d %H:%M")))
        except OSError:
            continue
    if bins:
        items.append(_item("宿主机新二进制（近 %dh）" % hours, WARN,
                           "%d 个: %s" % (len(bins), "; ".join(bins[:8])),
                           fix="赛题/exploit 二进制移入 VM 执行，宿主机只留资料与提交"))
    else:
        items.append(_item("宿主机新二进制（近 %dh）" % hours, OK, "无"))
    return {"status": _worst(items), "items": items}


# ---------------------------------------------------------------- 报告

def _render_md(result):
    lines = ["# 赛前环境体检", "",
             "- 时间: %s" % result["checked_at"],
             "- 权限: %s" % ("管理员" if result["is_admin"] else "普通用户（部分项无法检查，见 ℹ️）"),
             "- 总体: **%s**" % result["overall"].upper(), ""]
    for sec, data in result["sections"].items():
        lines.append("## %s（%s）" % (sec, data["status"]))
        lines.append("")
        for it in data.get("items", []):
            lines.append("- %s **%s** —— %s" % (_ICON.get(it["status"], "?"),
                                                it["name"], it.get("detail", "")))
            if it.get("fix"):
                lines.append("  - 建议: %s" % it["fix"])
            if it.get("cmd"):
                lines.append("  - 命令: `%s`%s" % (it["cmd"],
                             "（需管理员）" if it.get("needs_admin") else ""))
        if data.get("notes"):
            for n in data["notes"]:
                lines.append("- ℹ️ %s" % n)
        lines.append("")
    cmds = [(it["name"], it["cmd"], it.get("needs_admin", False))
            for data in result["sections"].values()
            for it in data.get("items", []) if it.get("cmd")]
    if cmds:
        lines.append("## 修复命令清单")
        lines.append("")
        for name, cmd, adm in cmds:
            lines.append("- [ ] %s：`%s`%s" % (name, cmd, "（需管理员）" if adm else ""))
        lines.append("")
    return "\n".join(lines)


def tool_env_prep_check(a):
    """一键赛前体检：依赖 / Defender / Windows 更新 / 网络 / VM 快照 / 宿主机卫生。

    **纯只读**——不改防护、不停服务、不动快照；非 ok 项给修复命令（需管理员者标注）。
    """
    args = dict(a or {})
    for k in ("wp_case", "wp_purpose", "wp_expectation"):
        args.pop(k, None)
    cfg = load_cfg()
    sections = {
        "Defender": check_defender(args, cfg),
        "Windows 更新": check_windows_update(args, cfg),
        "网络": check_network(args, cfg),
        "VM 快照": check_vm(args, cfg),
        "宿主机卫生": check_host_hygiene(args, cfg),
    }
    if args.get("deep", True):
        sections["依赖自检"] = check_deps(args, cfg)
    overall = _worst(list(sections.values()))
    result = {
        "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "is_admin": _is_admin(),
        "overall": overall,
        "summary": {sec: data["status"] for sec, data in sections.items()},
        "sections": sections,
    }
    if args.get("save_report", True):
        try:
            ENV_DIR.mkdir(parents=True, exist_ok=True)
            path = ENV_DIR / ("赛前体检-%s.md" % datetime.now().strftime("%Y%m%d-%H%M%S"))
            path.write_text(_render_md(result), encoding="utf-8")
            result["report_md"] = str(path)
        except Exception as exc:                                # noqa: BLE001
            result["report_md_error"] = repr(exc)
    return result


TOOLS = {
    "env_prep_check": (
        tool_env_prep_check,
        "一键赛前体检（纯只读）：依赖/Defender/Windows更新/网络/VM快照/宿主机卫生，"
        "非 ok 项给修复命令；比赛前跑一次，避免赛中被打断",
        {"type": "object",
         "properties": {
             "deep": {"type": "boolean", "description": "含依赖自检（默认 true）"},
             "save_report": {"type": "boolean", "description": "落盘 环境\\赛前体检-<ts>.md（默认 true）"},
             "platform_urls": {"type": "array", "items": {"type": "string"},
                               "description": "比赛平台 URL，默认取 config/envprep.local.json"},
             "vmx": {"type": "string", "description": "额外检查的 VMX 路径（默认含 startup.json 的 Muteki）"},
             "downloads_hours": {"type": "integer",
                                 "description": "宿主机新二进制扫描窗口小时数，默认 48"}},
         "required": []}),
}


if __name__ == "__main__":
    print(json.dumps(tool_env_prep_check({}), ensure_ascii=False, indent=2))
