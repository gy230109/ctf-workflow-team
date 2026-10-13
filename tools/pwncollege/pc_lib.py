# -*- coding: utf-8 -*-
"""Team CTF workflow component. See README.md for configuration and verified scope."""
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

import requests

BASE = "https://pwn.college"
API = BASE + "/pwncollege_api/v1"
SSH_HOST = "dojo.pwn.college"
SSH_USER = "hacker"

HOME = Path(os.environ.get("PWNCOLLEGE_HOME", str(Path.home() / ".ctf")))
CONFIG = HOME / "pwncollege.json"
KEY_PATH = HOME / "pc_ed25519"
KNOWN_HOSTS = HOME / "known_hosts"
SSH_KEYGEN = shutil.which("ssh-keygen") or "ssh-keygen"


# --------------------------------------------------------------------------- 配置

def load_config():
    if CONFIG.is_file():
        return json.loads(CONFIG.read_text(encoding="utf-8"))
    return {}


def save_config(data):
    HOME.mkdir(parents=True, exist_ok=True)
    merged = load_config()
    merged.update(data)
    CONFIG.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
    return CONFIG


# --------------------------------------------------------------------------- 客户端

class NotAuthed(RuntimeError):
    pass


class College:
    """pwn.college HTTP 客户端。优先用 token，退回 cookie + CSRF。"""

    def __init__(self, config=None, timeout=30):
        self.cfg = config if config is not None else load_config()
        self.timeout = timeout
        self.s = requests.Session()
        self.s.headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36 Edg/154.0.0.0"
        )
        self.s.headers["Accept"] = "application/json"
        self._csrf = None
        self.auth_mode = None

        token = self.cfg.get("token")
        if token:
            self.s.headers["Authorization"] = "Token " + token
            self.auth_mode = "token"
        else:
            for name, value in (self.cfg.get("cookies") or {}).items():
                self.s.cookies.set(name, value, domain="pwn.college", path="/")
            self.auth_mode = "cookie"

    # ---------------------------------------------------------------- 底层

    def _csrf_token(self, force=False):
        """取 CSRF nonce。

        ⚠️ 2026-10-10 实测修正：**`/csrf` 这个端点不存在**（404）。
        nonce 其实是页面 HTML 里那坨 `var init = { ... 'csrfNonce': "..." }`，
        **任意一个页面都有**（连 404 页面都带），所以从 `/dojos` 的 HTML 里正则抠。
        另外头名**必须是 `CSRF-Token`**：实测 `X-CSRF-Token` 和把 nonce 放进 body 都是 403。
        """
        if self._csrf is None or force:
            r = self.s.get(BASE + "/dojos", timeout=self.timeout)
            r.raise_for_status()
            m = re.search(r"'csrfNonce'\s*:\s*\"([^\"]+)\"", r.text)
            if not m:
                raise RuntimeError("页面里没找到 csrfNonce —— 登录态可能失效了")
            self._csrf = m.group(1)
        return self._csrf

    def _request(self, method, path, **kw):
        url = path if path.startswith("http") else API + path
        kw.setdefault("timeout", self.timeout)
        # API 未登录时 authed_only 会 302 到登录页；不要让 requests 跟过去把 HTML 当 JSON
        if url.startswith(API):
            kw.setdefault("allow_redirects", False)
        if method in ("POST", "PATCH", "DELETE") and self.auth_mode == "cookie":
            kw.setdefault("headers", {})["CSRF-Token"] = self._csrf_token()
        r = self.s.request(method, url, **kw)
        if r.status_code == 403 and self.auth_mode == "cookie":
            kw["headers"]["CSRF-Token"] = self._csrf_token(force=True)
            r = self.s.request(method, url, **kw)
        return r

    def _json(self, method, path, expect_ok=True, **kw):
        r = self._request(method, path, **kw)
        if r.status_code in (301, 302, 303, 307, 308) or r.status_code == 401:
            raise NotAuthed(f"{method} {path} -> HTTP {r.status_code}（未登录或登录态失效）")
        try:
            data = r.json()
        except ValueError:
            if r.status_code == 404:
                raise RuntimeError(f"{method} {path} -> HTTP 404，路径可能不对（核对 api/__init__.py 的 add_namespace 前缀）")
            raise RuntimeError(f"{method} {path} -> HTTP {r.status_code} 非 JSON: {r.text[:300]}")
        if expect_ok and r.status_code >= 400:
            raise RuntimeError(f"{method} {path} -> HTTP {r.status_code}: {data}")
        return data

    # ---------------------------------------------------------------- 身份

    def me(self):
        return self._json("GET", "/users/me")

    def whoami(self):
        try:
            return self.me()
        except Exception:                                       # noqa: BLE001
            return None

    def mint_token(self, expiration=None):
        body = {"expiration": expiration} if expiration else {}
        data = self._json("POST", "/users/me/tokens", json=body)
        return data["data"]["value"]

    def add_ssh_key(self, public_key):
        return self._json("POST", "/ssh_key", json={"ssh_key": public_key.strip()})

    # ---------------------------------------------------------------- 找题

    def dojos(self):
        return self._json("GET", "/dojos")["dojos"]

    def modules(self, dojo):
        return self._json("GET", f"/dojos/{dojo}/modules")["modules"]

    def solves(self, dojo, username=None):
        q = f"?username={username}" if username else ""
        return self._json("GET", f"/dojos/{dojo}/solves{q}")["solves"]

    def description(self, dojo, module, challenge):
        return self._json("GET", f"/dojos/{dojo}/{module}/{challenge}/description")["description"]

    def unsolved(self, dojo, include_optional=False):
        """按 模块顺序 → 挑战顺序 返回未完成的题目列表。

        挑战的 `id` 形如 `level-3`，模块内顺序由 API 返回顺序决定（服务端已排序）。
        """
        solved = {(s["module_id"], s["challenge_id"]) for s in self.solves(dojo)}
        out = []
        for module in self.modules(dojo):
            for ch in module["challenges"]:
                if not include_optional and ch.get("required") is False:
                    continue
                if (module["id"], ch["id"]) in solved:
                    continue
                out.append({
                    "dojo": dojo,
                    "module": module["id"],
                    "module_name": module.get("name"),
                    "challenge": ch["id"],
                    "challenge_name": ch.get("name"),
                    "description": ch.get("description"),
                })
        return out

    # ---------------------------------------------------------------- 环境

    def start(self, dojo, module, challenge, practice=False, home=True, access_code=None):
        body = {"dojo": dojo, "module": module, "challenge": challenge,
                "practice": practice, "home": home}
        if access_code:
            body["access_code"] = access_code
        return self._json("POST", "/docker", json=body)

    def current(self):
        return self._json("GET", "/docker")

    def stop(self):
        return self._json("DELETE", "/docker")

    def next_challenge(self):
        return self._json("GET", "/docker/next")

    # ---------------------------------------------------------------- 提交

    def submit(self, dojo, module, challenge, flag):
        try:
            return self._json("POST", f"/dojos/{dojo}/{module}/{challenge}/solve",
                              json={"submission": flag}, expect_ok=False)
        except RuntimeError as exc:
            return {"success": False, "status": "error", "message": str(exc)}

    # ---------------------------------------------------------------- SSH / SFTP

    def ensure_keypair(self):
        """生成一把专用 ed25519 密钥（幂等）。返回 (私钥路径, 公钥文本)。"""
        HOME.mkdir(parents=True, exist_ok=True)
        pub = Path(str(KEY_PATH) + ".pub")
        if not pub.is_file():
            subprocess.run([SSH_KEYGEN, "-t", "ed25519", "-f", str(KEY_PATH),
                            "-N", "", "-C", "workbuddy-ctf-pwncollege", "-q"],
                           check=True, capture_output=True)
        return KEY_PATH, pub.read_text(encoding="utf-8").strip()

    def sftp(self):
        """连上 dojo 的 SSH，返回 (SSHClient, SFTPClient)。调用方负责 close。"""
        import paramiko
        if not KEY_PATH.is_file():
            raise RuntimeError("还没有 SSH 私钥，先跑 ensure_keypair() 并在网页/API 注册公钥")
        client = paramiko.SSHClient()
        if KNOWN_HOSTS.is_file():
            client.load_host_keys(str(KNOWN_HOSTS))
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(SSH_HOST, username=SSH_USER, key_filename=str(KEY_PATH),
                       look_for_keys=False, allow_agent=False, timeout=20)
        # 首次连接后把主机公钥落到本地 known_hosts
        host_keys = client.get_host_keys()
        if host_keys:
            client.save_host_keys(str(KNOWN_HOSTS))
        return client, client.open_sftp()

    def download_challenge(self, dest_dir, remote="/challenge"):
        """把远程 /challenge 整个目录捞到本地 dest_dir。返回文件清单。"""
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)
        client, sftp = self.sftp()
        saved = []
        try:
            stack = [remote]
            while stack:
                cur = stack.pop()
                for attr in sftp.listdir_attr(cur):
                    rpath = cur.rstrip("/") + "/" + attr.filename
                    import stat as _stat
                    if _stat.S_ISDIR(attr.st_mode):
                        stack.append(rpath)
                        continue
                    rel = os.path.relpath(rpath, remote)
                    target = dest / rel
                    target.parent.mkdir(parents=True, exist_ok=True)
                    sftp.get(rpath, str(target))
                    saved.append({"path": rel, "bytes": target.stat().st_size})
        finally:
            sftp.close()
            client.close()
        return saved

    def run_remote(self, command, timeout=60, stdin_data=None):
        """在挑战容器里跑一条命令，返回 (rc, stdout, stderr)。

        `stdin_data`：喂给程序标准输入的字符串（很多题是 `scanf` 要答案，靠这个喂）。
        传了就写进去并关闭 stdin，避免程序一直等输入。
        """
        client, _ = self.sftp()
        try:
            stdin, out, err = client.exec_command(command, timeout=timeout)
            if stdin_data is not None:
                stdin.write(stdin_data)
                stdin.flush()
                stdin.channel.shutdown_write()
            return (out.channel.recv_exit_status(),
                    out.read().decode("utf-8", "replace"),
                    err.read().decode("utf-8", "replace"))
        finally:
            client.close()


# --------------------------------------------------------------------------- CLI 自检

def main():
    argv = sys.argv[1:]
    c = College()
    print("认证方式:", c.auth_mode, "| 配置:", CONFIG)
    if not argv or argv[0] == "whoami":
        u = c.whoami()
        if u is None:
            print("未登录 / 登录态已失效")
            return 1
        print(json.dumps(u, ensure_ascii=False, indent=2))
        return 0
    if argv[0] == "dojos":
        for d in c.dojos():
            print("%-28s %-10s 模块 %-3s 挑战 %-4s  %s" % (
                d["id"], d.get("type"), d.get("modules_count"),
                d.get("challenges_count"), (d.get("name") or "")[:40]))
        return 0
    if argv[0] == "unsolved":
        dojo = argv[1]
        rows = c.unsolved(dojo)
        print(f"{dojo}: 未完成 {len(rows)} 题")
        for r in rows[:30]:
            print("  %-22s %-14s %s" % (r["module"], r["challenge"], (r["challenge_name"] or "")[:36]))
        return 0
    print("用法: pc_lib.py [whoami|dojos|unsolved <dojo>]")
    return 2


if __name__ == "__main__":
    sys.exit(main())
