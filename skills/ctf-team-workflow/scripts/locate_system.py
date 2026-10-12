"""Locate the local checkout without running it or contacting a service."""
import argparse
import json
import os
from pathlib import Path
import sys

REQUIRED = ("AGENTS.md", "README.md", "setup.ps1", "tools/ctf_os.py")


def valid_repo(path):
    return path.is_dir() and all((path / name).is_file() for name in REQUIRED)


def describe(path, source, stale=False):
    interpreters = (path / ".venv/Scripts/python.exe", path / ".venv/bin/python")
    python = next((p for p in interpreters if p.is_file()), None)
    return {"ok": True, "repository": str(path), "root_source": source,
            "location_record_stale": stale, "python_executable": str(python or Path(sys.executable).resolve()),
            "host_venv_present": python is not None, "deployment_verified": False,
            "agent_contract": str(path / "AGENTS.md"), "readme": str(path / "README.md"),
            "agent_integration": str(path / "docs/agent-integration.md"),
            "tool_entry": str(path / "tools/ctf_os.py"),
            "verification_report": str(path / "logs/team-setup/verification.json"),
            "note": "定位成功不代表已部署、VM 在线、账号已认证或解题成功"}


def locate(repo=None, home=None, cwd=None, skill_file=None, environment=None):
    home = Path(home or Path.home())
    environment = os.environ if environment is None else environment
    explicit = repo or environment.get("CTF_WORKFLOW_HOME")
    if explicit:
        path = Path(explicit).expanduser().resolve()
        if not valid_repo(path):
            raise ValueError("指定仓库缺少 CTF-OS 入口文件；请检查 --repo / CTF_WORKFLOW_HOME")
        return describe(path, "argument" if repo else "environment")
    saved = home / ".ctf-workflow-team/location.json"
    stale = False
    if saved.is_file():
        try:
            data = json.loads(saved.read_text(encoding="utf-8"))
            path = Path(data["repository"]).expanduser()
            if not path.is_absolute():
                raise ValueError("位置记录必须是绝对路径")
            path = path.resolve()
            if valid_repo(path):
                return describe(path, "user_location_record")
            stale = True
        except (OSError, ValueError, KeyError, TypeError):
            stale = True
    script = Path(skill_file or __file__).resolve()
    for path in script.parents:
        if valid_repo(path):
            return describe(path, "skill_checkout", stale)
    current = Path(cwd or Path.cwd()).resolve()
    for path in (current, *current.parents):
        if valid_repo(path):
            return describe(path, "working_directory", stale)
    raise ValueError("未找到本机 CTF 仓库；提供 --repo <绝对路径>，或在仓库运行 tools/install_skill.py 写入本机位置")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", help="显式指定本机仓库位置")
    args = parser.parse_args()
    try:
        result = locate(args.repo)
    except (ValueError, OSError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
