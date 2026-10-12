"""Team CTF workflow component. See README.md for configuration and verified scope."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import uuid

BASE = Path(__file__).resolve().parent.parent
NAME = "ctf-team-workflow"
FILES = ("SKILL.md", "agents/openai.yaml", "scripts/locate_system.py")


def hashes(folder):
    if folder.is_symlink():
        raise ValueError("Skill 目标是符号链接，拒绝覆盖")
    result = {}
    for path in sorted(folder.rglob("*")):
        if path.is_symlink():
            raise ValueError("Skill 包含符号链接，拒绝覆盖")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
            result[path.relative_to(folder).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False, suffix=".tmp") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        temp = Path(stream.name)
    os.replace(temp, path)


def target_path(home, client):
    return home / (".agents" if client == "codex" else ".claude") / "skills" / NAME


def install(client, repo=None, home=None):
    repo = Path(repo or BASE).resolve()
    home = Path(home or Path.home()).resolve()
    if client not in ("codex", "claude", "both"):
        raise ValueError("client 必须为 codex/claude/both")
    for name in ("AGENTS.md", "README.md", "setup.ps1", "tools/ctf_os.py"):
        if not (repo/name).is_file():
            raise ValueError("仓库缺少入口文件: " + name)
    source = repo / "skills" / NAME
    if not source.is_dir() or any(not (source/name).is_file() for name in FILES):
        raise ValueError("仓库缺少完整 Skill")
    expected = hashes(source)
    if set(expected) != set(FILES):
        raise ValueError("Skill 包文件不在安装白名单中")
    folder = home / ".ctf-workflow-team"
    registry_path = folder / "skill-installs.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8")) if registry_path.exists() else {}
    clients = ("codex", "claude") if client == "both" else (client,)
    targets = []
    for item in clients:
        target = target_path(home, item)
        if target.exists() or target.is_symlink():
            if not target.is_dir():
                raise ValueError("Skill 目标不是目录: " + str(target))
            current = hashes(target)
            previous = registry.get(item, {})
            owned = previous.get("target") == str(target) and previous.get("files") == current
            if not owned and current != expected:
                raise ValueError("同名 Skill 已存在或被本机编辑，拒绝覆盖；先检查并备份: " + str(target))
        targets.append((item, target))
    installed = []
    for item, target in targets:
        target.parent.mkdir(parents=True, exist_ok=True)
        stage = Path(tempfile.mkdtemp(prefix=".ctf-skill-stage-", dir=target.parent))
        backup = target.parent / (".ctf-skill-backup-" + uuid.uuid4().hex)
        try:
            for name in FILES:
                dest = stage / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source/name, dest)
            assert hashes(stage) == expected
            if target.exists():
                target.rename(backup)
            try:
                stage.rename(target)
            except BaseException:
                if backup.exists():
                    backup.rename(target)
                raise
            registry[item] = {"target": str(target), "files": expected}
            write_json(registry_path, registry)
            if backup.exists():
                shutil.rmtree(backup)
        finally:
            if stage.exists():
                shutil.rmtree(stage)
        installed.append({"client": item, "path": str(target), "files_verified": hashes(target) == expected})
    write_json(folder / "location.json", {"version": 1, "repository": str(repo)})
    return {"ok": True, "skill": NAME, "installed": installed, "repository": str(repo),
            "location_record": str(folder / "location.json"), "deployment_verified": False,
            "next": "重开本机客户端会话，明确调用 Skill 并运行定位；安装文件不代表 VM 或完整解题验收通过"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", choices=("codex", "claude", "both"), required=True)
    parser.add_argument("--repo", help="默认使用此脚本所属仓库；移动仓库后重新运行")
    args = parser.parse_args()
    try:
        result = install(args.client, args.repo)
    except (ValueError, OSError, KeyError, TypeError, AttributeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
