"""Verify and reconstruct the unencrypted, credential-scrubbed team record snapshot."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import tempfile

BASE = Path(__file__).resolve().parents[1]
DEFAULT = BASE / "knowledge/records/20261023/manifest.json"


def safe_relative(value):
    p = PurePosixPath(value)
    if not value or p.is_absolute() or any(x in {"", ".", ".."} for x in p.parts) or "\\" in value or ":" in value:
        raise ValueError("Unsafe snapshot path: " + value)
    return p


def load_manifest(path=DEFAULT):
    path = Path(path).resolve(strict=True)
    manifest = json.loads(path.read_text(encoding="utf-8-sig"))
    if manifest.get("format") != 1 or manifest.get("encrypted") is not False:
        raise ValueError("Unsupported record snapshot")
    seen = set()
    for item in manifest["files"]:
        relative = safe_relative(item["source"] + "/" + item["path"])
        identity = str(relative).casefold()
        if identity in seen:
            raise ValueError("Duplicate destination path: " + str(relative))
        seen.add(identity)
        obj = safe_relative(item["object"])
        if obj.parts[0] != "objects":
            raise ValueError("Object outside snapshot object directory")
        candidate = path.parent.joinpath(*obj.parts)
        if candidate.is_symlink() or not candidate.resolve(strict=True).is_relative_to(path.parent):
            raise ValueError("Snapshot object path escaped")
    return path.parent, manifest


def verify(path=DEFAULT):
    root, manifest = load_manifest(path)
    checked = {}
    for item in manifest["files"]:
        obj = item["object"]
        if obj not in checked:
            raw = (root / obj).read_bytes()
            checked[obj] = (hashlib.sha256(raw).hexdigest(), len(raw))
        if checked[obj] != (item["sha256"], item["bytes"]):
            raise ValueError("Snapshot hash or length mismatch: " + obj)
    return {"ok": True, "snapshot": manifest["snapshot"], "files": len(manifest["files"]),
            "objects": len(checked), "bytes": sum(v[1] for v in checked.values()),
            "excluded": len(manifest.get("excluded", [])), "encrypted": False}


def restore(output, path=DEFAULT):
    result = verify(path)
    root, manifest = load_manifest(path)
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("Destination already exists; choose a new directory: " + str(output))
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".team-records-", dir=output.parent))
    try:
        for item in manifest["files"]:
            relative = safe_relative(item["source"] + "/" + item["path"])
            target = stage.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / item["object"], target)
        shutil.copyfile(Path(path), stage / "SNAPSHOT-MANIFEST.json")
        path_map = {
            "[CTF_ROOT]/wp": str(output / "project-wp"),
            "[CTF_ROOT]/战例库": str(output / "project-cases"),
            "[CTF_ROOT]/logs/calls": str(output / "tool-calls"),
            "[CTF_ROOT]/.local/ctf-system/tasks": str(output / "tasks"),
            "[CTF_ROOT]/dataset": str(output / "training"),
            "[WORKSPACE]/ctf-workbench/cases": str(output / "workbench"),
            "[OBSIDIAN_CTF]": str(output / "obsidian-notes"),
        }
        (stage / "PATH-MAP.json").write_text(json.dumps(path_map, ensure_ascii=False, indent=2), encoding="utf-8")
        (stage / "READ-ME.txt").write_text(
            "Historical CTF solving records. Published copies may contain credential redactions.\n"
            "Original source hashes and shared-copy hashes are separate.\n"
            "Fixtures, failures and incomplete attempts are not solved challenges.\n"
            "Original filenames and relative paths are restored inside each source group.\n"
            "Read existing scripts as reference; this command never executes them.\n", encoding="utf-8")
        stage.rename(output)
    except BaseException:
        if stage.exists():
            if stage.resolve().parent != output.parent.resolve() or not stage.name.startswith(".team-records-"):
                raise RuntimeError("Staging cleanup path escaped")
            shutil.rmtree(stage)
        raise
    return dict(result, output=str(output))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["verify", "list", "restore"])
    parser.add_argument("--manifest", type=Path, default=DEFAULT)
    parser.add_argument("--case", default="", help="Match a source group or relative filename")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.command == "verify":
        result = verify(args.manifest)
    elif args.command == "restore":
        result = restore(args.output or BASE / ".local/shared-records/20261023", args.manifest)
    else:
        _, manifest = load_manifest(args.manifest)
        query = args.case.casefold()
        result = [dict(source=x["source"], path=x["path"], bytes=x["bytes"],
                       modified_for_sharing=x["modified_for_sharing"])
                  for x in manifest["files"] if query in (x["source"] + "/" + x["path"]).casefold()]
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError) as exc:
        raise SystemExit("Record snapshot error: " + str(exc))
