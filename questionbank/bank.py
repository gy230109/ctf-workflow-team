"""Standalone CTF bank: inspect, select, fetch public handouts and prepare blind tasks.

Python 3.10+; standard library only. No challenge code or installers are executed.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import random
import re
import shutil
import sys
import tarfile
import threading
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
HANDOUTS = ROOT / "public_handouts"
FLAG_RE = re.compile(r"\b(?:flag|ctf|crypto|DUCTF|CSAW|HTB|SEKAI|SUCTF|picoCTF)\{[^{}\r\n]{1,300}\}", re.I)
CATEGORIES = ("web", "pwn", "reverse", "crypto", "misc", "forensics")
DOWNLOAD_LOCK = threading.Lock()


def load_rows():
    return [json.loads(line) for line in (DATA / "challenges.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]


def read_downloads():
    path = DATA / "downloads.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def require_task(rows, identifier, evaluation=False):
    matches = [row for row in rows if row["id"] == identifier]
    if not matches:
        raise ValueError("unknown task id")
    task = matches[0]
    if task.get("split") == "holdout" and not evaluation:
        raise ValueError("holdout task is reserved; use --evaluation only for an evaluation run")
    return task


def selection(rows, args):
    split = getattr(args, "split", "training")
    if split == "holdout" and not getattr(args, "evaluation", False):
        raise ValueError("holdout selection requires --evaluation")
    downloads = read_downloads()
    result = []
    for row in rows:
        if row.get("alias_of"):
            continue
        if split == "training" and row["split"] not in ("practice", "development"):
            continue
        if split not in ("training", "all") and row["split"] != split:
            continue
        if split == "all" and row["split"] == "holdout" and not getattr(args, "evaluation", False):
            continue
        if getattr(args, "category", None) and row["category"] != args.category:
            continue
        if getattr(args, "source", None) and row["source_id"] != args.source:
            continue
        if getattr(args, "difficulty", None) and row["difficulty"] != args.difficulty:
            continue
        if getattr(args, "kind", None) and row["content_type"] != args.kind:
            continue
        if getattr(args, "downloaded", False) and not downloads.get(row["id"], {}).get("complete"):
            continue
        query = getattr(args, "query", None)
        if query and query.casefold() not in (row["name"] + " " + row["description"] + " " + " ".join(row["tags"])).casefold():
            continue
        result.append(row)
    return result


def brief(task):
    return {key: task.get(key) for key in ("id", "name", "category", "difficulty", "content_type", "split", "practice_readiness")}


def verified_local(entry):
    relative = entry.get("local_path", "")
    if not relative or ".." in PurePosixPath(relative).parts:
        raise ValueError("invalid local handout path")
    path = (ROOT / relative).resolve()
    if not path.is_relative_to(HANDOUTS.resolve()) or not path.is_file() or path.is_symlink():
        raise ValueError("handout is missing or outside handout directory")
    if hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
        raise ValueError("handout checksum mismatch")
    return path


def solver_view(task, downloads):
    files = []
    record = downloads.get(task["id"], {})
    for item in record.get("files", []):
        path = verified_local(item)
        files.append({"name": path.name, "path": str(path), "sha256": item["sha256"], "bytes": item["bytes"]})
    description = re.sub(r"https?://[^\s<>\]\)\"]+", "[original external link; use the configured local instance]", task["description"])
    value = brief(task)
    value.update({"description": description, "tags": task["tags"], "handouts": files,
                  "handouts_complete": record.get("complete", False), "grading": task["grading"],
                  "environment_kind": task["environment"]["kind"], "runtime_verified": False,
                  "question_review_required": not bool(task["description"].strip()) or (task["content_type"] == "competition_ctf" and task.get("full_prompt_available") is False),
                  "target": "Set an explicitly authorized local instance or use your own platform lab."})
    if task["content_type"] == "online_lab" or task.get("platform_url"):
        value["platform_url"] = task.get("platform_url", task["source_url"])
    return value


def handout_url(task, asset):
    url = asset["url"]
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "raw.githubusercontent.com" or parsed.username or parsed.password or parsed.port:
        raise ValueError("only pinned public GitHub raw handouts are downloadable")
    commit = task.get("commit", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("a fixed repository commit is required")
    prefix = "/" + task["repository"] + "/" + commit + "/"
    decoded = urllib.parse.unquote(parsed.path)
    if not decoded.startswith(prefix) or ".." in PurePosixPath(decoded).parts:
        raise ValueError("handout URL does not match the fixed source")
    return url


class PublicOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme != "https" or parsed.hostname != "raw.githubusercontent.com" or parsed.username or parsed.password:
            raise ValueError("unexpected download redirect")
        return super().redirect_request(request, fp, code, message, headers, newurl)


def download_bytes(url, limit):
    opener = urllib.request.build_opener(PublicOnlyRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": "CTF-Team-Questionbank/1.0"})
    with opener.open(request, timeout=25) as response:
        size = response.headers.get("Content-Length")
        if size and int(size) > limit:
            raise ValueError("handout exceeds per-file limit")
        raw = response.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("handout exceeds per-file limit")
    return raw


def validate_archive(raw):
    """Inspect archive member names without extracting or executing any member."""
    names = []
    encrypted = set()
    try:
        if zipfile.is_zipfile(io.BytesIO(raw)):
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                members = archive.infolist()
                if len(members) > 3000: raise ValueError("archive needs review: too many entries")
                # ZIP central-directory inspection does not expand the members. Allow a
                # modest disk image, while leaving large datasets for explicit review.
                if sum(member.file_size for member in members) > 256 * 1024 * 1024 or any(member.file_size > 128 * 1024 * 1024 for member in members):
                    raise ValueError("archive expansion exceeds inspection bounds")
                names = [member.filename for member in members]
                encrypted = {member.filename for member in members if member.flag_bits & 1}
        elif raw[:2] == b"\x1f\x8b" or raw[257:262] == b"ustar":
            try:
                with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
                    expanded = 0
                    for index, member in enumerate(archive):
                        if index >= 3000: raise ValueError("archive needs review: too many entries")
                        expanded += member.size
                        if member.size > 32_000_000 or expanded > 64_000_000: raise ValueError("archive expansion exceeds inspection bounds")
                        if member.issym() or member.islnk(): raise ValueError("archive links need human review")
                        names.append(member.name)
            except tarfile.ReadError:
                pass  # A standalone gzip file is not a tar archive.
    except (zipfile.BadZipFile, EOFError, OSError) as exc:
        raise ValueError("archive structure needs human review") from exc
    for name in names:
        parts = PurePosixPath(name.replace("\\", "/")).parts
        if name.startswith(("/", "\\")) or ".." in parts or (parts and ":" in parts[0]):
            raise ValueError("archive contains an unsafe path")
        lowered = [part.casefold() for part in parts]
        if set(lowered) & {"solve", "solver", "solution", "solutions", "writeup", "writeups", "exp", "private"}:
            raise ValueError("archive contains reference material; review before downloading")
        if lowered and lowered[-1] in {"flag", "flag.txt", "flags.txt", "secret.py", "secrets.py"} and name not in encrypted:
            raise ValueError("archive includes a possible reference flag file; human review required")


def fetch_task(task, max_file_bytes=2_000_000, max_total_bytes=12_000_000):
    if task.get("public_files_need_review"):
        raise ValueError("public/private boundary has not been reviewed for this task")
    if not task["public_files"]:
        raise ValueError("no designated downloadable player handouts; use the official platform or review deployment sources")
    estimates = [asset.get("bytes") for asset in task["public_files"]]
    if any(size is not None and size > max_file_bytes for size in estimates) or sum(size or 0 for size in estimates) > max_total_bytes:
        raise ValueError("task handouts exceed the configured download limits")
    record = {"files": [], "complete": False, "downloaded_at": datetime.now(timezone.utc).isoformat()}
    total = 0
    for index, asset in enumerate(task["public_files"]):
        raw = download_bytes(handout_url(task, asset), min(max_file_bytes, max_total_bytes - total))
        blob_hash = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if blob_hash != asset["git_blob_sha1"]:
            raise ValueError("Git blob checksum mismatch")
        # Git LFS pointers are not the actual binary, and are not counted as attachments.
        if raw.startswith(b"version https://git-lfs.github.com/spec/v1"):
            raise ValueError("Git LFS pointer requires a separate reviewed asset transfer")
        if b"\0" not in raw and FLAG_RE.search(raw.decode("utf-8", "replace")):
            raise ValueError("literal flag-like text requires human handout review")
        validate_archive(raw)
        total += len(raw)
        if total > max_total_bytes:
            raise ValueError("task download exceeds total limit")
        basename = PurePosixPath(asset["path"]).name
        basename = re.sub(r"[^A-Za-z0-9._-]", "_", basename)[:100] or "handout"
        local = HANDOUTS / task["id"] / (str(index).zfill(3) + "_" + basename)
        local.parent.mkdir(parents=True, exist_ok=True)
        if local.is_symlink() or not local.resolve().is_relative_to(HANDOUTS.resolve()):
            raise ValueError("unsafe destination")
        temporary = local.with_suffix(local.suffix + ".part")
        if temporary.is_symlink():
            raise ValueError("unsafe temporary destination")
        temporary.write_bytes(raw)
        temporary.replace(local)
        record["files"].append({"local_path": local.relative_to(ROOT).as_posix(), "sha256": hashlib.sha256(raw).hexdigest(),
                                "git_blob_sha1": blob_hash, "bytes": len(raw), "upstream_path": asset["path"]})
    record["complete"] = True
    with DOWNLOAD_LOCK:
        downloads = read_downloads()
        downloads[task["id"]] = record
        write_json(DATA / "downloads.json", downloads)
    return {"id": task["id"], "files": len(record["files"]), "bytes": total, "complete": True}


def prepare_task(task, destination, allow_incomplete=False):
    view = solver_view(task, read_downloads())
    if view["question_review_required"] and not allow_incomplete:
        raise ValueError("clean prompt is unavailable; review the original question before preparing this task")
    if task["public_files"] and not view["handouts_complete"] and not allow_incomplete:
        raise ValueError("download all declared player handouts before preparing this task")
    out = Path(destination).resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError("prepare destination must be new or empty")
    out.mkdir(parents=True, exist_ok=True)
    public = out / "attachments"
    public.mkdir(exist_ok=True)
    for entry in view["handouts"]:
        source = Path(entry["path"])
        shutil.copyfile(source, public / entry["name"])
        entry["path"] = "attachments/" + entry["name"]
    write_json(out / "task.json", view)
    (out / "README.md").write_text("# " + task["name"] + "\n\n" + view["description"] + "\n\nLocal target: set an authorized instance.\n", encoding="utf-8")
    return {"id": task["id"], "task_directory": str(out), "attachments": len(view["handouts"])}


def add_filters(parser):
    parser.add_argument("--category", choices=CATEGORIES)
    parser.add_argument("--source")
    parser.add_argument("--difficulty")
    parser.add_argument("--kind", choices=("competition_ctf", "guided_exercise", "online_lab"))
    parser.add_argument("--split", choices=("training", "practice", "development", "holdout", "all"), default="training")
    parser.add_argument("--evaluation", action="store_true")
    parser.add_argument("--downloaded", action="store_true")
    parser.add_argument("--query")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("stats")
    search = sub.add_parser("search"); add_filters(search); search.add_argument("--limit", type=int, default=20)
    pick = sub.add_parser("pick"); add_filters(pick); pick.add_argument("--count", type=int, default=6); pick.add_argument("--seed", default="team-1")
    show = sub.add_parser("show"); show.add_argument("id"); show.add_argument("--evaluation", action="store_true")
    fetch = sub.add_parser("fetch"); fetch.add_argument("id"); fetch.add_argument("--evaluation", action="store_true")
    fetch.add_argument("--max-file-mb", type=float, default=2); fetch.add_argument("--max-total-mb", type=float, default=12)
    prepare = sub.add_parser("prepare"); prepare.add_argument("id"); prepare.add_argument("--out", required=True)
    prepare.add_argument("--evaluation", action="store_true"); prepare.add_argument("--allow-incomplete", action="store_true")
    record = sub.add_parser("record"); record.add_argument("id"); record.add_argument("--evaluation", action="store_true")
    record.add_argument("--outcome", choices=("solved_self_reported", "failed", "blocked_environment", "blocked_question"), required=True)
    record.add_argument("--minutes", type=int); record.add_argument("--notes", default="")
    args = parser.parse_args(argv)
    try:
        rows = load_rows()
        if args.command == "stats":
            canonical = [row for row in rows if not row.get("alias_of")]
            value = {"records": len(rows), "canonical_records": len(canonical), "families": len({row["family_key"] for row in canonical}),
                     "categories": dict(Counter(row["category"] for row in canonical)), "content_types": dict(Counter(row["content_type"] for row in canonical)),
                     "splits": dict(Counter(row["split"] for row in canonical)), "complete_downloads": sum(v.get("complete", False) for v in read_downloads().values()),
                     "runtime_verified": 0, "solving_verified": 0}
        elif args.command in ("search", "pick"):
            candidates = selection(rows, args)
            if args.command == "pick":
                random.Random(args.seed).shuffle(candidates)
                seen = set(); unique = []
                for task in candidates:
                    if task["family_key"] not in seen:
                        unique.append(task); seen.add(task["family_key"])
                value = [brief(task) for task in unique[:max(0, args.count)]]
            else:
                value = {"matched": len(candidates), "items": [brief(task) for task in candidates[:max(0, args.limit)]]}
        else:
            task = require_task(rows, args.id, args.evaluation)
            if args.command == "show": value = solver_view(task, read_downloads())
            elif args.command == "fetch": value = fetch_task(task, int(args.max_file_mb * 1_000_000), int(args.max_total_mb * 1_000_000))
            elif args.command == "prepare": value = prepare_task(task, args.out, args.allow_incomplete)
            else:
                if FLAG_RE.search(args.notes): raise ValueError("record notes must not contain reference flags")
                value = {"id": task["id"], "at": datetime.now(timezone.utc).isoformat(), "outcome": args.outcome,
                         "minutes": args.minutes, "notes": args.notes, "independently_verified": False}
                with (ROOT / "practice-results.jsonl").open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(value, ensure_ascii=False) + "\n")
        print(json.dumps(value, ensure_ascii=False, indent=2))
        return 0
    except (ValueError, OSError, KeyError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
