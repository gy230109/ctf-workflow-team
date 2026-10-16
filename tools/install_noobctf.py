"""Install a pinned, reference-only NoobCTF Git object store and local text index.

Run with ``python tools/install_noobctf.py``. Downloaded solvers are never run.
Existing repositories with another origin, revision, or local changes are kept.
"""
import argparse
from contextlib import contextmanager
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid


BASE = Path(__file__).resolve().parents[1]
UPSTREAM = "https://github.com/Lo4pca/NoobCTF.git"
PINNED_COMMIT = "0d9d8721f1c86f6529363fc63a6b915a1073ff77"
MARKER = "ctf-system-noobctf.json"
EXPECTED_MARKER = {"origin": UPSTREAM, "commit": PINNED_COMMIT,
                   "storage": "git-objects-no-checkout-v1"}


def _git(*args, timeout=180, input_text=None):
    environment = dict(os.environ, GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="Never")
    result = subprocess.run(
        ["git", "-c", "credential.interactive=false", *map(str, args)],
        capture_output=True, timeout=timeout, env=environment,
        input=input_text.encode("utf-8") if input_text is not None else None,
    )
    if result.returncode:
        # Git stderr may echo a user's credential-bearing URL. Do not echo it.
        raise RuntimeError("Git operation failed (exit %d); check Git/network locally; "
                           "no existing repository was reset." % result.returncode)
    return result.stdout.decode("utf-8", errors="replace").strip()


def _official(url):
    return url.rstrip("/") in (UPSTREAM, UPSTREAM[:-4])


def _keep_existing(reason):
    raise ValueError(
        reason + " Existing files were retained. Back up and inspect this directory; "
        "move it aside manually if a separate pinned reference install is wanted. "
        "This installer never resets, checks out, or overwrites an existing repository."
    )


def verify_repository(repo):
    """Accept a clean checkout or an unchanged installer-owned object store."""
    if repo.is_symlink() or not repo.is_dir() or not (repo / ".git").is_dir() or (repo / ".git").is_symlink():
        _keep_existing("NoobCTF target is not a standalone Git repository.")
    # Validate both the stored origin and the effective URL after Git rewrites.
    if not _official(_git("-C", repo, "config", "--get", "remote.origin.url")) or not _official(
            _git("-C", repo, "remote", "get-url", "origin")):
        _keep_existing("NoobCTF origin does not match the fixed official repository.")
    if _git("-C", repo, "rev-parse", "HEAD") != PINNED_COMMIT:
        _keep_existing("NoobCTF HEAD differs from the pinned commit " + PINNED_COMMIT + ".")
    marker = repo / ".git" / MARKER
    if marker.exists():
        try:
            valid_marker = json.loads(marker.read_text(encoding="utf-8")) == EXPECTED_MARKER
        except (ValueError, OSError):
            valid_marker = False
        if not valid_marker:
            _keep_existing("NoobCTF object-store marker changed.")
        # --no-checkout deliberately has no index/worktree; missing files are not
        # deletions to repair. Any subsequently added files or index are changes.
        if (repo / ".git" / "index").exists() or any(p.name != ".git" for p in repo.iterdir()):
            _keep_existing("NoobCTF object store has local working-tree or index changes.")
    elif _git("-C", repo, "status", "--porcelain", "--untracked-files=all", "--ignore-submodules=none"):
        _keep_existing("NoobCTF repository has local modifications or untracked files.")


@contextmanager
def _install_lock(parent):
    lock = parent / ".noobctf-install.lock"
    try:
        lock.mkdir()
    except FileExistsError:
        raise RuntimeError("Another NoobCTF installation is active, or a previous run stopped. "
                           "Inspect references/.noobctf-install.lock before removing that lock.") from None
    try:
        yield
    finally:
        lock.rmdir()


def _download(repo):
    staging = repo.parent / (".noobctf-download-" + uuid.uuid4().hex)
    try:
        _git("clone", "--filter=blob:none", "--depth", "1", "--no-checkout", UPSTREAM, staging)
        if _git("-C", staging, "rev-parse", "HEAD") != PINNED_COMMIT:
            _git("-C", staging, "fetch", "--depth", "1", "origin", PINNED_COMMIT)
            # This is only the newly created staging clone; no existing repo is
            # ever moved to another commit, and no source files are checked out.
            _git("-C", staging, "update-ref", "HEAD", PINNED_COMMIT)
        (staging / ".git" / MARKER).write_text(
            json.dumps(EXPECTED_MARKER, indent=2) + "\n", encoding="utf-8")
        verify_repository(staging)
        staging.rename(repo)
    finally:
        if staging.exists():
            # Only remove the unique staging directory created by this call.
            if staging.resolve().parent != repo.parent.resolve() or not staging.name.startswith(".noobctf-download-"):
                raise RuntimeError("Unexpected staging path; cleanup refused")
            shutil.rmtree(staging)


def _prefetch_text(repo, suffixes):
    # Partial clones otherwise lazily fetch each blob in a separate network
    # request. Fetch only the reference text objects together, without checkout.
    tree = _git("-C", repo, "ls-tree", "-rz", "HEAD")
    objects = set()
    for record in tree.split("\0"):
        if not record:
            continue
        metadata, relative = record.split("\t", 1)
        fields = metadata.split()
        if fields[1] == "blob" and Path(relative).suffix.lower() in suffixes and (
                relative == "README.md" or relative.startswith(("CTF/", "笔记/"))):
            objects.add(fields[2])
    if not objects:
        raise RuntimeError("The pinned NoobCTF tree contains no expected reference texts")
    _git("-C", repo, "-c", "fetch.negotiationAlgorithm=noop", "fetch", "origin", "--no-tags",
         "--no-write-fetch-head", "--recurse-submodules=no", "--filter=blob:none", "--stdin",
         input_text="\n".join(sorted(objects)) + "\n", timeout=300)


def install(root=BASE, reference_module=None):
    root = Path(root).resolve()
    parent = root / "references"
    parent.mkdir(parents=True, exist_ok=True)
    repo = parent / "noobctf"
    with _install_lock(parent):
        reused = repo.exists()
        if reused:
            verify_repository(repo)
        else:
            _download(repo)
        if reference_module is None:
            sys.path.insert(0, str(root / "tools"))
            reference_module = importlib.import_module("ctf_reference_sources")
        spec, configured_repo, index = reference_module.locations("noobctf")
        if Path(configured_repo).resolve() != repo or not _official(spec["url"]):
            raise ValueError("ctf_reference_sources is not configured for this local NoobCTF install")
        current = reference_module.status("noobctf")
        index_reused = current.get("ready") is True and current.get("commit") == PINNED_COMMIT
        if not index_reused:
            _prefetch_text(repo, reference_module.TEXT_SUFFIXES)
        result = current if index_reused else reference_module.build("noobctf")
        if result.get("ready") is not True or result.get("commit") != PINNED_COMMIT:
            raise RuntimeError("NoobCTF index did not confirm the pinned revision")
        verify_repository(repo)
    return dict(result, installed=True, repository_reused=reused, index_reused=index_reused,
                executes_source=False, trusted_instructions=False,
                usage="kb_search/kb_read source=noobctf allow_reference=true; reference learning only")


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        result = install()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False, indent=2))
        return 1
    print(json.dumps({"ok": True, **result}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
