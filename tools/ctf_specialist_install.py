"""Team CTF workflow component. See README.md for configuration and verified scope."""
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import venv

PACKAGES = ["lief", "angr<10", "bitstring<5", "fpylll", "cysignals", "volatility3", "pwntools",
            "pycryptodome", "pillow", "scapy", "playwright", "beautifulsoup4",
            "requests", "sympy", "z3-solver"]


def main():
    case = Path(os.environ["CTF_CASE_DIR"]).resolve()
    env = case.parents[1] / ".venv-specialists"
    work = case / "work"
    receipt = work / "specialists-install.json"
    record = {"started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "status": "running", "venv": str(env), "packages": PACKAGES,
              "core_environment_changed": False}
    receipt.write_text(json.dumps(record, indent=2), encoding="utf-8")
    with (work/"specialists-install.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if not (env/"bin/python3").is_file():
            venv.EnvBuilder(with_pip=True, symlinks=True).create(env)
        cmd = [str(env/"bin/python3"), "-m", "pip", "install", "--prefer-binary",
               "--index-url", os.environ.get("CTF_SPECIALIST_INDEX", "https://pypi.org/simple"),
               "--disable-pip-version-check", "--timeout", "25", "--retries", "2",
               "--report", str(work/"specialists-pip-report.json"), *PACKAGES]
        try:
            result = subprocess.run(cmd, timeout=1800)
            record.update(status="installed" if result.returncode == 0 else "failed",
                          returncode=result.returncode)
            if result.returncode == 0:
                subprocess.run([str(env/"bin/python3"), "-m", "pip", "freeze"],
                               stdout=(work/"specialists-freeze.txt").open("w"), check=True)
                check = subprocess.run([str(env/"bin/python3"), "-m", "pip", "check"],
                                       capture_output=True, text=True)
                record.update(pip_check=check.stdout.strip(), pip_check_exit=check.returncode)
        except subprocess.TimeoutExpired:
            record.update(status="timeout", returncode=124)
        except Exception as exc:
            record.update(status="failed", error=str(exc))
    record["finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    receipt.write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(json.dumps(record))
    return 0 if record["status"] == "installed" else 1


if __name__ == "__main__":
    sys.exit(main())
