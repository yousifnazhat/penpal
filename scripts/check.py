from __future__ import annotations

import subprocess
import sys


CHECKS = (
    (sys.executable, "-m", "ruff", "check", "."),
    (sys.executable, "-m", "ruff", "format", "--check", "."),
    (sys.executable, "-m", "unittest", "discover", "-v"),
    (sys.executable, "-m", "penpal", "playbooks", "playbooks"),
    (sys.executable, "scripts/release_check.py"),
)


def main() -> int:
    for command in CHECKS:
        print(f"+ {' '.join(command)}", flush=True)
        completed = subprocess.run(command, check=False)
        if completed.returncode:
            return completed.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
