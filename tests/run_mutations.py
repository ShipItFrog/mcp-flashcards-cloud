"""Prove the test suite catches real mistakes: run it once per deliberately broken
variant (tests/mutations.py) and require at least one test to FAIL each time.

A run that errors during setup (e.g. a mutation that no longer applies) does not
count as caught: it is reported as invalid.

Usage:  python tests/run_mutations.py
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "tests"), str(ROOT)]
from mutations import MUTATIONS  # noqa: E402


def run(mutation: str | None) -> tuple[int, str, list[str]]:
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    env.pop("FLASHCARDS_MUTATION", None)
    if mutation:
        env["FLASHCARDS_MUTATION"] = mutation
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-rf"],
        cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    summary = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else "(no output)"
    failed = sorted(set(re.findall(r"^FAILED (\S+?)(?:\[| - |$)", r.stdout, re.MULTILINE)))
    return r.returncode, summary, failed


def main() -> int:
    code, summary, _ = run(None)
    print(f"baseline (real code): {summary}")
    if code != 0:
        print("baseline must pass first")
        return 1
    problems = []
    for name in MUTATIONS:
        code, summary, failed = run(name)
        if "error" in summary:
            status = "INVALID (errors, not failures)"
        elif code == 1 and failed:
            status = "CAUGHT"
        else:
            status = "NOT CAUGHT"
        print(f"\n{name}: {status} - {summary}")
        for test in failed:
            print(f"    {test}")
        if status != "CAUGHT":
            problems.append(name)
    print("\nall mutations caught" if not problems else f"\nnot caught or invalid: {problems}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
