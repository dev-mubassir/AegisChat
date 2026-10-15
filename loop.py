#!/usr/bin/env python3
"""Run PROMPT.md in a loop with Claude Code until the app is built, reviewed and checked.

  python loop.py            up to 10 runs in this session
  python loop.py --max 4    only 4 runs now; run it again later (progress lives in the files)

The loop ends when DONE exists AND this script's own final checks pass.
It also stops on BLOCKED.md, 3 failed runs in a row, 3 runs with no progress,
a plan usage limit, or when the estimated budget for this session is used up.
Exit codes: 0 finished, 1 session limit reached, 2 blocked, 3 failures or usage limit,
4 no progress, 5 budget reached.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# Ensure Flutter is in PATH if installed in standard location
if sys.platform == "win32" and Path(r"C:\src\flutter\bin").exists():
    if r"C:\src\flutter\bin" not in os.environ.get("PATH", ""):
        os.environ["PATH"] = r"C:\src\flutter\bin;" + os.environ.get("PATH", "")

ROOT = Path(__file__).resolve().parent
LOGS = ROOT / "logs"

BUILD_MODEL = "sonnet"
REVIEW_MODEL = "sonnet"   # try "opus" for the final security review if your plan allows it
MAX_TURNS = 80            # agent turns per run
MAX_USD_PER_RUN = 3.0     # estimated cost cap per run (client-side estimate, not your bill)
RUN_TIMEOUT_MIN = 45

ALLOWED = ["Read", "Edit", "Write", "Glob", "Grep"]
for _tool in ("Bash", "PowerShell"):  # Windows may use PowerShell instead of Bash
    for _cmd in ("git status", "git diff", "git log", "git init", "git add", "git commit",
                 "git restore", "git stash", "git mv", "git rm",
                 "python", "pip", "pytest", "ruff", "bandit", "pip-audit", "flutter", "dart"):
        ALLOWED.append(f"{_tool}({_cmd} *)")


def run(cmd, cwd=ROOT, timeout=None, text_in=None):
    kw = {"input": text_in} if text_in is not None else {"stdin": subprocess.DEVNULL}
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout, **kw)


def show_login(claude):
    """Print how Claude Code is logged in, so you know if the loop uses your plan or pay-per-token."""
    try:
        method = json.loads(run([claude, "auth", "status"], timeout=60).stdout).get("authMethod", "unknown")
    except Exception:
        method = "unknown"
    print(f"Claude login type: {method}")
    if method == "none":
        sys.exit("Not logged in. Run: claude auth login")
    if method in ("api_key", "api_key_helper", "third_party"):
        print("WARNING: this login is billed per token. A long loop can cost real money.")
        try:
            answer = input("Continue? [y/N] ")
        except EOFError:
            answer = "n"
        if answer.strip().lower() != "y":
            sys.exit(0)


def open_tasks():
    text = (ROOT / "TASKS.md").read_text(encoding="utf-8")
    return len(re.findall(r"^- \[ \]", text, re.M))


def progress_marker():
    head = ""
    if (ROOT / ".git").exists():
        head = run(["git", "rev-parse", "HEAD"]).stdout.strip()
    return hashlib.sha1(head.encode() + (ROOT / "TASKS.md").read_bytes()).hexdigest()


def gate_steps():
    py, flutter = sys.executable, shutil.which("flutter")
    return [
        ("server tests", [py, "-m", "pytest", "-q"], ROOT / "server"),
        ("flutter analyze", [flutter, "analyze"], ROOT / "app"),
        ("flutter test", [flutter, "test"], ROOT / "app"),
        ("crypto lint", [py, "tools/crypto_lint.py"], ROOT),
        ("secret scan", [py, "tools/scan_secrets.py"], ROOT),
        ("platform flags", [py, "tools/check_platform_flags.py"], ROOT),
        ("cross-language crypto check", [py, "tools/xcheck.py"], ROOT),
        ("end-to-end test", [py, "tools/e2e.py"], ROOT),
    ]


def gate():
    """Final checks run by THIS script, so the result does not depend on what the agent claims."""
    print("\nDONE found. Running the final checks myself (not trusting the agent)...")
    failed = None
    if not (ROOT / "FINAL_REPORT.md").exists():
        failed = ("final report", "DONE was created but FINAL_REPORT.md is missing.")
    else:
        for name, cmd, cwd in gate_steps():
            print(f"  - {name} ... ", end="", flush=True)
            if cmd[0] is None:
                print("FAILED")
                failed = (name, "Command not found on PATH.")
                break
            try:
                r = run(cmd, cwd=cwd, timeout=20 * 60)
                ok, out = r.returncode == 0, r.stdout + r.stderr
            except Exception as e:  # missing folder, timeout, ...
                ok, out = False, str(e)
            print("ok" if ok else "FAILED")
            if not ok:
                failed = (name, out[-3000:])
                break
    if failed is None:
        return True
    LOGS.mkdir(exist_ok=True)
    n = len(list(LOGS.glob("gate-failure-*.txt"))) + 1
    log = LOGS / f"gate-failure-{n:02d}.txt"
    log.write_text(f"{failed[0]}\n\n{failed[1]}", encoding="utf-8")
    with open(ROOT / "TASKS.md", "a", encoding="utf-8") as f:
        f.write(f"\n- [ ] GATE-{n:02d} Fix the failed final check: {failed[0]}\n"
                f"  Do: read `logs/{log.name}`, fix the real cause (not the test), keep every other check green.\n"
                f"  Check: the command that failed now passes.\n")
    (ROOT / "DONE").unlink(missing_ok=True)
    print(f"  Final check failed: {failed[0]}. Added task GATE-{n:02d} and removed DONE.")
    return False


def run_agent(claude, model):
    cmd = [claude, "-p", "--output-format", "json", "--model", model,
           "--permission-mode", "acceptEdits",
           "--allowedTools", ",".join(ALLOWED),
           "--max-turns", str(MAX_TURNS),
           "--max-budget-usd", str(MAX_USD_PER_RUN)]
    prompt = (ROOT / "PROMPT.md").read_text(encoding="utf-8")
    try:
        r = run(cmd, timeout=RUN_TIMEOUT_MIN * 60, text_in=prompt)
    except subprocess.TimeoutExpired:
        return 124, "timeout", 0.0
    LOGS.mkdir(exist_ok=True)
    (LOGS / datetime.now().strftime("run-%m%d-%H%M%S-%f.txt")).write_text(
        r.stdout + "\n--- stderr ---\n" + r.stderr, encoding="utf-8")
    text, cost = (r.stdout or r.stderr)[-500:], 0.0
    try:
        data = json.loads(r.stdout)
        text, cost = data.get("result") or text, float(data.get("total_cost_usd") or 0)
    except (ValueError, TypeError, AttributeError):
        pass
    return r.returncode, text, cost


def finish():
    print("\nFINISHED. The final checks passed on this machine.")
    lines = (ROOT / "FINAL_REPORT.md").read_text(encoding="utf-8").splitlines()
    print("\n--- FINAL_REPORT.md (first 40 lines) ---")
    print("\n".join(lines[:40]))
    print("\nNext: do the steps in MANUAL_CHECKS.md on a real phone. Those parts cannot be tested here.")
    return 0


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--max", type=int, default=10, help="max runs in this session (default 10)")
    ap.add_argument("--budget", type=float, default=30.0,
                    help="stop after this estimated USD in this session (default 30)")
    args = ap.parse_args()

    claude = shutil.which("claude")
    if not claude:
        sys.exit("Claude Code not found on PATH. Install it, then run: claude auth login")
    for name in ("PROMPT.md", "TASKS.md"):
        if not (ROOT / name).exists():
            sys.exit(f"Missing {name} next to loop.py")
    show_login(claude)

    if (ROOT / "DONE").exists() and gate():
        return finish()

    spent, fails, same, last = 0.0, 0, 0, progress_marker()
    for n in range(1, args.max + 1):
        if (ROOT / "BLOCKED.md").exists():
            print("\nBLOCKED.md exists. Read it, fix the cause, delete the file, then run again.")
            return 2
        left = open_tasks()
        mode, model = ("review", REVIEW_MODEL) if left == 0 else ("build", BUILD_MODEL)
        print(f"\n=== Run {n}/{args.max} | {mode} | {left} task(s) open | {model} ===", flush=True)
        started = time.time()
        code, text, cost = run_agent(claude, model)
        spent += cost
        m = re.search(r"RESULT:\s*(\S+)\s+(PASS|FAIL|BLOCKED)", text)
        print(f"    exit {code} | {time.time() - started:.0f}s | est. ${cost:.2f} "
              f"(session total ${spent:.2f}) | {m.group(0) if m else 'no RESULT line'}", flush=True)

        if (ROOT / "DONE").exists() and gate():
            return finish()
        if (ROOT / "BLOCKED.md").exists():
            print("\nThe agent wrote BLOCKED.md. Read it, fix the cause, delete the file, then run again.")
            return 2
        fails = fails + 1 if code != 0 else 0
        if code != 0 and re.search(r"(session|usage|rate) limit", text, re.I):
            print("\nLooks like a plan usage limit. Wait for the reset, then run again (progress is saved).")
            return 3
        if fails >= 3:
            print("\n3 failed runs in a row. Check logs/. Causes: login, plan limit, or a task too big "
                  "(split it in TASKS.md).")
            return 3
        marker = progress_marker()
        same = same + 1 if marker == last else 0
        last = marker
        if same >= 3:
            print("\nNo progress in 3 runs (no commit, no ticked task). Stopping. Read CONTEXT.md and logs/.")
            return 4
        if spent >= args.budget:
            print(f"\nEstimated spend ${spent:.2f} reached the budget. Run again to continue.")
            return 5
    print("\nReached --max for this session. Run again to continue; progress is saved in TASKS.md and git.")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nStopped by you. Progress is saved; run again to continue.")
        sys.exit(130)
