"""Process-execution and concurrency helpers shared across the network app."""

import json
import subprocess
from concurrent.futures import ThreadPoolExecutor

DEFAULT_TIMEOUT_S = 10


def run_result(command: str, args: list[str], timeout: float = DEFAULT_TIMEOUT_S) -> subprocess.CompletedProcess | None:
    """Runs a command and returns its CompletedProcess (any exit code), or
    None if the binary is missing or the call times out. The one place that
    actually shells out — run()/run_ok() below cover the two common ways
    callers want the result read; a caller that needs the exit code itself
    (nmap's raw-privileges check) uses this directly."""
    try:
        return subprocess.run([command, *args], capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def run(command: str, args: list[str], timeout: float = DEFAULT_TIMEOUT_S) -> str:
    """Runs a command and returns its stdout, even on a non-zero exit — ping's
    summary line still matters at 100% loss. "" if the binary is missing or
    the call times out."""
    result = run_result(command, args, timeout=timeout)
    return result.stdout if result else ""


def run_ok(command: str, args: list[str], timeout: float = DEFAULT_TIMEOUT_S) -> str | None:
    """Like run(), but None (not partial stdout) on a non-zero exit — for
    commands where failure genuinely means "no result", unlike ping above."""
    result = run_result(command, args, timeout=timeout)
    return result.stdout if result and result.returncode == 0 else None


def run_json(command: str, args: list[str], timeout: float = DEFAULT_TIMEOUT_S):
    """Runs a command that prints JSON on stdout (iproute2's `-j`) and parses it."""
    stdout = run_ok(command, args, timeout=timeout)
    trimmed = (stdout or "").strip()
    if not trimmed:
        return None
    try:
        return json.loads(trimmed)
    except json.JSONDecodeError:
        return None


def normalize_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    return mac.replace("-", ":").lower()


def run_parallel(*fns):
    """Runs each zero-arg callable in its own thread and returns results in
    call order — Python stand-in for `Promise.all` over blocking I/O work
    (pings, socket probes, subprocess calls)."""
    with ThreadPoolExecutor(max_workers=len(fns)) as pool:
        futures = [pool.submit(fn) for fn in fns]
        return [f.result() for f in futures]
