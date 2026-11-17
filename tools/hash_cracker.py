#!/usr/bin/env python3
# ============================================================
#  Night-Hawk :: Wordlist Hash Cracker (./nh Suite Edition)
#  Block 1/2: Imports, paths, bold-red output, ASCII art, options
# ============================================================
import hashlib
import mmap
import os
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path

RED = "\033[1;31m"
RST = "\033[0m"

HERE = Path(__file__).resolve().parent
SUITE_ROOT = HERE.parent if HERE.name == "tools" else HERE
OUT_DIR = SUITE_ROOT / "reports"

ART = (
    "     #####    ##                        /        ###          ##     \n"
    "  ######  /  #### /                   #/        /####       ####  /  \n"
    " /#   /  /   ####/                    ##       /   ###      /####/   \n"
    "/    /  /    # #                      ##            ###    /   ##    \n"
    "    /  /     #                        ##             ###  /          \n"
    "   ## ##     #      /###      /###    ##  /##         ###/           \n"
    "   ## ##     #     / ###  /  / #### / ## / ###         ###           \n"
    "   ## ########    /   ###/  ##  ###/  ##/   ###        /###          \n"
    "   ## ##     #   ##    ##  ####       ##     ##       /  ###         \n"
    "   ## ##     ##  ##    ##    ###      ##     ##      /    ###        \n"
    "   ## ##     ##  ##    ##      ###    ##     ##     /      ###       \n"
    "   ##  |      ## ##    ##        ###  ##     ##    /        ###      \n"
    "   ##  |      ## ##    /#   /###  ##  ##     ##   /          ###   / \n"
    "   #####       ## ####/ ## / #### /   ##     ##  /            ####/  \n"
    "   ## ##           ###   ##   ###/    ##     ## /              ###   \n"
    "                                                                     \n"
    "                                                                     \n"
    "                                                                     \n"
)

OPTIONS = {
    "1": ("sha256", hashlib.sha256, 64),
    "2": ("md5", hashlib.md5, 32),
    "3": ("sha1", hashlib.sha1, 40),
}

REPORT_STEP = 250_000


def rprint(msg: str, stream=sys.stdout) -> None:
    for line in str(msg).splitlines():
        stream.write(f"{RED}{line}{RST}\n")
    stream.flush()


def rprompt(label: str) -> str:
    sys.stdout.write(f"{RED}{label}{RST}")
    sys.stdout.flush()
    return input().strip()


def physical_cores() -> int:
    try:
        import psutil
        n = psutil.cpu_count(logical=False)
        if n and n > 0:
            return n
    except Exception:
        pass

    try:
        if sys.platform.startswith("linux"):
            pairs = set()
            phys, core = "0", None
            with open("/proc/cpuinfo", "r") as fh:
                for line in fh:
                    if line.startswith("physical id"):
                        phys = line.split(":", 1)[1].strip()
                    elif line.startswith("core id"):
                        core = line.split(":", 1)[1].strip()
                    elif not line.strip():
                        if core is not None:
                            pairs.add((phys, core))
                        phys, core = "0", None
            if pairs:
                return len(pairs)

            per_socket, sockets = 0, 1
            with open("/proc/cpuinfo", "r") as fh:
                for line in fh:
                    if line.startswith("cpu cores"):
                        per_socket = max(per_socket, int(line.split(":", 1)[1]))
                    elif line.startswith("physical id"):
                        sockets = max(sockets, int(line.split(":", 1)[1]) + 1)
            if per_socket:
                return per_socket * sockets

        elif sys.platform == "darwin":
            out = subprocess.check_output(["sysctl", "-n", "hw.physicalcpu"], timeout=5)
            n = int(out.strip())
            if n > 0:
                return n

        elif sys.platform == "win32":
            probes = (
                ["powershell", "-NoProfile", "-Command",
                 "(Get-CimInstance Win32_Processor).NumberOfCores"],
                ["wmic", "cpu", "get", "NumberOfCores"],
            )
            for cmd in probes:
                try:
                    out = subprocess.check_output(
                        cmd, stderr=subprocess.DEVNULL, timeout=10
                    ).decode(errors="ignore")
                    nums = [int(t) for t in out.replace("NumberOfCores", " ").split()
                            if t.isdigit()]
                    if nums:
                        return sum(nums)
                except Exception:
                    continue
    except Exception:
        pass

    return os.cpu_count() or 4


def _worker_batch(
    lines: list[bytes], algo_name: str, target_hex: str
) -> tuple[str | None, int, str]:
    hash_fn = getattr(hashlib, algo_name)
    last_hash = ""
    tested = 0
    for raw in lines:
        word = raw.rstrip(b"\r\n")
        if not word:
            continue
        tested += 1
        digest = hash_fn(word).hexdigest()
        last_hash = digest
        if digest == target_hex:
            return word.decode("utf-8", errors="replace"), tested, digest
    return None, tested, last_hash

# ============================================================
#  Night-Hawk :: Wordlist Hash Cracker (./nh Suite Edition)
#  Block 2/2: Chunked mmap reader, 250k progress log, run()
# ============================================================
def iter_wordlist_batches(wordlist_path: str, batch_size: int = 32768):
    with open(wordlist_path, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            batch = []
            for line in iter(mm.readline, b""):
                batch.append(line)
                if len(batch) >= batch_size:
                    yield batch
                    batch = []
            if batch:
                yield batch


def crack_with_wordlist(
    algo_name: str,
    target_hash: str,
    wordlist_path: str,
    workers: int | None = None,
    concurrency: str = "process",
    batch_size: int = 32768,
) -> tuple[str | None, int, float]:
    target_hex = target_hash.strip().lower()
    cpu_workers = workers or physical_cores()
    pool_cls = ThreadPoolExecutor if concurrency == "thread" else ProcessPoolExecutor

    rprint(f"[*] Algorithm: {algo_name.upper()} | Workers: {cpu_workers} | Concurrency: {concurrency}")
    rprint("[*] Cracking started...\n")

    start = time.perf_counter()
    checked = 0
    next_log = REPORT_STEP
    found = None

    with pool_cls(max_workers=cpu_workers) as pool:
        pending = []
        max_inflight = cpu_workers * 4

        for batch in iter_wordlist_batches(wordlist_path, batch_size=batch_size):
            pending.append(pool.submit(_worker_batch, batch, algo_name, target_hex))
            if len(pending) >= max_inflight:
                done_fut = pending.pop(0)
                match, count, cur_hash = done_fut.result()
                checked += count
                if checked >= next_log:
                    elapsed_so_far = max(time.perf_counter() - start, 1e-9)
                    rate_so_far = int(checked / elapsed_so_far)
                    rprint(f"Log | Attemps/sec:{rate_so_far} | Current Hash: {cur_hash}")
                    while checked >= next_log:
                        next_log += REPORT_STEP
                if match is not None:
                    found = match
                    for fut in pending:
                        fut.cancel()
                    break

        if found is None:
            for fut in pending:
                match, count, cur_hash = fut.result()
                checked += count
                if checked >= next_log:
                    elapsed_so_far = max(time.perf_counter() - start, 1e-9)
                    rate_so_far = int(checked / elapsed_so_far)
                    rprint(f"Log | Attemps/sec:{rate_so_far} | Current Hash: {cur_hash}")
                    while checked >= next_log:
                        next_log += REPORT_STEP
                if match is not None:
                    found = match
                    break

    elapsed = max(time.perf_counter() - start, 1e-9)
    return found, checked, elapsed


def run() -> None:
    rprint(ART)
    print()
    rprint("[+] 1: SHA256")
    rprint("[+] 2: MD5")
    rprint("[+] 3: SHA1")
    print()

    try:
        choice = rprompt("Option: ")
        if choice not in OPTIONS:
            rprint("[!] Invalid option. Choose 1, 2, or 3.")
            return

        algo_name, _, expected_len = OPTIONS[choice]
        target_hash = rprompt("Hash: ").lower()
        wordlist_path = rprompt("Wordlist: ")
    except EOFError:
        return

    if not target_hash or not wordlist_path:
        rprint("[!] Hash and Wordlist are both required.")
        return

    if len(target_hash) != expected_len or not all(
        c in "0123456789abcdef" for c in target_hash
    ):
        rprint(f"[!] Invalid {algo_name.upper()} hex hash.")
        return

    if not os.path.isfile(wordlist_path):
        rprint(f"[!] Wordlist not found: {wordlist_path}")
        return

    real_cores = physical_cores()
    try:
        raw_cores = rprompt(f"CPU cores [{real_cores}]: ")
    except EOFError:
        raw_cores = ""

    if raw_cores == "":
        cores = real_cores
    else:
        try:
            cores = max(1, int(raw_cores))
        except ValueError:
            cores = real_cores

    try:
        rprompt("Concurrency: ")
    except EOFError:
        pass
    concurrency = "process"

    try:
        secret, checked, elapsed = crack_with_wordlist(
            algo_name, target_hash, wordlist_path, cores, concurrency
        )
    except KeyboardInterrupt:
        rprint("\n[!] Interrupted by user.")
        return

    rate = checked / elapsed
    print()
    if secret is not None:
        rprint(f"[+] CRACKED: {secret}")
    else:
        rprint("[-] Not found in wordlist.")
    rprint(
        f"[*] Checked {checked:,} candidates in {elapsed:.2f}s ({rate:,.0f} hashes/sec)"
    )


def main() -> None:
    try:
        run()
    except KeyboardInterrupt:
        rprint("\n[!] Interrupted.")


if __name__ == "__main__":
    main()

