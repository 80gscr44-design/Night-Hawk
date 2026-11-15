import asyncio
import time
import sys
import aiohttp

RED = "\033[1;31m"
RESET = "\033[0m"

def rprint(*args, sep=" ", end="\n"):
    """print(), but everything comes out bold red."""
    print(RED + sep.join(str(a) for a in args) + RESET, end=end)

async def worker(session, queue, stats, target_url):
    while not queue.empty():
        try:
            queue.get_nowait()
        except asyncio.QueueEmpty:
            break

        try:
            async with session.get(target_url) as response:
                await response.read()  # Drain response payload
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
            queue.task_done()

async def live_monitor(stats, stop_event, target_url):
    """Prints live stats every second with requested prefixes."""
    while not stop_event.is_set():
        await asyncio.sleep(1)
        t_stamp = time.strftime("%H:%M:%S")
        succ = stats["this_second_success"]
        fail = stats["this_second_failed"]

        rprint(f"[+] TIME: {t_stamp} | [+] URL: {target_url} | Success/sec: {succ} | Failed/sec: {fail} | Total OK: {stats['success']}")

        # Reset per-second counters
        stats["this_second_success"] = 0
        stats["this_second_failed"] = 0

async def main():
    # ASCII Art Banner
    rprint(r"""
      :::::::::  :::::::::  :::::::::
     :+:    :+: :+:    :+: :+:    :+:
    +:+    +:+ +:+    +:+ +:+
   +#+    +:+ +#+    +#+ +#++:++#++
  +#+    +#+ +#+    +#+        +#+
 #+#    #+# #+#    #+# #+#    #+#
#########   ########   ########      """)


    # Interactive configuration prompts


    user_url = input(f"{RED}Enter target URL: {RESET}").strip()
    target_url = user_url if user_url else default_url

    default_concurrency = 300
    user_concurrency = input(f"{RED}Enter concurrency strength (Press Enter for default [{default_concurrency}]): {RESET}").strip()
    concurrency = int(user_concurrency) if user_concurrency.isdigit() else default_concurrency

    default_total = 50000
    user_total = input(f"{RED}Enter total requests pool size (Press Enter for default [{default_total}]): {RESET}").strip()
    total_requests = int(user_total) if user_total.isdigit() else default_total

    queue = asyncio.Queue()
    for _ in range(total_requests):
        queue.put_nowait(1)

    stats = {
        "success": 0,
        "failed": 0,
        "this_second_success": 0,
        "this_second_failed": 0
    }

    stop_event = asyncio.Event()

    connector = aiohttp.TCPConnector(
        limit=concurrency,
        limit_per_host=concurrency,
        keepalive_timeout=60,
        ttl_dns_cache=300
    )

    rprint(f"\n[+] Starting Load Test...")
    rprint(f"[+] URL: {target_url}")
    rprint(f"[+] Strength (Concurrency): {concurrency} workers | Target Volume: {total_requests} requests\n")

    start_time = time.perf_counter()

    async with aiohttp.ClientSession(connector=connector) as session:
        # Start background monitor printer
        monitor_task = asyncio.create_task(live_monitor(stats, stop_event, target_url))

        # Start worker tasks
        workers = [asyncio.create_task(worker(session, queue, stats, target_url)) for _ in range(concurrency)]

        await queue.join()
        stop_event.set()
        await monitor_task

    elapsed = time.perf_counter() - start_time
    total_sent = stats["success"] + stats["failed"]
    rps = total_sent / elapsed if elapsed > 0 else 0

    rprint("\n================ BENCHMARK FINISHED ================")
    rprint(f"[+] TIME: {time.strftime('%H:%M:%S')}")
    rprint(f"Total Requests Completed: {total_sent}")
    rprint(f"Time Taken:               {elapsed:.2f} seconds")
    rprint(f"Requests Per Second:      {rps:.2f} RPS")
    rprint(f"Successful (HTTP 2xx/3xx):{stats['success']}")
    rprint(f"Failed / Connection Errs: {stats['failed']}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        rprint("\n[!] Test aborted by user.")
        sys.exit(0)
