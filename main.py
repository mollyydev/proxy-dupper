import argparse
import asyncio
import ipaddress
from dataclasses import dataclass

import httpx
from loguru import logger

TEST_URL = "http://httpbin.org/ip"
DEFAULT_TIMEOUT = 8.0


@dataclass(frozen=True)
class ProxySeed:
    auth: str
    network_prefix: str
    port: int


def parse_proxy_line(line: str) -> tuple[str, str, int]:
    """Parses `login:password@ip:port` and returns (auth, ip, port)."""
    raw = line.strip()
    if not raw:
        raise ValueError("empty line")

    if "@" not in raw:
        raise ValueError(f"invalid proxy format: {raw}")

    auth, host_port = raw.rsplit("@", 1)
    if ":" not in host_port:
        raise ValueError(f"missing port: {raw}")

    ip_text, port_text = host_port.rsplit(":", 1)

    try:
        ipaddress.IPv4Address(ip_text)
    except ipaddress.AddressValueError as exc:
        raise ValueError(f"invalid IPv4: {ip_text}") from exc

    try:
        port = int(port_text)
    except ValueError as exc:
        raise ValueError(f"invalid port: {port_text}") from exc

    if not (1 <= port <= 65535):
        raise ValueError(f"port out of range: {port}")

    return auth, ip_text, port


def build_seeds(lines: list[str]) -> list[ProxySeed]:
    """
    Builds unique seeds by /24 network.
    If lines contain same first three octets, only first one is used.
    """
    seeds: list[ProxySeed] = []
    seen_prefixes: set[str] = set()

    for idx, line in enumerate(lines, start=1):
        text = line.strip()
        if not text:
            continue
        try:
            auth, ip_text, port = parse_proxy_line(text)
        except ValueError as err:
            logger.warning("line {} skipped: {}", idx, err)
            continue

        octets = ip_text.split(".")
        prefix = ".".join(octets[:3])

        if prefix in seen_prefixes:
            continue

        seen_prefixes.add(prefix)
        seeds.append(ProxySeed(auth=auth, network_prefix=prefix, port=port))

    return seeds


def generate_candidates(seeds: list[ProxySeed]) -> list[str]:
    """Generates proxies for each seed by replacing last octet with 0..255."""
    candidates: list[str] = []
    for seed in seeds:
        for last_octet in range(256):
            ip_text = f"{seed.network_prefix}.{last_octet}"
            candidates.append(f"{seed.auth}@{ip_text}:{seed.port}")
    return candidates


async def check_proxy(
    proxy_line: str, protocol: str, timeout: float, test_url: str
) -> bool:
    proxy_url = f"{protocol}://{proxy_line}"
    try:
        async with httpx.AsyncClient(
            proxy=proxy_url,
            timeout=timeout,
            follow_redirects=True,
        ) as client:
            response = await client.get(test_url)
            return response.status_code == 200
    except Exception:
        return False


async def run_check(
    candidates: list[str],
    protocol: str,
    workers: int,
    output_path: str,
    timeout: float,
    test_url: str,
) -> None:
    total = len(candidates)
    checked = 0
    valid_count = 0
    semaphore = asyncio.Semaphore(workers)

    async def run_one(proxy: str) -> tuple[str, bool]:
        async with semaphore:
            return proxy, await check_proxy(proxy, protocol, timeout, test_url)

    tasks = [asyncio.create_task(run_one(proxy)) for proxy in candidates]

    with open(output_path, "w", encoding="utf-8") as output_file:
        for task in asyncio.as_completed(tasks):
            proxy, is_valid = await task
            checked += 1

            if is_valid:
                output_file.write(proxy + "\n")
                output_file.flush()
                valid_count += 1
                logger.success("valid {}", proxy)

            if checked % 50 == 0 or checked == total:
                logger.info("checked {}/{}; valid: {}", checked, total, valid_count)

    logger.info("done; total checked: {}, valid found: {}", total, valid_count)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Checks generated proxy IPs in /24 range and saves valid ones."
    )
    parser.add_argument("-i", "--input", required=True, help="Path to input proxies file")
    parser.add_argument("-o", "--output", required=True, help="Output file for valid proxies")
    parser.add_argument(
        "-p",
        "--protocol",
        default="http",
        choices=["http", "socks5"],
        help="Proxy protocol (default: http)",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=10,
        help="Async concurrency limit (default: 10)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--test-url",
        default=TEST_URL,
        help=f"URL to test proxy connectivity (default: {TEST_URL})",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.workers < 1:
        raise SystemExit("workers must be >= 1")

    with open(args.input, "r", encoding="utf-8") as f:
        lines = f.readlines()

    seeds = build_seeds(lines)
    if not seeds:
        logger.info("no valid input proxies to process")
        return

    candidates = generate_candidates(seeds)
    logger.info("unique /24 seeds: {}", len(seeds))
    logger.info("candidates to check: {}", len(candidates))

    asyncio.run(
        run_check(
            candidates=candidates,
            protocol=args.protocol,
            workers=args.workers,
            output_path=args.output,
            timeout=args.timeout,
            test_url=args.test_url,
        )
    )


if __name__ == "__main__":
    main()
