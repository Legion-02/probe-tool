#!/usr/bin/env python3
"""
Probe Tool — Lightweight reconnaissance utility
Use only on systems you own or have explicit permission to test.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable, List, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------- Config & Setup ---------------------------- #

DEFAULT_COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 8080, 8443]
REQUEST_TIMEOUT = 4.0
MAX_WORKERS = 32

logger = logging.getLogger("probe")


def session_with_retries() -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=3, backoff_factor=0.3,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "HEAD"])
    )
    s.headers.update({"User-Agent": "ProbeTool/1.0 (+for authorized testing)"})
    s.mount("http://", HTTPAdapter(max_retries=retries))
    s.mount("https://", HTTPAdapter(max_retries=retries))
    return s


# ---------------------------- Utilities ---------------------------- #

def read_wordlist(path: Path) -> List[str]:
    words: List[str] = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.strip().strip("/")
            if w and not w.startswith("#"):
                words.append(w)
    return words


def is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


# ---------------------------- Features ---------------------------- #

def subdomain_enum(domain: str, words: Iterable[str]) -> List[str]:
    found: List[str] = []
    sess = session_with_retries()

    def try_sub(sub: str) -> Optional[str]:
        url = f"http://{sub}.{domain}"
        try:
            r = sess.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            # Consider anything not NXDOMAIN/connection error as "alive"
            if r.status_code < 500:
                return url
        except requests.RequestException:
            pass
        return None

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(try_sub, w): w for w in words}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                logger.info("[+] Subdomain: %s", res)
                found.append(res)
    return sorted(set(found))


def scan_port(host: str, port: int, timeout: float = 0.6) -> Optional[int]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                return port
    except OSError:
        pass
    return None


def port_scan(host: str, ports: Iterable[int]) -> List[int]:
    open_ports: List[int] = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(scan_port, host, p): p for p in ports}
        for fut in as_completed(futures):
            res = fut.result()
            if res is not None:
                logger.info("[+] Open port %d on %s", res, host)
                open_ports.append(res)
    return sorted(open_ports)


def banner_grab(host: str, port: int) -> Optional[str]:
    try:
        with socket.socket() as s:
            s.settimeout(1.5)
            s.connect((host, port))
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
            data = s.recv(2048)
            return data.decode(errors="ignore").strip()
    except OSError:
        return None


def dir_bruteforce(base_url: str, words: Iterable[str]) -> List[str]:
    found: List[str] = []
    sess = session_with_retries()

    def try_path(p: str) -> Optional[str]:
        url = f"{base_url.rstrip('/')}/{p}"
        try:
            r = sess.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
            if r.status_code in (200, 204, 301, 302, 307, 308, 401, 403):
                return url
        except requests.RequestException:
            pass
        return None

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(try_path, w): w for w in words}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                logger.info("[+] Path: %s", res)
                found.append(res)
    return sorted(set(found))


# ---------------------------- Output Helpers ---------------------------- #

def save_json(path: Path, data: Dict) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def save_csv(path: Path, rows: List[Dict[str, str]], fieldnames: List[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)


# ---------------------------- CLI ---------------------------- #

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="probe",
        description="Probe Tool — Lightweight reconnaissance utility (authorized use only)."
    )
    p.add_argument("--verbose", "-v", action="count", default=0, help="Increase verbosity (-v, -vv).")

    sub = p.add_subparsers(dest="cmd", required=True)

    # Subdomains
    sp = sub.add_parser("subs", help="Enumerate subdomains")
    sp.add_argument("domain", help="Target domain, e.g., example.com")
    sp.add_argument("--wordlist", "-w", type=Path, default=Path("wordlists/subs.txt"))

    # Ports
    pp = sub.add_parser("ports", help="Scan common TCP ports and grab banners")
    pp.add_argument("host", help="Target host/IP")
    pp.add_argument("--ports", "-p", help="Comma-separated list (e.g., 22,80,443)")
    pp.add_argument("--no-banners", action="store_true", help="Skip banner grabbing")

    # Dirs
    dp = sub.add_parser("dirs", help="Bruteforce directories/paths on a base URL")
    dp.add_argument("url", help="Base URL, e.g., http://example.com")
    dp.add_argument("--wordlist", "-w", type=Path, default=Path("wordlists/dirs.txt"))

    # Output
    for subp in (sp, pp, dp):
        subp.add_argument("--json-out", type=Path, help="Write results to JSON file")
        subp.add_argument("--csv-out", type=Path, help="Write results to CSV file (where applicable)")

    return p.parse_args()


def main() -> None:
    args = parse_args()

    # Logging level
    level = logging.WARNING
    if args.verbose == 1:
        level = logging.INFO
    elif args.verbose >= 2:
        level = logging.DEBUG
    logging.basicConfig(format="%(message)s", level=level)

    if args.cmd == "subs":
        words = read_wordlist(args.wordlist)
        results = subdomain_enum(args.domain, words)
        for s in results:
            print(s)
        payload = {"domain": args.domain, "found": results}
        if args.json_out:
            save_json(args.json_out, payload)
        if args.csv_out:
            rows = [{"domain": args.domain, "subdomain": s} for s in results]
            save_csv(args.csv_out, rows, ["domain", "subdomain"])

    elif args.cmd == "ports":
        if args.ports:
            ports = [int(x) for x in args.ports.split(",") if x.strip().isdigit()]
        else:
            ports = DEFAULT_COMMON_PORTS
        target = args.host
        if not is_ip(target):
            target = socket.gethostbyname(target)

        open_ports = port_scan(target, ports)
        results = []
        for pnum in open_ports:
            banner = None if args.no_banners else banner_grab(target, pnum)
            results.append({"host": target, "port": pnum, "banner": banner})
            out = f"{target}:{pnum}"
            if banner and args.verbose:
                out += f"  |  {banner.splitlines()[0][:120]}"
            print(out)

        if args.json_out:
            save_json(args.json_out, {"host": target, "results": results})
        if args.csv_out:
            save_csv(args.csv_out, results, ["host", "port", "banner"])

    elif args.cmd == "dirs":
        words = read_wordlist(args.wordlist)
        hits = dir_bruteforce(args.url, words)
        for h in hits:
            print(h)
        if args.json_out:
            save_json(args.json_out, {"base_url": args.url, "found": hits})
        if args.csv_out:
            rows = [{"base_url": args.url, "path": h} for h in hits]
            save_csv(args.csv_out, rows, ["base_url", "path"])


if __name__ == "__main__":
    main()
