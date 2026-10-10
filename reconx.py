#!/usr/bin/env python3
"""Vidyexd ReconX — bounded public-surface inventory for authorized security work."""
from __future__ import annotations
import argparse, csv, ipaddress, json, re, socket, sys, time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse, urldefrag
import xml.etree.ElementTree as ET
import requests
from bs4 import BeautifulSoup

VERSION = "1.2.0"
UA = f"VidyexdReconX/{VERSION} (public-surface inventory; contact site owner before active use)"
TIMEOUT = 10
DELAY = 0.7
MAX_BODY = 1_000_000
SECURITY_HEADERS = ["strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy"]


def normalize_domain(value: str) -> str:
    value = value.strip().lower()
    if "://" in value:
        value = urlparse(value).hostname or ""
    else:
        value = value.split("/")[0].split(":")[0]
    value = value.rstrip(".")
    if not value or len(value) > 253 or "." not in value:
        raise ValueError("Enter a domain such as example.com")
    labels = value.split(".")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels):
        raise ValueError("Invalid domain format")
    return value


def host_is_public(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        ips = {x[4][0].split("%")[0] for x in infos}
        return bool(ips) and all(ipaddress.ip_address(ip).is_global for ip in ips)
    except (OSError, ValueError):
        return False


def in_scope(host: str | None, root: str, include_subdomains: bool) -> bool:
    host = (host or "").lower().rstrip(".")
    return host == root or (include_subdomains and host.endswith("." + root))


def clean_url(value: str) -> str | None:
    try:
        p = urlparse(value.strip())
        if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
            return None
        return urldefrag(value.strip())[0]
    except ValueError:
        return None


def session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept": "text/html,application/xml,text/xml,*/*;q=0.8"})
    return s


def ct_subdomains(domain: str, s: requests.Session) -> tuple[list[str], str]:
    found = {domain}
    try:
        r = s.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=20)
        r.raise_for_status()
        for cert in r.json():
            for raw in cert.get("name_value", "").splitlines():
                name = raw.lower().strip().lstrip("*.").rstrip(".")
                if (name == domain or name.endswith("." + domain)) and re.fullmatch(r"[a-z0-9.-]+", name):
                    found.add(name)
        return sorted(found), "ok"
    except (requests.RequestException, ValueError) as e:
        return sorted(found), f"unavailable: {type(e).__name__}"


def safe_get(s: requests.Session, url: str):
    """No redirects; only retrieve URLs after checking the destination host resolves publicly."""
    p = urlparse(url)
    if not p.hostname or not host_is_public(p.hostname):
        return None
    return s.get(url, timeout=TIMEOUT, allow_redirects=False, stream=True)


def passive_urls(domain: str, s: requests.Session) -> tuple[set[str], list[dict]]:
    origin = f"https://{domain}"
    found: set[str] = set()
    notes = []
    robots_url = origin + "/robots.txt"
    try:
        with safe_get(s, robots_url) as r:
            if r is not None and r.status_code == 200:
                body = r.raw.read(MAX_BODY, decode_content=True).decode("utf-8", "replace")
                for line in body.splitlines():
                    key, sep, val = line.partition(":")
                    if sep and key.strip().lower() == "sitemap":
                        u = clean_url(val.strip())
                        if u and urlparse(u).hostname == domain:
                            found.add(u)
                notes.append({"source": "robots.txt", "status": r.status_code})
            elif r is not None:
                notes.append({"source": "robots.txt", "status": r.status_code})
    except requests.RequestException as e:
        notes.append({"source": "robots.txt", "error": type(e).__name__})
    candidates = {origin + "/sitemap.xml", *found}
    for sitemap in list(candidates):
        try:
            with safe_get(s, sitemap) as r:
                if r is None or r.status_code != 200:
                    continue
                body = r.raw.read(MAX_BODY, decode_content=True).decode("utf-8", "replace")
                try:
                    root = ET.fromstring(body)
                    for elem in root.iter():
                        if elem.tag.lower().endswith("loc") and elem.text:
                            u = clean_url(elem.text.strip())
                            if u and urlparse(u).hostname == domain:
                                found.add(u)
                except ET.ParseError:
                    notes.append({"source": sitemap, "note": "invalid XML"})
        except requests.RequestException as e:
            notes.append({"source": sitemap, "error": type(e).__name__})
        time.sleep(DELAY)
    return found, notes


def crawl(start: str, root: str, s: requests.Session, max_pages: int, max_depth: int, include_subdomains: bool) -> list[dict]:
    q = deque([(start, 0)])
    seen: set[str] = set()
    rows: list[dict] = []
    while q and len(seen) < max_pages:
        url, depth = q.popleft()
        url = clean_url(url)
        if not url or url in seen:
            continue
        p = urlparse(url)
        if not in_scope(p.hostname, root, include_subdomains) or not host_is_public(p.hostname or ""):
            continue
        seen.add(url)
        row = {"url": url, "status": "", "content_type": "", "location": "", "title": "", "security_headers_missing": "", "note": ""}
        try:
            with s.get(url, timeout=TIMEOUT, allow_redirects=False, stream=True) as r:
                row["status"] = r.status_code
                row["content_type"] = r.headers.get("Content-Type", "")
                row["location"] = r.headers.get("Location", "")
                missing = [h for h in SECURITY_HEADERS if not r.headers.get(h)]
                row["security_headers_missing"] = ";".join(missing)
                print(f"[{r.status_code}] {url}")
                if r.status_code == 200 and depth < max_depth and "text/html" in row["content_type"].lower():
                    body = r.raw.read(MAX_BODY, decode_content=True).decode("utf-8", "replace")
                    soup = BeautifulSoup(body, "html.parser")
                    if soup.title:
                        row["title"] = soup.title.get_text(" ", strip=True)[:250]
                    for tag in soup.find_all("a", href=True):
                        link = clean_url(urljoin(url, tag.get("href", "")))
                        if link and in_scope(urlparse(link).hostname, root, include_subdomains) and link not in seen:
                            q.append((link, depth + 1))
        except requests.RequestException as e:
            row["note"] = type(e).__name__
            print(f"[ERR] {url}: {row['note']}")
        rows.append(row)
        time.sleep(DELAY)
    return rows


def write_reports(out_dir: Path, stem: str, data: dict, http_rows: list[dict]):
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{stem}.json").write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / f"{stem}_subdomains.txt").write_text("\n".join(data["subdomains"]) + "\n", encoding="utf-8")
    (out_dir / f"{stem}_urls.txt").write_text("\n".join(data["passive_urls"]) + ("\n" if data["passive_urls"] else ""), encoding="utf-8")
    fields = ["url", "status", "content_type", "location", "title", "security_headers_missing", "note"]
    with (out_dir / f"{stem}_http.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(http_rows)


def main():
    p = argparse.ArgumentParser(description="Vidyexd ReconX — public-surface inventory for authorized security work")
    p.add_argument("domain", help="Domain to inventory, e.g. example.com")
    p.add_argument("--active", action="store_true", help="Crawl pages and record HTTP status/security-header presence (authorization required)")
    p.add_argument("--include-subdomains", action="store_true", help="Include discovered subdomains in active crawl (requires --active)")
    p.add_argument("--max-pages", type=int, default=50, help="Maximum pages per crawl, 1–200 (default: 50)")
    p.add_argument("--max-depth", type=int, default=2, help="Link depth, 0–5 (default: 2)")
    p.add_argument("--out", default="", help="Optional report filename prefix")
    p.add_argument("--reports-dir", default="reports", help="Report output folder (default: reports)")
    args = p.parse_args()
    try: domain = normalize_domain(args.domain)
    except ValueError as e: p.error(str(e))
    if not 1 <= args.max_pages <= 200: p.error("--max-pages must be between 1 and 200")
    if not 0 <= args.max_depth <= 5: p.error("--max-depth must be between 0 and 5")
    if args.include_subdomains and not args.active: p.error("--include-subdomains requires --active")
    s = session()
    print("\033[93m")
    print("██╗   ██╗██╗██████╗ ██╗   ██╗███████╗██╗  ██╗██████╗")
    print("╚██╗ ██╔╝██║██╔══██╗╚██╗ ██╔╝██╔════╝╚██╗██╔╝██╔══██╗")
    print(" ╚████╔╝ ██║██║  ██║ ╚████╔╝ █████╗   ╚███╔╝ ██║  ██║")
    print("  ╚██╔╝  ██║██║  ██║  ╚██╔╝  ██╔══╝   ██╔██╗ ██║  ██║")
    print("   ██║   ██║██████╔╝   ██║   ███████╗██╔╝ ██╗██████╔╝")
    print("   ╚═╝   ╚═╝╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝╚═════╝")
    print("                 R E C O N X")
    print("\033[0m")
    print(f"Vidyexd ReconX v{VERSION} | Website Reconnaissance Tool")
    print("MADE BY AashishRaazKumar")
    print("=" * 64)
    print(f"Target: {domain}\nMode: {'PASSIVE + ACTIVE' if args.active else 'PASSIVE DISCOVERY'}")
    if not host_is_public(domain):
        print("[!] Domain does not resolve exclusively to public IP addresses. Web requests skipped.")
        subs, ct_state, urls, notes, rows = [domain], "not checked", set(), [], []
    else:
        subs, ct_state = ct_subdomains(domain, s)
        if ct_state != "ok": print(f"[!] Certificate Transparency lookup {ct_state}; continuing with available data.")
        print(f"\n[+] Certificate names collected: {len(subs)}")
        for h in subs: print(f"    {h}")
        urls, notes = passive_urls(domain, s)
        print(f"\n[+] Same-host sitemap URLs collected: {len(urls)}")
        rows = []
        if args.active:
            targets = [f"https://{h}" for h in subs] if args.include_subdomains else [f"https://{domain}"]
            for target in targets:
                print(f"\n[*] Authorized crawl: {target}")
                rows.extend(crawl(target, domain, s, args.max_pages, args.max_depth, args.include_subdomains))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", Path(args.out).name) if args.out else f"{domain}_{stamp}"
    data = {"tool": "Vidyexd ReconX", "version": VERSION, "target": domain, "mode": "passive+active" if args.active else "passive", "generated_utc": datetime.now(timezone.utc).isoformat(), "certificate_transparency": ct_state, "subdomains": subs, "passive_urls": sorted(urls), "discovery_notes": notes, "http_results": rows}
    write_reports(Path(args.reports_dir), stem, data, rows)
    print(f"\n[+] Reports saved to: {Path(args.reports_dir).resolve()}")
    print("[+] Finished. Discovery is not exhaustive; missing headers are observations, not proof of a vulnerability.")
    print("\033[93mMADE BY AashishRaazKumar | Vidyexd · Explore • Learn • Achieve\033[0m")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt:
        print("\n[!] Stopped by user."); sys.exit(130)
