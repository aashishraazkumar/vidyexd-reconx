# Vidyexd ReconX

**Public-surface inventory for authorized security work**  
Version 1.2.0 · Parrot OS / Debian / Ubuntu · Python 3

![Vidyexd ReconX black-and-gold banner](vidyexd-reconx-banner.png)

**MADE BY AashishRaazKumar**

Vidyexd ReconX is a small command-line helper for gathering public certificate-transparency names, sitemap URLs, and (when explicitly enabled) a bounded inventory of HTTP responses. It exports JSON, CSV, and text reports.

## Features

- Public Certificate Transparency lookup through crt.sh (service may be temporarily unavailable).
- Same-host `robots.txt` and XML sitemap URL collection.
- Optional bounded HTML link crawl with HTTP status, response content type, redirect location, page title, and a snapshot of common security-header presence.
- JSON, CSV, and text reports.
- No login attempts, password guessing, exploit payloads, or automatic redirect following.
- XML parsing uses Python's standard library; no separate `lxml` install is required.

## Install on Parrot OS

Open a terminal in the extracted folder and run:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip unzip
chmod +x install.sh run.sh
./install.sh
```

The installer creates a local `.venv` and installs only the packages in `requirements.txt`.

## Run it

Passive discovery (still makes a small number of ordinary requests to the domain's public robots/sitemap endpoints):

```bash
./run.sh example.com
```

Replace `example.com` with a domain you own or are authorized to assess. To inventory your own Vidyexd domain, for example:

```bash
./run.sh vidyexd.in
```

Bounded active crawl — **only on a site you own or have explicit permission to test**:

```bash
./run.sh yourdomain.com --active --max-pages 50 --max-depth 2
```

Include discovered subdomains only when your authorization covers them:

```bash
./run.sh yourdomain.com --active --include-subdomains --max-pages 30
```

Useful options:

```bash
./run.sh --help
./run.sh yourdomain.com --out my_audit
./run.sh yourdomain.com --active --reports-dir my_reports
```

## Reports

Reports are saved in `reports/` by default:

- `*_subdomains.txt` — certificate names collected.
- `*_urls.txt` — same-host URLs found from public sitemap sources.
- `*_http.csv` — HTTP response observations (empty of scan rows in passive mode).
- `*.json` — combined machine-readable report and discovery notes.

## Troubleshooting

- **`externally-managed-environment`**: run `./install.sh`; do not use system-wide `sudo pip`.
- **`ModuleNotFoundError`**: `source .venv/bin/activate && python -m pip install -r requirements.txt`.
- **crt.sh 502 / unavailable**: the external service may be down or rate-limiting. The tool continues with whatever data it has.
- **No sitemap URLs**: the website may not publish a sitemap or may use a different sitemap location.
- **DNS/public-IP warning**: the tool skips web requests if the hostname does not resolve exclusively to globally routable IPs.

## Safety and limits

Use only for assets you own or are explicitly authorized to assess. Active crawling is rate-limited and capped. It does not bypass authentication or access controls. DNS and web data can change between checks; results are incomplete by design. A missing security header is only an observation and is not, by itself, proof of a vulnerability. Review scope and local laws/policies before testing.

**MADE BY AashishRaazKumar**  
**Vidyexd · Explore • Learn • Achieve**
