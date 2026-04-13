# Probe Tool

Lightweight multithreaded reconnaissance utility for **authorized security testing, lab practice, and networking research**.

## Overview

Probe Tool is a Python command-line project built to perform three practical reconnaissance tasks:

- **Subdomain enumeration** using a wordlist and HTTP probing
- **TCP port scanning** with optional banner grabbing
- **Directory bruteforcing** against a target web application

The project is designed to be simple to run, easy to understand, and strong enough to showcase practical cybersecurity and Python development skills in a portfolio.

> Use this tool only on systems you own or are explicitly authorized to assess.

## Features

- Clean CLI interface using `argparse`
- Multithreaded execution with `ThreadPoolExecutor`
- Retry-aware HTTP requests using `requests` and `urllib3`
- Wordlist-driven recon workflow
- JSON and CSV export support
- Hostname to IP resolution for port scanning
- Banner grabbing for basic service identification
- Organized project structure for learning and extension

## Project Structure

```text
probe-tool/
├── probe.py
├── README.md
├── requirements.txt
├── .gitignore
└── wordlists/
    ├── dirs.txt
    └── subs.txt
```

## Installation

```bash
git clone https://github.com/Legion-02/probe-tool.git
cd probe-tool
python -m venv venv
```

### Windows

```bash
venv\Scripts\activate
pip install -r requirements.txt
```

### Linux / Kali

```bash
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

Show help:

```bash
python probe.py --help
```

### 1. Subdomain Enumeration

```bash
python probe.py subs example.com -w wordlists/subs.txt
```

Export results:

```bash
python probe.py subs example.com --json-out output/subdomains.json --csv-out output/subdomains.csv
```

### 2. Port Scanning

Scan default common ports:

```bash
python probe.py ports scanme.nmap.org
```

Scan specific ports:

```bash
python probe.py ports scanme.nmap.org -p 22,80,443 -v
```

Disable banner grabbing:

```bash
python probe.py ports scanme.nmap.org --no-banners
```

### 3. Directory Bruteforce

```bash
python probe.py dirs http://example.com -w wordlists/dirs.txt
```

Export results:

```bash
python probe.py dirs http://example.com --json-out output/dirs.json --csv-out output/dirs.csv
```

## Example Output

### Port Scan

```text
========== Port Scan ==========
45.33.32.156:22
80.33.32.156:80
45.33.32.156:443
```

### Directory Bruteforce

```text
========== Directory Bruteforce ==========
http://example.com/admin
http://example.com/login
http://example.com/robots.txt
```

## Skills Demonstrated

This project highlights:

- Python scripting for security automation
- Networking fundamentals and socket programming
- Concurrent execution for faster scanning
- HTTP response handling and retry logic
- File export for reporting and automation workflows
- CLI application design and input validation

## Why This Project Is Valuable

Probe Tool is a practical project for aspiring SOC analysts, blue team learners, and cybersecurity beginners because it demonstrates hands-on understanding of how reconnaissance works at a technical level while keeping the implementation readable and modular.

It can also be extended later with:

- DNS record lookups
- WHOIS support
- Service fingerprinting improvements
- HTML report generation
- Passive recon sources

## Safe Use Note

This tool is meant for:

- Personal lab environments
- CTFs and training ranges
- Security research with permission
- Educational demonstrations

Do not use it against third-party infrastructure without explicit authorization.

## Resume-Friendly Project Description

**Probe Tool** is a Python-based reconnaissance utility developed for authorized security testing and lab-based research. It performs subdomain enumeration, TCP port scanning, banner grabbing, and directory bruteforcing using multithreading and retry-aware HTTP requests. The project demonstrates practical knowledge of networking, sockets, concurrent execution, structured output generation, and security-focused CLI tool development.

## Author

**Anush**  
Cyber Security Enthusiast
