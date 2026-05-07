<p align="center">
  <img src="driftmux.png" alt="Driftmux logo" width="320">
</p>

<p align="center">
  <a href="https://pypi.org/project/driftmux/">
    <img alt="PyPI Version" src="https://img.shields.io/pypi/v/driftmux">
  </a>
  <a href="https://pypi.org/project/driftmux/">
    <img alt="Python Version" src="https://img.shields.io/pypi/pyversions/driftmux">
  </a>
  <a href="https://github.com/aidaph/driftmux/actions/workflows/ci.yml">
    <img alt="CI" src="https://github.com/aidaph/driftmux/actions/workflows/ci.yml/badge.svg">
  </a>
  <a href="https://github.com/aidaph/driftmux/blob/main/LICENSE">
    <img alt="License" src="https://img.shields.io/badge/license-Apache-2.0-blue.svg">
  </a>
</p>

<p align="center">
  <strong>Black-box service discovery, classification, and adaptive scan routing</strong>
</p>

---

**Driftmux** is a black-box auditing tool focused on **service discovery, classification, and adaptive scan routing**.

It starts by probing a target surface, identifies exposed services and technologies, and then routes each finding to the most suitable scanner. Instead of treating every host the same way, Driftmux adapts its scanning workflow based on what it discovers.

For example:

- generic network discovery with **Nmap**
- web and exposed service vulnerability checks with **Nuclei**
- WordPress-specific assessment with **Plecost**

Driftmux is designed as an **orchestrator**, not as a monolithic scanner.

---

## Features

- Black-box service discovery
- Technology-aware scan routing
- Structured output for automation and CI
- Multiple output formats
- Modular scanner integration
- Lightweight CLI workflow
- Extensible architecture for new service detectors and scanners

---

## Why driftmux?

Many security tools are powerful but noisy. driftmux focuses on orchestration and correlation: it uses existing tools, normalizes their output and decides what should run next.

| Feature | driftmux | Raw Nmap | Raw Nuclei | Full scanners |
|---|---:|---:|---:|---:|
| Service discovery | Yes | Yes | No | Yes |
| Version/CPE parsing | Yes | Yes | No | Yes |
| Vulnerability enrichment | Yes | No | Template-based | Yes |
| Targeted Nuclei execution | Yes | No | Manual | Varies |
| Scan planning | Yes | No | No | Varies |
| Lower-noise profiles | Yes | Manual | Manual | Varies |
| Structured final report | Yes | XML/text | JSONL/text | Varies |
| Lightweight and scriptable | Yes | Yes | Yes | Often heavier |

driftmux is not a replacement for Nmap, Nuclei or dedicated scanners. It is a thin coordination layer that makes them easier to combine.

## How it works

Driftmux follows a simple pipeline:

1. **Discover** exposed ports and services
2. **Classify** detected applications and technologies
3. **Route** targets to specialized scanners
4. **Aggregate** findings into a common data model
5. **Render** results as console output, JSON, CSV, or Markdown

Example routing logic:

- WordPress detected → **Plecost**
- HTTP/HTTPS services detected → **Nuclei**
- Generic open ports detected → **Nmap fingerprints**


## Installation

### Requirements

- Python 3.10+
- `nmap`
- `nuclei`
- `plecost`

### Clone the repository

```bash
git clone https://github.com/<your-user>/driftmux.git
cd driftmux
```

### Install the Python package

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### External tools

Depending on the features you use, install Nmap:

```bash
sudo apt install nmap
```

Nuclei and Plecost are optional, but required for their respective checks.
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
pip install plecost

```


## Usage

Basic scan:

```bash
driftmux --host example.org
```

Scan a specific IP:

```bash
driftmux --host 193.146.75.190
```

Scan known ports:

```bash
driftmux --host example.org --ports 80,443,8443
```

Run with NVD enrichment:

```bash
driftmux --host example.org \
  --vuln-backend nvd \
  --min-cvss 7.0
```

Run a fast profile:

```bash
driftmux --host example.org --profile fast
```

Run a passive profile:

```bash
driftmux --host example.org --profile passive
```

## Example output

```text
$ driftmux --host 205.87.65.183  --profile passive   --vuln-backend nvd   --min-cvss 7.0
[205.87.65.183]
Services: 1 | Findings: 4 | Errors: 1
  - 22/tcp     ssh          OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 [ssh]
  * CRITICAL nvd: CVE-2008-3844 affects OpenSSH
  * HIGH nvd: CVE-2024-6387 affects OpenSSH
  * HIGH nvd: CVE-2026-35385 affects OpenSSH
  * HIGH nvd: CVE-2023-51767 affects OpenSSH

Saved report to reports/driftmux-report.json
```

When Nmap can identify product, version or CPE information, driftmux can use that evidence to enrich findings through vulnerability backends such as NVD.

If a service is reported as `tcpwrapped`, driftmux can still report the exposed port, but it may not have enough evidence to map it to a specific vulnerable product.

---

## Scan profiles

| Profile | Purpose | Active checks |
|---|---|---:|
| `passive` | Conservative discovery and enrichment | No |
| `passive + NVD` | Conservative discovery and enrichment | Yes |
| `fast` | Practical day-to-day checks | Limited |
| `deep` | Broader authorized assessment | More extensive |

Use `passive` for low-noise review, `fast` for regular checks and `deep` only when you have explicit authorization for a more complete assessment.

---

## Roadmap

Planned or possible improvements:

- OS detection support from Nmap XML;
- clearer handling of `tcpwrapped` services;
- improved Nuclei target planning;
- richer JSON and HTML reports;
- optional SARIF export;
- better test coverage for planners and scanners.

---

## Disclaimer

driftmux is provided for defensive and authorized security work only. You are responsible for complying with all applicable laws, regulations and rules of engagement.

