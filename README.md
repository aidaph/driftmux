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

## Install the Python package

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

