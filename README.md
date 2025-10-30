# TorEnv – Anonymous OSINT Research Tool

**Fast, Safe, Multi-Instance Tor Proxy with Automatic IP Rotation**  
**Kali Linux Ready** | **pip installable**

[![PyPI version](https://badge.fury.io/py/torenv.svg)](https://badge.fury.io/py/torenv)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow)](LICENSE)

---

## Features

- Auto-install & configure Tor
- **Multi-instance rotation** → new IP every request
- Block detection (403/429/CAPTCHA) → auto-rotate
- DNS leak-proof (`socks5h://`)
- CLI + Python API
- No `NEWNYM` spam

---

## Installation

### Option 1: From GitHub (Recommended)

```bash
git clone https://github.com/bl4ckethh/torenv.git
cd torenv
pip install -e .
