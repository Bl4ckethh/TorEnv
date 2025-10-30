# TorEnv – Anonymous OSINT Research Tool

**Fast, Safe, Multi-Instance Tor Proxy with Automatic IP Rotation**  
**Kali Linux Ready** | **pip installable**

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

### Cookie/Control Port Hang? (Fixed!)

**Old issue**: Waits 60s on non-Kali distros (group/login needed).  
**Now fixed**: Uses **password auth** (`HashedControlPassword`).  

- No re-login  
- No group add  
- Works on **Kali, Fedora, Arch, Ubuntu, FreeBSD**

**Test**:
```bash
./torenv.py

---

## Installation

### Option 1: From GitHub (Recommended)

```bash
git clone https://github.com/bl4ckethh/torenv.git
cd torenv
python3 -m venv venv
source venv/bin/activate
pip install -e .
chmod +x torenv.py
./torenv.py

---
