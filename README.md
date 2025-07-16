# HunterForge

```
▗▖ ▗▖█  ▐▌▄▄▄▄     ■  ▗▞▀▚▖ ▄▄▄ ▗▄▄▄▖ ▄▄▄   ▄▄▄  ▗▞▀▚▖
▐▌ ▐▌▀▄▄▞▘█   █ ▗▄▟▙▄▖▐▛▀▀▘█    ▐▌   █   █ █     ▐▛▀▀▘
▐▛▀▜▌     █   █   ▐▌  ▝▚▄▄▖█    ▐▛▀▀▘▀▄▄▄▀ █     ▝▚▄▄▖
▐▌ ▐▌             ▐▌            ▐▌             ▗▄▖    
                   ▐▌                          ▐▌ ▐▌   
                                                ▝▀▜▌   
                                               ▐▙▄▞▘   
```

**HunterForge** is an advanced bug bounty toolkit designed for **security researchers, penetration testers, and bug bounty hunters**.  
It combines **subdomain reconnaissance**, **brute force enumeration**, **IP & ASN lookups**, and **web vulnerability scanning** into one powerful CLI tool.

---

## ✨ Features
- ✅ **Subdomain Enumeration**
  - Passive sources: `crt.sh`, `ThreatCrowd`, `HackerTarget`
  - Brute-force mode with concurrency control
- ✅ **IP & ASN Information**
- ✅ **Vulnerability Scanning**
  - Reflected **XSS**
  - **Open Redirect**
  - **CORS Misconfigurations**
  - **Security Headers Check**

---

## ⚡ Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/HunterForge.git
cd HunterForge

# Install dependencies
pip install -r requirements.txt
```

---

## 🔥 Usage
Run the main CLI:
```bash
python hunterforge.py --help
```

You will see:
```
Usage: hunterforge.py [OPTIONS] COMMAND [ARGS]...

HunterForge - Advanced Bug Bounty Toolkit
Version: 1.0.4

A powerful CLI tool for bug bounty hunters:
- Subdomain enumeration (passive & brute force)
- IP & ASN resolution
- Vulnerability scanning (XSS, Open Redirect, CORS, Security Headers)

Commands:
  recon  Subdomain enumeration & reconnaissance
  scan   Scan URLs for vulnerabilities
```

---

### ✅ **Reconnaissance**
Enumerate subdomains for a domain:
```bash
python hunterforge.py recon --domain example.com
```

Enable brute force with custom wordlist:
```bash
python hunterforge.py recon --domain example.com --bruteforce --wordlist subdomains.txt --concurrency 200
```

Save output to custom file:
```bash
python hunterforge.py recon --domain example.com --output custom_subs.txt
```

---

### ✅ **Vulnerability Scanning**
Scan a single URL:
```bash
python hunterforge.py scan --url https://example.com
```

Scan multiple URLs from a file:
```bash
python hunterforge.py scan --urls-file urls.txt --output report.txt
```

---



## 🛠 Requirements
- Python 3.8+
- `rich`, `click`, `aiohttp`, `dnspython`

Install them:
```bash
pip install -r requirements.txt
```

---

## ⚠️ Disclaimer
HunterForge is for **educational and authorized security testing only**.  
Do **NOT** use this tool on systems you do not own or have permission to test.

---

## 📜 License
MIT License © 2025 - haudy-al
