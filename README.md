# 🔍 MikroTik Port Scanner - by @OmApip

A lightweight Python-based port scanner that detects open services, grabs banners, and identifies MikroTik devices using `nmap`.

---

## ✨ Features

- ✅ Scan a **single IP and port**
- ✅ Scan **multiple IP:PORT combinations** from a file
- ✅ Detects **MikroTik** devices via service banner
- ✅ Informative and readable output
- ✅ Command-line interface with `--help` and `--version`

---

## ⚙️ Requirements

Make sure the following are installed:

### Python & Modules
- Python 3.7+
- `python-nmap` module

Install with:
```bash
pip install python-nmap
```

### Nmap (CLI tool)
This script uses the system-installed `nmap` command-line tool.

#### On Debian/Ubuntu/WSL:
```bash
sudo apt update
sudo apt install nmap
```

#### On macOS:
```bash
brew install nmap
```

#### On Windows:
Download from: https://nmap.org/download.html  
Make sure to add Nmap to your system `PATH`.

---

## 🚀 How to Use

### 🔹 Scan a Single IP and Port
```bash
python3 scanner.py --ip 203.34.118.33 --port 1701
```

### 🔹 Bulk Scan from File (Format: IP:PORT)
Create a file `targets.txt`:

```
203.34.118.33:1701
192.168.1.1:8291
8.8.8.8:443
```

Run:
```bash
python3 scanner.py --bulk targets.txt
```

### 🔹 Show Help
```bash
python3 scanner.py --help
```

---

## 🧾 Example Output

### ✅ If port is open:
```
[>] Scanning 203.34.118.33:1701 ...
[✓] 203.34.118.33:1701 - OPEN
     Service : l2tp
     Product : MikroTik RouterOS
     Version : 6.49.7
     [!] MikroTik device detected!
```

### ❌ If port is closed:
```
[>] Scanning 8.8.8.8:1701 ...
[!] Port 1701 is closed or no service detected.
```

---

## 📁 Project Structure

```
.
├── scanner.py        # Main scanner script
├── targets.txt       # Sample file with IP:PORT targets
└── README.md         # This file
```

---

## 👨‍💻 Author

Created by [@OmApip]  
Open for contributions and ideas — feel free to fork or improve it!
