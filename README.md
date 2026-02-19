# 🛡️ PortScanner – Python TCP Port Scanner

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Sockets](https://img.shields.io/badge/Library-socket-yellow)
![CLI](https://img.shields.io/badge/Interface-CLI-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

**PortScanner** is a lightweight Python script that performs a simple TCP port scan using only the built‑in `socket` library.

Designed for **cybersecurity learning**, **network fundamentals**, and **Python scripting practice**.

---

## 📝 Overview

PortScanner allows you to quickly test:

- 🔌 Open TCP ports  
- 🌐 Host reachability  
- 📡 Port ranges or custom lists  
- ⚙️ Basic network diagnostics  

Instead of relying on heavy tools like Nmap, this script provides a **minimal, educational, and transparent** implementation of a TCP connect scan.

This project is part of my learning journey in:

- Python scripting  
- Network fundamentals  
- Cybersecurity basics  
- CLI tool development  

---

## ✨ Features

- Accepts host + ports via command line  
- Supports:
  - Single port (`80`)
  - Port list (`22,80,443`)
  - Port range (`1-1000`)
- Uses TCP connect scan (`socket.connect_ex`)  
- Displays only **open** ports  
- Lightweight and dependency‑free  
- Works on Windows, Linux, and macOS  

---

## 🔧 Usage

### Scan a list of ports

```bash
python portscan.py scanme.nmap.org 22,80,443
```

### Scan a range

```bash
python portscan.py 192.168.1.10 1-1000
```

### Scan a single port

```bash
python portscan.py 127.0.0.1 80
```

---

## 💻 Script – portscan.py

```python
#!/usr/bin/env python3
import argparse
import socket


def parse_ports(ports_str):
    # Handles port ranges (e.g., "1-1000")
    if "-" in ports_str:
        start, end = ports_str.split("-")
        return list(range(int(start), int(end) + 1))

    # Handles port lists (e.g., "22,80,443")
    if "," in ports_str:
        return [int(p) for p in ports_str.split(",")]

    # Handles a single port (e.g., "80")
    return [int(ports_str)]


def scan_port(host, port):
    # Create a TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)  # 1-second timeout

    # Attempt connection
    result = sock.connect_ex((host, port))

    # Close socket
    sock.close()

    # If result == 0 → port is open
    return result == 0


def main():
    # Command-line argument handling
    parser = argparse.ArgumentParser(description="Simple TCP port scanner")
    parser.add_argument("host", help="Target host (IP or FQDN)")
    parser.add_argument("ports", help="Port list (22,80,443) or range (1-1000)")
    args = parser.parse_args()

    # Convert port string to list of integers
    ports = parse_ports(args.ports)

    print(f"Scanning {args.host} on {len(ports)} ports...\n")

    # Scan loop
    for port in ports:
        if scan_port(args.host, port):
            print(f"[+] Port {port} OPEN")


if __name__ == "__main__":
    main()
```

---

## 🔎 Example Output

```
Scanning scanme.nmap.org on 3 ports...

[+] Port 22 OPEN
```

If no ports are open, the script prints nothing.

---

## 🧪 How It Works

### 1. Argument parsing

The script uses `argparse` to read:

- the target host  
- the port(s) to scan  

### 2. Port parsing

`parse_ports()` supports:

- `"80"` → `[80]`
- `"22,80,443"` → `[22, 80, 443]`
- `"1-1000"` → `[1, 2, ..., 1000]`

### 3. TCP connect scan

`socket.connect_ex()` attempts a TCP handshake:

- `0` → port open  
- non‑zero → closed or filtered  

### 4. Output

Only open ports are displayed.

---

## 🎓 Why I Built This

I am improving my skills in:

- Python scripting  
- Network scanning fundamentals  
- CLI tool development  
- Cybersecurity basics  

This project helps me understand **how port scanning works internally**, without relying on external tools.

---

## 🚀 Future Improvements

- Multithreading for faster scans  
- UDP scanning  
- Service detection  
- Banner grabbing  
- JSON / CSV output  

---

## ⚙️ Requirements

- Python 3.10+  
- Works on Windows, Linux, macOS  
- No external dependencies  

---

## 📂 License

MIT License – free to use, modify, and learn from.
