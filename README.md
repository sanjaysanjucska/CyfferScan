# CyfferScan

**CyfferScan** is an advanced Python-based network scanner that performs multi-phase scanning, including TCP/UDP port detection, service enumeration, OS fingerprinting, and aggressive per-service checks. Designed for ethical hackers, penetration testers, and network administrators.

---

## Features

- Host discovery via ICMP ping.
- TCP & UDP scanning with optional all-port scanning (1-65535).
- Service/version detection (`-sV`) with smart banner grabbing.
- Aggressive per-service enumeration (`-A`) for FTP, SMTP, HTTP, SSH, MySQL, PostgreSQL, and more.
- OS detection based on TTL, TCP window, and options.
- Advanced UDP probing with retries for common services (DNS, NTP, SNMP, SSDP, TFTP).
- Verbose mode for detailed output.
- Rate limiting (`--rate`) to control scan speed.
- Safe defaults that avoid destructive write tests unless explicitly enabled.

---

## Positional Arguments

- **TARGET** — Target IP or hostname.

---

## Options

| Flag | Description |
|------|-------------|
| `-p, --ports` | Ports to scan (e.g., 80,443 or 1-1000). Default = common ports |
| `--all` | Scan all 65535 ports |
| `-t, --threads` | Number of threads (default: 100) |
| `-o, --osdetect` | Enable OS detection |
| `-s, --scan` | Scan type: tcp, udp, or both (default: tcp) |
| `-A, --aggressive` | Enable aggressive per-service checks |
| `-v, --verbose` | Enable verbose output |
| `-sV, --service` | Enable service/version detection |
| `--rate RATE` | Max requests per second (0 = unlimited) |
| `--no-write-tests` | Disable destructive write tests (e.g., FTP STOR) |

---

## Examples
## Usage

```bash
# Basic TCP scan of target
sudo python3 CyfferScan.py 192.168.1.10

# Scan specific ports with service detection
sudo python3 CyfferScan.py 192.168.1.10 -p 22,80,443 -sV

# Full port scan with aggressive enumeration and OS detection
sudo python3 CyfferScan.py 192.168.1.10 --all -A -o -sV

# UDP scan with verbose output
sudo python3 CyfferScan.py 192.168.1.10 -s udp -v

# Limit scan speed to 50 requests/sec
sudo python3 CyfferScan.py 192.168.1.10 --rate 50

Disclaimer

⚠️ This project is for educational and research purposes only.
Do not use it on networks or systems you do not own or without explicit permission.
The author is not responsible for any misuse, damage, or legal consequences caused by this tool.

