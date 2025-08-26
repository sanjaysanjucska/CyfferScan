#!/usr/bin/env python3
# myscanner_phases1to6.py
"""
Advanced scanner implementing Phases 1-6:
 - Host discovery (ICMP)
 - TCP & UDP scanning (threads, --all)
 - Service/version detection (-sV)
 - Aggressive per-service enumeration (-A)
 - Improved OS detection (-o)
 - Advanced UDP probing with retries
Run with sudo/root for Scapy raw packets.
"""

import argparse
import socket
import ssl
import re
import struct
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

from scapy.all import sr1, sr, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw

# -------------------------
# Port-to-Service Mapping
# -------------------------
port_services = {
    # Web
    80: "HTTP", 443: "HTTPS", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    # File Transfer
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 69: "TFTP", 989: "FTPS", 990: "FTPS",
    # Remote Access
    23: "Telnet", 3389: "RDP", 5900: "VNC",
    # Email
    25: "SMTP", 110: "POP3", 143: "IMAP", 465: "SMTPS", 587: "SMTP-Alt",
    993: "IMAPS", 995: "POP3S",
    # Databases
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB",
    # Networking
    53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client", 161: "SNMP", 162: "SNMP-Trap",
    179: "BGP", 389: "LDAP", 636: "LDAPS",
    # Windows Services
    135: "MS RPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
    445: "SMB", 5985: "WinRM", 5986: "WinRM-SSL",
    # Security & VPN
    500: "IPSec/IKE", 1701: "L2TP", 1723: "PPTP", 1194: "OpenVPN", 4500: "NAT-T"
}

# -------------------------
# Default common ports lists
# -------------------------
common_tcp_ports = sorted(list(port_services.keys()))
common_udp_ports = [53, 67, 68, 69, 123, 161, 162, 1900, 500, 514, 520, 1434, 4500]

# -------------------------
# Helpers
# -------------------------
def _connect(ip, port, use_ssl=False, timeout=3):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((ip, port))
    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=ip)
    return s

def _recv_some(s, n=2048):
    try:
        return s.recv(n)
    except:
        return b""

# -------------------------
# Host discovery (ICMP ping)
# -------------------------
def host_is_up(ip, timeout=1):
    try:
        p = IP(dst=ip)/ICMP()
        resp = sr1(p, timeout=timeout, verbose=0)
        return resp is not None
    except Exception:
        return False

# -------------------------
# Smart banner grabbing (protocol-aware)
# -------------------------
def grab_banner(ip, port, timeout=3):
    try:
        ssl_ports = (443, 8443, 465, 993, 995, 990, 989, 5986)
        use_ssl = port in ssl_ports
        s = _connect(ip, port, use_ssl=use_ssl, timeout=timeout)

        if port in (80, 8080, 8443, 443, 5985, 5986):
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
            data = _recv_some(s, 4096)
        elif port == 21:
            data = _recv_some(s, 1024)
        elif port in (25, 587, 465):
            data = _recv_some(s, 1024)
        elif port == 22:
            data = _recv_some(s, 1024)
        elif port in (110, 995, 143, 993):
            data = _recv_some(s, 1024)
        elif port == 3306:
            data = _recv_some(s, 1024)
        elif port == 3389:
            try:
                s.sendall(b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x08\x00\x03\xea\x00\x00\x00")
                data = _recv_some(s, 1024)
            except:
                data = _recv_some(s, 1024)
        else:
            try:
                s.sendall(b"\r\n")
            except:
                pass
            data = _recv_some(s, 1024)

        s.close()
        return data.decode(errors="ignore").strip() if data else None
    except Exception:
        return None

# -------------------------
# Smarter service naming using banner hints
# -------------------------
def detect_service(port, banner):
    if banner:
        b = banner.lower()
        if "apache" in b: return "Apache HTTPD"
        if "nginx" in b: return "Nginx"
        if "microsoft-iis" in b or "iis/" in b: return "Microsoft IIS"
        if b.startswith("ssh-"): return "SSH"
        if "proftpd" in b or "vsftpd" in b or "pure-ftpd" in b or "ftp" in b: return "FTP"
        if "mysql" in b: return "MySQL"
        if "postgres" in b or "postgresql" in b: return "PostgreSQL"
        if "smtp" in b or "esmtp" in b: return "SMTP"
        if "imap" in b: return "IMAP"
        if "pop3" in b: return "POP3"
        if "rdp" in b: return "RDP"
        if "winrm" in b: return "WinRM"
    return port_services.get(port, "Unknown")

# -------------------------
# Advanced OS Detection (multi-port TTL + window + options)
# -------------------------
def detect_os(ip):
    try:
        samples = []
        for dport in (22, 80, 443, 135, 3389):
            pkt = IP(dst=ip)/TCP(dport=dport, flags="S")
            resp = sr1(pkt, timeout=1, verbose=0)
            if resp and resp.haslayer(TCP):
                ttl = int(resp.ttl)
                win = int(resp[TCP].window)
                opts = resp[TCP].options if hasattr(resp[TCP], "options") else []
                samples.append((ttl, win, opts))

        if not samples:
            return "Unknown"

        score = {"Windows": 0, "Linux": 0, "Cisco/Router": 0, "BSD/Solaris": 0}
        for ttl, win, opts in samples:
            if ttl >= 200: score["Cisco/Router"] += 2
            elif ttl >= 120: score["Windows"] += 2
            elif ttl >= 60: score["Linux"] += 2

            if win in (8192, 65535, 64240): score["Windows"] += 1
            if win in (5840, 29200, 64240): score["Linux"] += 1
            if win == 4128: score["Cisco/Router"] += 2
            if win == 16384: score["BSD/Solaris"] += 2

            # option heuristics (quick)
            opt_names = [o[0] if isinstance(o, tuple) else str(o) for o in opts]
            if any("WScale" in str(x) or "Wscale" in str(x) for x in opt_names):
                score["Linux"] += 1

        best = max(score, key=score.get)
        return best if score[best] > 0 else "Unknown"
    except Exception as e:
        return f"OS detection failed: {e}"

# -------------------------
# Aggressive TCP Checks (per service)
# -------------------------
def aggressive_tcp_checks(ip, port, no_write_tests=False):
    out = []
    try:
        if port == 21:  # FTP anonymous test
            try:
                s = _connect(ip, port, use_ssl=False, timeout=4)
                greet = _recv_some(s, 1024).decode(errors="ignore")
                s.sendall(b"USER anonymous\r\n")
                resp1 = _recv_some(s, 1024).decode(errors="ignore")
                s.sendall(b"PASS anonymous\r\n")
                resp2 = _recv_some(s, 1024).decode(errors="ignore")
                allowed = ("230" in resp2)
                out.append(f"Anonymous Login: {'ALLOWED ✅' if allowed else 'DENIED ❌'}")
                # Optional write test skipped unless allowed and not no_write_tests
                if allowed and not no_write_tests:
                    try:
                        s.sendall(b"TYPE I\r\n")
                        _recv_some(s, 1024)
                        s.sendall(b"STOR scan_test.txt\r\n")
                        # many FTP servers will require data connection; skip real STOR to avoid problems
                        out.append("FTP write test: SKIPPED (safe default)")
                    except:
                        out.append("FTP write test: failed to attempt")
                if greet:
                    out.append(f"FTP Greet: {greet.strip()}")
                s.close()
            except Exception:
                out.append("FTP anonymous test: error")
        elif port == 25:  # SMTP VRFY/STARTTLS detection
            try:
                s = _connect(ip, port, use_ssl=False, timeout=4)
                greet = _recv_some(s, 1024).decode(errors="ignore")
                s.sendall(b"EHLO scanner.local\r\n")
                resp = _recv_some(s, 4096).decode(errors="ignore")
                supports_starttls = "STARTTLS" in resp.upper()
                # VRFY test (non-destructive): try VRFY root or postmaster
                s.sendall(b"VRFY postmaster\r\n")
                vrfy_resp = _recv_some(s, 1024).decode(errors="ignore")
                vrfy_ok = any(code in vrfy_resp for code in ("250", "252"))
                out.append(f"Greet: {greet.strip()}" if greet else "Greet: (none)")
                out.append(f"STARTTLS: {'advertised' if supports_starttls else 'not advertised'}")
                out.append(f"VRFY postmaster: {'allowed' if vrfy_ok else 'not allowed'}")
                s.close()
            except Exception:
                out.append("SMTP aggressive checks failed")
        elif port in (80, 8080, 8443, 443):
            out.extend(check_http_details(ip, port, https=(port in (443,8443))))
            # probe a few common paths
            paths = probe_common_paths(ip, port, https=(port in (443,8443)))
            if paths:
                out.append("Common paths: " + ", ".join(paths))
        elif port == 3306:
            out.extend(check_mysql(ip, port))
        elif port == 5432:
            out.extend(check_postgres(ip, port))
        elif port == 22:
            # SSH: banner is usually enough for sV
            out.append("SSH: banner checked")
        elif port in (139, 445):
            out.append("SMB: service detected (deep enum requires SMB library like impacket)")
    except Exception:
        pass
    return out

# -------------------------
# Aggressive UDP payloads & checks
# -------------------------
udp_payloads = {
    53: DNS(rd=1, qd=DNSQR(qname="version.bind", qtype="TXT", qclass=3)),
    123: Raw(load=b'\x1b' + 47 * b'\0'),  # NTP
    161: Raw(load=b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x71\x6f\x7a\x5b\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00'),
    69: Raw(load=b"\x00\x01test\x00octet\x00"),
    1900: Raw(load=b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n"),
    500: Raw(load=b"\x00" * 28),
    4500: Raw(load=b"\x00" * 28),
    514: Raw(load=b"<14>1 test syslog message\n")
}

def aggressive_udp_checks(ip, port, resp_pkt):
    out = []
    try:
        if port == 53:
            if resp_pkt and resp_pkt.haslayer(DNS):
                answers = []
                for i in range(getattr(resp_pkt[DNS], "ancount", 0)):
                    try:
                        answers.append(str(resp_pkt[DNS].an[i].rdata))
                    except:
                        pass
                out.append(f"DNS Answers: {answers if answers else 'response present'}")
            else:
                out.append("DNS: no version info (maybe filtered)")
        elif port == 161:
            out.append("SNMP: responded (public?)" if resp_pkt else "SNMP: no response to public probe")
        elif port == 123:
            out.append("NTP: responded" if resp_pkt else "NTP: no response")
        elif port == 1900:
            if resp_pkt and resp_pkt.haslayer(Raw):
                try:
                    txt = resp_pkt[Raw].load.decode(errors="ignore")
                    lines = [ln for ln in txt.split("\r\n") if ln]
                    out.append("SSDP: " + "; ".join(lines[:4]))
                except:
                    out.append("SSDP: raw response")
            else:
                out.append("SSDP: no response")
        elif port == 69:
            out.append("TFTP: probe sent (use TFTP client to test file read/write)")
        elif port in (67, 68):
            out.append("DHCP: probe not fully implemented here")
        elif port in (500, 4500):
            out.append("IKE/NAT-T: responder detected or no ICMP unreachable")
        elif port == 514:
            out.append("Syslog: test message sent")
    except Exception as e:
        out.append(f"UDP aggressive check error: {e}")
    return out

# -------------------------
# Parse HTTP helpers used in aggressive checks
# -------------------------
def _parse_http_headers(raw):
    headers = {}
    if not raw: return headers
    head = raw.split("\r\n\r\n", 1)[0]
    lines = head.split("\r\n")
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return headers

def _extract_html_title(raw):
    if not raw: return None
    body = raw.split("\r\n\r\n", 1)[-1]
    m = re.search(r"<title>(.*?)</title>", body, re.I | re.S)
    return m.group(1).strip() if m else None

def check_http_details(ip, port, https=False):
    out = []
    try:
        s = _connect(ip, port, use_ssl=https, timeout=5)
        s.sendall(b"GET / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
        raw = _recv_some(s, 65536).decode(errors="ignore")
        s.close()
        headers = _parse_http_headers(raw)
        server = headers.get("server")
        title = _extract_html_title(raw)
        if server: out.append(f"Server: {server}")
        if title: out.append(f"Title: {title[:120]}")
        missing = []
        if "strict-transport-security" not in headers and https:
            missing.append("HSTS")
        if "content-security-policy" not in headers:
            missing.append("CSP")
        if "x-frame-options" not in headers:
            missing.append("X-Frame-Options")
        if missing:
            out.append("Security Headers: Missing " + ", ".join(missing))
        return out if out else ["HTTP check: no details"]
    except Exception:
        return ["HTTP check failed"]

# -------------------------
# MySQL / Postgres minimal checks
# -------------------------
def check_mysql(ip, port):
    try:
        s = _connect(ip, port, use_ssl=False, timeout=5)
        hs = _recv_some(s, 1024)
        s.close()
        ver = None
        if hs and len(hs) > 2:
            try:
                end = hs[1:].find(b"\x00")
                if end != -1:
                    ver = hs[1:1+end].decode(errors="ignore")
            except:
                pass
        return [f"MySQL Version: {ver}"] if ver else ["MySQL: handshake read (version unknown)"]
    except Exception:
        return ["MySQL check failed"]

def check_postgres(ip, port):
    try:
        s = _connect(ip, port, use_ssl=False, timeout=5)
        pkt = struct.pack("!II", 8, 80877103)
        s.sendall(pkt)
        ans = _recv_some(s, 1)
        s.close()
        if ans == b'S': return ["PostgreSQL: SSL supported (S)"]
        if ans == b'N': return ["PostgreSQL: SSL not supported (N)"]
        return ["PostgreSQL: unexpected response"]
    except Exception:
        return ["PostgreSQL check failed"]

# -------------------------
# TCP Connect Scan (sV integrated)
# Returns: (port, state, proto, svc_info/banner, extra)
# -------------------------
def tcp_scan(ip, port, verbose=False, sV=False, aggressive=False, no_write_tests=False):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        result = sock.connect_ex((ip, port))
        if verbose:
            print(f"[VERBOSE] Scanning TCP {port} => result {result}")

        if result == 0:
            svc_info = None
            banner = None
            if sV:
                banner = grab_banner(ip, port, timeout=2)
                svc_info = banner
                # TLS inspection for HTTPS if requested
                if port in (443, 8443):
                    try:
                        tls = tls_inspect(ip, port)
                        if tls:
                            if isinstance(svc_info, str):
                                svc_info = {"banner": svc_info, "tls": tls}
                            else:
                                svc_info = {"tls": tls}
                    except:
                        pass
            else:
                banner = None

            extra = aggressive_tcp_checks(ip, port, no_write_tests=no_write_tests) if aggressive else None
            # return banner or svc_info (svc_info may be dict when sV used)
            return port, "OPEN", "TCP", svc_info or banner, extra
        else:
            return port, "CLOSED", "TCP", None, None
    except Exception as e:
        return port, f"ERROR ({e})", "TCP", None, None
    finally:
        try:
            sock.close()
        except:
            pass

# -------------------------
# UDP Scan (advanced)
# Returns: (port, state, proto, svc_info/banner_summary, extra)
# -------------------------
def udp_scan(ip, port, verbose=False, sV=False, aggressive=False, retries=2, timeout=2):
    try:
        payload = udp_payloads.get(port, Raw(load=b""))
        for attempt in range(retries):
            pkt = IP(dst=ip) / UDP(dport=port) / payload
            if verbose:
                print(f"[VERBOSE] UDP probe {port} attempt {attempt+1}")
            resp = sr1(pkt, timeout=timeout, verbose=0)
            if resp is None:
                continue
            # ICMP unreachable => closed or filtered
            if resp.haslayer(ICMP):
                icmp = resp.getlayer(ICMP)
                if int(icmp.type) == 3 and int(icmp.code) == 3:
                    return port, "CLOSED", "UDP", None, None
                else:
                    return port, "FILTERED", "UDP", None, None
            # UDP response
            banner_summary = None
            try:
                if resp.haslayer(DNS):
                    banner_summary = "DNS response"
                elif resp.haslayer(Raw):
                    banner_summary = resp[Raw].load.decode(errors="ignore")[:200]
                else:
                    banner_summary = resp.summary()
            except:
                banner_summary = resp.summary()

            extra = aggressive_udp_checks(ip, port, resp) if aggressive else None
            svc_info = banner_summary if sV else None
            return port, "OPEN", "UDP", svc_info, extra

        # retries exhausted -> open|filtered
        return port, "OPEN|FILTERED", "UDP", None, None
    except Exception as e:
        return port, f"ERROR ({e})", "UDP", None, None

# -------------------------
# TLS inspection helper (used for -sV)
# -------------------------
def tls_inspect(ip, port, timeout=3):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                proto = ssock.version()
        return {"cert": cert, "cipher": cipher, "tls_version": proto}
    except Exception as e:
        return {"error": str(e)}

# -------------------------
# Common-path probe helper
# -------------------------
def probe_common_paths(ip, port, https=False, paths=None):
    found = []
    if paths is None:
        paths = ["/robots.txt", "/.git/", "/server-status", "/admin", "/login"]
    for p in paths:
        try:
            s = _connect(ip, port, use_ssl=https, timeout=2)
            s.sendall(b"GET %b HTTP/1.1\r\nHost: %b\r\nConnection: close\r\n\r\n" % (p.encode(), ip.encode()))
            data = _recv_some(s, 4096)
            s.close()
            if data:
                first = data.split(b"\r\n",1)[0].upper()
                if b"200" in first or b"301" in first or b"302" in first:
                    found.append(p)
        except:
            pass
    return found

# -------------------------
# Port parsing helper
# -------------------------
def parse_ports_arg(ports_arg, scan_type):
    if ports_arg:
        parts = re.split(r"\s*,\s*", ports_arg.strip())
        ports = []
        for p in parts:
            if "-" in p:
                a,b = p.split("-",1)
                ports.extend(range(int(a), int(b)+1))
            else:
                ports.append(int(p))
        return ports
    else:
        return common_tcp_ports if scan_type in ("tcp","both") else common_udp_ports

# -------------------------
# Main
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="Advanced Python Port Scanner (Phases 1-6)")
    parser.add_argument("target", help="Target IP or Hostname")
    parser.add_argument("-p", "--ports", help="Ports (e.g. 1-1000 or 80,443). Default = common ports", default=None)
    parser.add_argument("--all", help="Scan all 65535 ports", action="store_true")
    parser.add_argument("-t", "--threads", help="Number of threads", type=int, default=100)
    parser.add_argument("-o", "--osdetect", help="Enable OS detection", action="store_true")
    parser.add_argument("-s", "--scan", help="Scan type (tcp/udp/both)", choices=["tcp","udp","both"], default="tcp")
    parser.add_argument("-A", "--aggressive", help="Aggressive per-service checks", action="store_true")
    parser.add_argument("-v", "--verbose", help="Enable verbose output", action="store_true")
    parser.add_argument("-sV", "--service", help="Enable service/version detection", action="store_true")
    parser.add_argument("--rate", type=int, default=0, help="max requests per second (0=unlimited)")
    parser.add_argument("--no-write-tests", action="store_true", help="disable destructive write tests (FTP STOR, etc.)")
    args = parser.parse_args()

    # Resolve IP
    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print("Invalid target hostname or IP.")
        return

    # Host discovery
    print(f"[*] Host discovery: checking {args.target} ({target_ip}) ...")
    up = host_is_up(target_ip)
    if not up:
        print(f"[!] Host appears down (no ICMP response). Scans may still find open ports if host filters ICMP.")
    else:
        print(f"[+] Host responded to ICMP echo.")

    # Determine ports to scan
    if args.all:
        port_range = range(1, 65536)
    else:
        port_range = parse_ports_arg(args.ports, args.scan) if args.ports else (common_tcp_ports if args.scan in ("tcp","both") else common_udp_ports)

    # rate limiting
    delay_between = 0.0
    if args.rate and args.rate > 0:
        delay_between = 1.0 / args.rate

    # Summary
    print(f"\n[*] Starting {args.scan.upper()} scan on {args.target} ({target_ip})")
    print(f"[*] Ports: {'1-65535' if args.all else (args.ports if args.ports else 'Common Ports')}")
    print(f"[*] Threads: {args.threads}")
    print(f"[*] Verbose: {'ON' if args.verbose else 'OFF'}")
    print(f"[*] Aggressive: {'ON' if args.aggressive else 'OFF'}")
    print(f"[*] Service/version detection: {'ON' if args.service else 'OFF'}")
    print(f"[*] Time: {datetime.now()}\n")

    results = []

    def scan_worker_tcp(ports):
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            futures = []
            for p in ports:
                futures.append(pool.submit(tcp_scan, target_ip, p, args.verbose, sV=args.service, aggressive=args.aggressive, no_write_tests=args.no_write_tests))
                if delay_between > 0:
                    time.sleep(delay_between)
            for f in as_completed(futures):
                try:
                    results.append(f.result())
                except Exception as e:
                    if args.verbose:
                        print(f"[!] Task error: {e}")

    def scan_worker_udp(ports):
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            futures = []
            for p in ports:
                futures.append(pool.submit(udp_scan, target_ip, p, args.verbose, sV=args.service, aggressive=args.aggressive))
                if delay_between > 0:
                    time.sleep(delay_between)
            for f in as_completed(futures):
                try:
                    results.append(f.result())
                except Exception as e:
                    if args.verbose:
                        print(f"[!] Task error: {e}")

    # Run scans: TCP then UDP for predictability when "both"
    if args.scan in ("tcp","both"):
        tcp_ports = port_range if (args.ports or args.all) else common_tcp_ports
        scan_worker_tcp(tcp_ports)

    if args.scan in ("udp","both"):
        udp_ports = port_range if (args.ports or args.all) else common_udp_ports
        scan_worker_udp(udp_ports)

    # Collect & print open/filtered results
    open_entries = []
    for entry in sorted(results, key=lambda x: (x[0] if isinstance(x, tuple) else 0)):
        try:
            port, state, proto, svc_or_banner, extra = entry
        except:
            continue

        if state in ("OPEN", "OPEN|FILTERED"):
            # Determine service name
            service_name = None
            if args.service and svc_or_banner:
                # if sV returned a dict (e.g., banner + tls), try to summarize
                if isinstance(svc_or_banner, dict):
                    # prefer banner text if present
                    if svc_or_banner.get("banner"):
                        service_name = detect_service(port, svc_or_banner.get("banner"))
                    elif svc_or_banner.get("tls"):
                        service_name = port_services.get(port, "Unknown")
                    else:
                        service_name = port_services.get(port, "Unknown")
                else:
                    service_name = detect_service(port, str(svc_or_banner))
            else:
                service_name = port_services.get(port, "Unknown")

            print(f"Port {port} {service_name} {state}")
            if svc_or_banner:
                if isinstance(svc_or_banner, dict):
                    # pretty-print relevant keys
                    if svc_or_banner.get("banner"):
                        print(f"    Banner: {str(svc_or_banner.get('banner'))[:200]}")
                    if svc_or_banner.get("tls"):
                        tls = svc_or_banner.get("tls")
                        if isinstance(tls, dict):
                            print(f"    TLS: version={tls.get('tls_version')} cipher={tls.get('cipher')}")
                    if svc_or_banner.get("server"):
                        print(f"    Server header: {svc_or_banner.get('server')}")
                else:
                    print(f"    Info: {str(svc_or_banner)[:300]}")
            if extra:
                if isinstance(extra, dict):
                    for k,v in extra.items():
                        print(f"    {k}: {v}")
                elif isinstance(extra, list):
                    for line in extra:
                        print(f"    {line}")
                else:
                    print(f"    Extra: {extra}")

            open_entries.append((port, service_name, proto, svc_or_banner, extra))

    # OS Detection
    if args.osdetect:
        print("\n[*] Running OS Detection...")
        os_guess = detect_os(target_ip)
        print(f"[+] OS Guess: {os_guess}")

    print("\n[*] Scan complete.\n")

if __name__ == "__main__":
    main()
