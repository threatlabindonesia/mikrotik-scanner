#!/usr/bin/env python3

import argparse
import nmap
import sys
import os

def print_banner():
    banner = r"""
  ____             _       _   _                 
 |  _ \ ___   __ _(_)_ __ | |_(_)_ __   ___ _ __ 
 | |_) / _ \ / _` | | '_ \| __| | '_ \ / _ \ '__|
 |  _ < (_) | (_| | | | | | |_| | | | |  __/ |   
 |_| \_\___/ \__, |_|_| |_|\__|_|_| |_|\___|_|   
             |___/                               
     Network Port Scanner - by @OmApip
    """
    print(banner)

def scan_with_nmap(ip, port):
    scanner = nmap.PortScanner()
    print(f"\n[>] Scanning {ip}:{port} ...")
    try:
        scanner.scan(ip, str(port), arguments='-sV')
        if ip in scanner.all_hosts() and port in scanner[ip]['tcp']:
            service = scanner[ip]['tcp'][port]
            print(f"[✓] {ip}:{port} - {service['state'].upper()}")
            print(f"     Service : {service['name']}")
            print(f"     Product : {service.get('product', 'N/A')}")
            print(f"     Version : {service.get('version', 'N/A')}")
            if 'mikrotik' in service.get('product', '').lower():
                print("     [!] MikroTik device detected!")
        else:
            print(f"[!] Port {port} is closed or no service detected.")
    except Exception as e:
        print(f"[!] Failed to scan {ip}:{port} - {e}")

def load_bulk_targets(file_path):
    if not os.path.exists(file_path):
        print(f"[!] File not found: {file_path}")
        sys.exit(1)

    targets = []
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if ":" in line:
                try:
                    ip, port = line.split(":")
                    targets.append((ip.strip(), int(port.strip())))
                except ValueError:
                    print(f"[!] Skipping invalid line: {line}")
    return targets

def main():
    parser = argparse.ArgumentParser(
        description="Network Port Scanner with Banner Detection (MikroTik Aware)",
        epilog="Example: python3 scanner.py --ip x.x.x.x. --port 1701"
    )

    parser.add_argument('--ip', help='Target IP address (single)')
    parser.add_argument('--port', type=int, default=1701, help='Target port (default: 1701)')
    parser.add_argument('--bulk', help='Path to file with IP:PORT targets (one per line)')
    parser.add_argument('--version', action='version', version='Scanner v1.0 by @YourName')

    args = parser.parse_args()

    print_banner()

    if args.ip:
        scan_with_nmap(args.ip, args.port)
    elif args.bulk:
        targets = load_bulk_targets(args.bulk)
        for ip, port in targets:
            scan_with_nmap(ip, port)
    else:
        print("[!] Please provide either --ip or --bulk")
        parser.print_help()

if __name__ == "__main__":
    main()
