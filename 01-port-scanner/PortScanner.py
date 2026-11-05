"""
PortScanner.py — Project #1: TCP Port Scanner
Usage:
    python PortScanner.py
    python PortScanner.py 127.0.0.1
    python PortScanner.py 127.0.0.1 --ports 1-2000 --workers 50
"""

import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

def parse_ports(port_str):
    """Convert a range like '1-1024' or single '80' into a list of ports."""
    if "-" in port_str:
        start, end = port_str.split("-")
        return range(int(start), int(end) + 1)
    return [int(port_str)]

def scan_port(target, port):
    """
    Attempt a TCP connection to target:port.
    Returns (port, state, service) — state is 'open' or 'closed'.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((target, port)) == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "unknown"
                return (port, "open", service)
    except socket.error:
        pass  # host unreachable or similar — treat as closed
    return (port, "closed", None)

def scan_target(target, ports, workers):
    """Scan all ports using a thread pool. Returns sorted list of open ports."""
    open_ports = []
    total = len(list(ports))

    print(f"[*] Scanning {total} ports on {target} with {workers} threads...\n")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_port, target, port): port for port in ports}
        for future in as_completed(futures):
            port, state, service = future.result()
            if state == "open":
                open_ports.append((port, service))
                print(f"[+] Port {port:<6} OPEN  ({service})")

    open_ports.sort(key=lambda entry: entry[0])
    return open_ports

def main():
    parser = argparse.ArgumentParser(description="Simple TCP Port Scanner")
    parser.add_argument("target", nargs="?", default="127.0.0.1",
                        help="IP address or hostname to scan (default: 127.0.0.1)")
    parser.add_argument("--ports", default="1-1024",
                        help="Port range, e.g. '1-1024' or '80' (default: 1-1024)")
    parser.add_argument("--workers", type=int, default=100,
                        help="Number of threads (default: 100)")
    args = parser.parse_args()

    # Resolve hostname to IP (e.g. 'localhost' -> 127.0.0.1)
    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[!] Could not resolve hostname: {args.target}")
        sys.exit(1)

    if ip != args.target:
        print(f"[*] {args.target} resolved to {ip}")

    open_ports = scan_target(ip, parse_ports(args.ports), args.workers)

    # Final summary
    print("\n" + "=" * 40)
    if open_ports:
        print(f"[*] Scan complete: {len(open_ports)} open port(s) found")
        for port, service in open_ports:
            print(f"    {port}/tcp  ->  {service}")
    else:
        print("[*] Scan complete: no open ports found")
    print("=" * 40)

if __name__ == "__main__":
    main()