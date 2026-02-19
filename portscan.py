#!/usr/bin/env python3
import argparse
import socket

def parse_ports(ports_str):
    if "-" in ports_str:
        start, end = ports_str.split("-")
        return list(range(int(start), int(end) + 1))

    if "," in ports_str:
        return [int(p) for p in ports_str.split(",")]

    return [int(ports_str)]

def scan_port(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((host, port))
    sock.close()
    return result == 0

def main():
    parser = argparse.ArgumentParser(description="Simple port scanner")
    parser.add_argument("host", help="Hôte à scanner (IP ou FQDN)")
    parser.add_argument("ports", help="Liste de ports (22,80,443) ou plage (1-1000)")
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    counter=0

    print(f"Scan de {args.host} sur {len(ports)} ports...\n")

    for port in ports:
        if scan_port(args.host, port):
            print(f"[+] Port {port} OUVERT")
            counter += 1
    
    print("le nombre de ports ouverts est de ", counter)


if __name__ == "__main__":
    main()
