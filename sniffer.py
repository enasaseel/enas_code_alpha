#!/usr/bin/env python3
"""
CodeAlpha Cyber Security Internship - Task 1: Basic Network Sniffer

Captures network packets (live or from a .pcap file), parses the main
protocol layers and prints useful information:
source/destination IPs and MACs, protocol, ports, TCP flags, DNS queries,
HTTP request lines and a payload preview.

ETHICAL USE: only capture traffic on networks/devices you own or have
explicit permission to monitor.

Examples:
    sudo python3 sniffer.py                          # sniff everything
    sudo python3 sniffer.py -i wlan0 -c 50           # 50 packets on wlan0
    sudo python3 sniffer.py -f "tcp port 80" -p      # HTTP only + payload
    sudo python3 sniffer.py -c 100 -w capture.pcap   # save to pcap
    python3 sniffer.py -r sample_capture.pcap        # analyse a pcap (no root)
"""

import argparse
import sys
from collections import Counter
from datetime import datetime

try:
    from scapy.all import (
        ARP, DNS, ICMP, IP, IPv6, TCP, UDP, Ether, Raw,
        PcapWriter, sniff, rdpcap,
    )
except ImportError:
    sys.exit("scapy is required:  pip install scapy")

stats = Counter()
pcap_writer = None
ARGS = None

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
TCP_FLAGS = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
             "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR"}
WELL_KNOWN_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-alt",
}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
                b"OPTIONS ", b"PATCH ", b"HTTP/1.")


def port_label(port):
    name = WELL_KNOWN_PORTS.get(port)
    return f"{port} ({name})" if name else str(port)


def payload_preview(raw_bytes, limit):
    """Return a printable preview of the payload (non-printables -> '.')."""
    data = raw_bytes[:limit]
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    suffix = "..." if len(raw_bytes) > limit else ""
    return f"{text}{suffix}"


def describe_tcp_flags(tcp):
    flags = str(tcp.flags)
    return "+".join(TCP_FLAGS[f] for f in flags if f in TCP_FLAGS) or "none"


def handle_packet(pkt):
    """Called for every captured packet."""
    stats["total"] += 1
    stamp = datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S.%f")[:-3]
    lines = [f"\n[{stats['total']:>4}] {stamp}  ({len(pkt)} bytes)"]

    if pcap_writer is not None:
        pcap_writer.write(pkt)

    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        lines.append(f"      MAC  : {eth.src} -> {eth.dst}")

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        stats["ARP"] += 1
        kind = "request" if arp.op == 1 else "reply" if arp.op == 2 else str(arp.op)
        lines.append(f"      ARP  : {kind}  {arp.psrc} ({arp.hwsrc}) -> {arp.pdst}")
        print("\n".join(lines))
        return

    ip = None
    if pkt.haslayer(IP):
        ip = pkt[IP]
        proto = PROTO_NAMES.get(ip.proto, f"proto-{ip.proto}")
        lines.append(f"      IPv4 : {ip.src} -> {ip.dst}  | protocol={proto} ttl={ip.ttl}")
    elif pkt.haslayer(IPv6):
        ip = pkt[IPv6]
        proto = PROTO_NAMES.get(ip.nh, f"nh-{ip.nh}")
        lines.append(f"      IPv6 : {ip.src} -> {ip.dst}  | next-header={proto}")
    else:
        stats["other"] += 1
        lines.append("      (non-IP packet)")
        print("\n".join(lines))
        return

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        stats["TCP"] += 1
        lines.append(f"      TCP  : {port_label(tcp.sport)} -> {port_label(tcp.dport)}"
                     f"  flags={describe_tcp_flags(tcp)} seq={tcp.seq} win={tcp.window}")
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        stats["UDP"] += 1
        lines.append(f"      UDP  : {port_label(udp.sport)} -> {port_label(udp.dport)}"
                     f"  len={udp.len}")
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        stats["ICMP"] += 1
        lines.append(f"      ICMP : type={icmp.type} code={icmp.code}")
    else:
        stats["other"] += 1

    # DNS
    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        stats["DNS"] += 1
        if dns.qr == 0 and dns.qd is not None:
            qname = dns.qd.qname.decode(errors="replace")
            lines.append(f"      DNS  : query for {qname}")
        elif dns.qr == 1:
            lines.append(f"      DNS  : response ({dns.ancount} answer(s))")

    # Payload / HTTP
    if pkt.haslayer(Raw):
        raw = bytes(pkt[Raw].load)
        if raw.startswith(HTTP_METHODS):
            stats["HTTP"] += 1
            first_line = raw.split(b"\r\n", 1)[0].decode(errors="replace")
            lines.append(f"      HTTP : {first_line}")
        elif pkt.haslayer(TCP) and 443 in (pkt[TCP].sport, pkt[TCP].dport):
            lines.append("      TLS  : encrypted payload (not readable)")
        if ARGS.payload:
            lines.append(f"      DATA : {payload_preview(raw, ARGS.payload_len)}")

    print("\n".join(lines))


def print_summary():
    print("\n" + "=" * 50)
    print("CAPTURE SUMMARY")
    print("=" * 50)
    print(f"Total packets : {stats['total']}")
    for key in ("TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "other"):
        if stats[key]:
            print(f"{key:<14}: {stats[key]}")


def parse_args():
    p = argparse.ArgumentParser(description="Basic network sniffer (CodeAlpha Task 1)")
    p.add_argument("-i", "--interface", help="interface to sniff on (default: auto)")
    p.add_argument("-c", "--count", type=int, default=0,
                   help="number of packets to capture (0 = until Ctrl+C)")
    p.add_argument("-f", "--filter", default="",
                   help='BPF filter, e.g. "tcp port 80" or "host 8.8.8.8"')
    p.add_argument("-p", "--payload", action="store_true", help="show payload preview")
    p.add_argument("--payload-len", type=int, default=64,
                   help="payload bytes to preview (default 64)")
    p.add_argument("-w", "--write", help="save captured packets to a .pcap file")
    p.add_argument("-r", "--read", help="read packets from a .pcap file instead of sniffing")
    return p.parse_args()


def main():
    global ARGS, pcap_writer
    ARGS = parse_args()

    if ARGS.write:
        pcap_writer = PcapWriter(ARGS.write, append=False, sync=True)

    try:
        if ARGS.read:
            print(f"[*] Reading packets from {ARGS.read}")
            for pkt in rdpcap(ARGS.read):
                handle_packet(pkt)
        else:
            print(f"[*] Sniffing on {ARGS.interface or 'default interface'}"
                  f"  filter='{ARGS.filter or 'none'}'  (Ctrl+C to stop)")
            sniff(iface=ARGS.interface, filter=ARGS.filter or None,
                  prn=handle_packet, count=ARGS.count, store=False)
    except PermissionError:
        sys.exit("[!] Permission denied. Run with sudo (Linux/macOS) or as "
                 "Administrator with Npcap installed (Windows).")
    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")
    finally:
        if pcap_writer is not None:
            pcap_writer.close()
        print_summary()


if __name__ == "__main__":
    main()
