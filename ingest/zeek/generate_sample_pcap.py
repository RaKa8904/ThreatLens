"""
ThreatLens Sample Attack PCAP Generator
=======================================
Generates a standalone, self-contained libpcap file ('sample_attack.pcap')
containing:
  1. Normal DNS & HTTP web browsing traffic.
  2. A high-rate TCP SYN flood (Volumetric DDoS).
  3. A periodic C2 beaconing socket pair at exact 15-second intervals.
  4. A high-entropy DGA / DNS tunneling query.

Uses pure Python raw network frame structures (struct) with zero external dependencies.
"""

import argparse
from datetime import datetime
import os
import socket
import struct
import time
from typing import List, Tuple


def ip_checksum(header: bytes) -> int:
    """Calculates standard Internet Checksum (RFC 1071)."""
    if len(header) % 2 == 1:
        header += b"\x00"
    s = 0
    for i in range(0, len(header), 2):
        w = (header[i] << 8) + header[i + 1]
        s += w
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


class PcapWriter:
    """Builds and serializes standard libpcap binary capture files."""

    def __init__(self, filename: str):
        self.filename = filename
        self.packets: List[Tuple[float, bytes]] = []

    def add_packet(self, timestamp: float, pkt_data: bytes) -> None:
        self.packets.append((timestamp, pkt_data))

    def write(self) -> str:
        # Sort packets chronologically
        self.packets.sort(key=lambda p: p[0])

        os.makedirs(os.path.dirname(os.path.abspath(self.filename)), exist_ok=True)
        with open(self.filename, "wb") as f:
            # 24-byte PCAP Global Header
            # magic=0xa1b2c3d4, v_maj=2, v_min=4, zone=0, sig=0, snaplen=65535, network=1 (Ethernet)
            f.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

            for ts, data in self.packets:
                sec = int(ts)
                usec = int((ts - sec) * 1_000_000)
                length = len(data)
                # 16-byte Packet Header: ts_sec, ts_usec, incl_len, orig_len
                f.write(struct.pack("!IIII", sec, usec, length, length))
                f.write(data)

        return self.filename


def build_ethernet_frame(src_mac: str, dst_mac: str, ethertype: int, payload: bytes) -> bytes:
    dst = bytes.fromhex(dst_mac.replace(":", ""))
    src = bytes.fromhex(src_mac.replace(":", ""))
    return dst + src + struct.pack("!H", ethertype) + payload


def build_ipv4_packet(src_ip: str, dst_ip: str, protocol: int, payload: bytes, ip_id: int = 1) -> bytes:
    version_ihl = (4 << 4) | 5
    tos = 0
    total_len = 20 + len(payload)
    flags_offset = 0x4000  # DF flag
    ttl = 64
    checksum = 0
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)

    header_pre = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_len,
        ip_id,
        flags_offset,
        ttl,
        protocol,
        checksum,
        src_bytes,
        dst_bytes,
    )
    chk = ip_checksum(header_pre)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_len,
        ip_id,
        flags_offset,
        ttl,
        protocol,
        chk,
        src_bytes,
        dst_bytes,
    )
    return header + payload


def build_tcp_packet(
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
    window: int = 64240,
) -> bytes:
    data_offset = (5 << 4)  # 20 bytes header
    checksum = 0
    urgent = 0
    header = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, data_offset, flags, window, checksum, urgent)
    return header + payload


def build_udp_packet(src_port: int, dst_port: int, payload: bytes = b"") -> bytes:
    length = 8 + len(payload)
    checksum = 0
    header = struct.pack("!HHHH", src_port, dst_port, length, checksum)
    return header + payload


def encode_dns_name(domain: str) -> bytes:
    parts = domain.strip(".").split(".")
    encoded = b"".join(struct.pack("!B", len(p)) + p.encode("ascii") for p in parts)
    return encoded + b"\x00"


def build_dns_query(domain: str, qtype: int = 1, tx_id: int = 0x1234) -> bytes:
    flags = 0x0100  # Standard query, recursion desired
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0
    header = struct.pack("!HHHHHH", tx_id, flags, qdcount, ancount, nscount, arcount)
    qname = encode_dns_name(domain)
    qtail = struct.pack("!HH", qtype, 1)  # QTYPE, QCLASS=IN
    return header + qname + qtail


def build_dns_response(domain: str, answer_ip: str, tx_id: int = 0x1234) -> bytes:
    flags = 0x8180  # Standard response, no error
    header = struct.pack("!HHHHHH", tx_id, flags, 1, 1, 0, 0)
    qname = encode_dns_name(domain)
    qtail = struct.pack("!HH", 1, 1)
    # Answer RR: Name pointer (0xc00c), Type=A (1), Class=IN (1), TTL=300, RdLength=4, IP
    answer = struct.pack("!HHHIH4s", 0xC00C, 1, 1, 300, 4, socket.inet_aton(answer_ip))
    return header + qname + qtail + answer


def generate_pcap(output_path: str = "pcaps/sample_attack.pcap") -> str:
    """Generates the synthetic multi-threat attack PCAP."""
    writer = PcapWriter(output_path)
    base_t = time.time() - 300.0  # Start 5 minutes in past for sliding windows

    mac_host = "00:0c:29:ab:cd:01"
    mac_gateway = "00:50:56:ea:eb:ec"
    mac_attacker = "52:54:00:99:88:77"

    # =========================================================================
    # 1. Normal DNS Query & HTTP Web Session
    # =========================================================================
    t = base_t
    # DNS lookup for www.google.com
    dns_q = build_dns_query("www.google.com", tx_id=0x1001)
    udp_q = build_udp_packet(53100, 53, dns_q)
    ip_q = build_ipv4_packet("192.168.1.100", "8.8.8.8", 17, udp_q, 101)
    writer.add_packet(t, build_ethernet_frame(mac_host, mac_gateway, 0x0800, ip_q))

    t += 0.03
    dns_r = build_dns_response("www.google.com", "142.250.190.46", tx_id=0x1001)
    udp_r = build_udp_packet(53, 53100, dns_r)
    ip_r = build_ipv4_packet("8.8.8.8", "192.168.1.100", 17, udp_r, 102)
    writer.add_packet(t, build_ethernet_frame(mac_gateway, mac_host, 0x0800, ip_r))

    # HTTP 3-Way Handshake + GET Request
    t += 0.05
    # SYN
    tcp_syn = build_tcp_packet(49152, 80, seq=1000, ack=0, flags=0x02)
    writer.add_packet(t, build_ethernet_frame(mac_host, mac_gateway, 0x0800, build_ipv4_packet("192.168.1.100", "142.250.190.46", 6, tcp_syn, 201)))

    t += 0.02
    # SYN-ACK
    tcp_synack = build_tcp_packet(80, 49152, seq=5000, ack=1001, flags=0x12)
    writer.add_packet(t, build_ethernet_frame(mac_gateway, mac_host, 0x0800, build_ipv4_packet("142.250.190.46", "192.168.1.100", 6, tcp_synack, 202)))

    t += 0.01
    # ACK
    tcp_ack = build_tcp_packet(49152, 80, seq=1001, ack=5001, flags=0x10)
    writer.add_packet(t, build_ethernet_frame(mac_host, mac_gateway, 0x0800, build_ipv4_packet("192.168.1.100", "142.250.190.46", 6, tcp_ack, 203)))

    t += 0.01
    # HTTP GET
    http_get = b"GET /index.html HTTP/1.1\r\nHost: www.google.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    tcp_psh = build_tcp_packet(49152, 80, seq=1001, ack=5001, flags=0x18, payload=http_get)
    writer.add_packet(t, build_ethernet_frame(mac_host, mac_gateway, 0x0800, build_ipv4_packet("192.168.1.100", "142.250.190.46", 6, tcp_psh, 204)))

    t += 0.03
    # HTTP 200 OK
    http_resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 42\r\n\r\n<html><body>ThreatLens Verified</body></html>"
    tcp_resp = build_tcp_packet(80, 49152, seq=5001, ack=1001 + len(http_get), flags=0x18, payload=http_resp)
    writer.add_packet(t, build_ethernet_frame(mac_gateway, mac_host, 0x0800, build_ipv4_packet("142.250.190.46", "192.168.1.100", 6, tcp_resp, 205)))

    # =========================================================================
    # 2. DGA & DNS Tunneling Telemetry
    # =========================================================================
    t = base_t + 20.0
    dga_fqdn = "v8xq9p2m1k0z4w7y9l3n6c5b2r8t.tunnel-exfil.biz"
    dga_pkt = build_dns_query(dga_fqdn, qtype=16, tx_id=0x9999)  # TXT query
    udp_dga = build_udp_packet(54321, 53, dga_pkt)
    ip_dga = build_ipv4_packet("192.168.1.75", "8.8.4.4", 17, udp_dga, 301)
    writer.add_packet(t, build_ethernet_frame(mac_host, mac_gateway, 0x0800, ip_dga))

    # =========================================================================
    # 3. Periodic Botnet C2 Beaconing (5 heartbeats @ 15.0s Δt)
    # =========================================================================
    c2_ip = "198.51.100.77"
    bot_ip = "192.168.1.150"
    c2_port = 8443
    bot_port = 52140

    for i in range(5):
        t_beacon = base_t + 50.0 + (i * 15.0)
        # SYN
        syn_pkt = build_tcp_packet(bot_port, c2_port, seq=10000 + (i * 500), ack=0, flags=0x02)
        writer.add_packet(t_beacon, build_ethernet_frame(mac_host, mac_gateway, 0x0800, build_ipv4_packet(bot_ip, c2_ip, 6, syn_pkt, 400 + (i * 10))))

        # SYN-ACK
        synack_pkt = build_tcp_packet(c2_port, bot_port, seq=50000 + (i * 500), ack=10001 + (i * 500), flags=0x12)
        writer.add_packet(t_beacon + 0.015, build_ethernet_frame(mac_gateway, mac_host, 0x0800, build_ipv4_packet(c2_ip, bot_ip, 6, synack_pkt, 401 + (i * 10))))

        # PSH-ACK (Heartbeat beacon data)
        beacon_data = b"\x17\x03\x03\x00\x18" + b"BEACON_ID=9021;STATUS=ACTIVE"
        psh_pkt = build_tcp_packet(bot_port, c2_port, seq=10001 + (i * 500), ack=50001 + (i * 500), flags=0x18, payload=beacon_data)
        writer.add_packet(t_beacon + 0.025, build_ethernet_frame(mac_host, mac_gateway, 0x0800, build_ipv4_packet(bot_ip, c2_ip, 6, psh_pkt, 402 + (i * 10))))

        # FIN-ACK
        fin_pkt = build_tcp_packet(bot_port, c2_port, seq=10001 + (i * 500) + len(beacon_data), ack=50001 + (i * 500), flags=0x11)
        writer.add_packet(t_beacon + 0.05, build_ethernet_frame(mac_host, mac_gateway, 0x0800, build_ipv4_packet(bot_ip, c2_ip, 6, fin_pkt, 403 + (i * 10))))

    # =========================================================================
    # 4. Volumetric TCP SYN Flood Attack (60 packets burst)
    # =========================================================================
    t_syn = base_t + 200.0
    target_ip = "192.168.1.1"
    attacker_ip = "203.0.113.88"

    for idx in range(60):
        t_pkt = t_syn + (idx * 0.01)  # 10ms intervals = 100 PPS rate
        syn_flood = build_tcp_packet(src_port=30000 + idx, dst_port=80, seq=100000 + idx, ack=0, flags=0x02)
        ip_flood = build_ipv4_packet(attacker_ip, target_ip, 6, syn_flood, ip_id=1000 + idx)
        writer.add_packet(t_pkt, build_ethernet_frame(mac_attacker, mac_gateway, 0x0800, ip_flood))

    # =========================================================================
    # 5. Internal Reconnaissance Port Sweep (35 ports)
    # =========================================================================
    t_recon = base_t + 240.0
    recon_src = "192.168.1.99"
    recon_dst = "192.168.1.200"

    for port_offset in range(35):
        t_scan = t_recon + (port_offset * 0.03)
        scan_tcp = build_tcp_packet(src_port=45000, dst_port=1000 + port_offset, seq=200000 + port_offset, ack=0, flags=0x02)
        ip_scan = build_ipv4_packet(recon_src, recon_dst, 6, scan_tcp, ip_id=2000 + port_offset)
        writer.add_packet(t_scan, build_ethernet_frame(mac_host, mac_gateway, 0x0800, ip_scan))

    written_path = writer.write()
    print(f"[ThreatLens] Successfully generated sample PCAP: {written_path}")
    print(f"[ThreatLens] Total packets encoded: {len(writer.packets)}")
    return written_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate ThreatLens sample attack PCAP")
    parser.add_argument("--output", default="pcaps/sample_attack.pcap", help="Output path for .pcap file")
    args = parser.parse_args()

    generate_pcap(args.output)
