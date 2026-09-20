"""
ThreatLens Sample Attack PCAP Generator Suite
================================================
Generates specialized PCAP files in the pcaps/ directory:
  - pcaps/sample_attack.pcap (Comprehensive multi-threat)
  - pcaps/recon_port_scan.pcap (Reconnaissance Port Scan)
  - pcaps/syn_flood_ddos.pcap (Volumetric SYN Flood DDoS)
  - pcaps/botnet_c2_beacon.pcap (Botnet C2 Beaconing)
  - pcaps/dga_dns_tunnel.pcap (DGA & DNS Tunneling)
"""

import os
import socket
import struct
import time
from typing import List, Tuple


def ip_checksum(header: bytes) -> int:
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
    def __init__(self, filename: str):
        self.filename = filename
        self.packets: List[Tuple[float, bytes]] = []

    def add_packet(self, timestamp: float, pkt_data: bytes) -> None:
        self.packets.append((timestamp, pkt_data))

    def write(self) -> str:
        self.packets.sort(key=lambda p: p[0])
        os.makedirs(os.path.dirname(os.path.abspath(self.filename)), exist_ok=True)
        with open(self.filename, "wb") as f:
            f.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for ts, data in self.packets:
                sec = int(ts)
                usec = int((ts - sec) * 1_000_000)
                length = len(data)
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
    flags_offset = 0x4000
    ttl = 64
    checksum = 0
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    header_pre = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, tos, total_len, ip_id, flags_offset, ttl, protocol, checksum, src_bytes, dst_bytes
    )
    chk = ip_checksum(header_pre)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, tos, total_len, ip_id, flags_offset, ttl, protocol, chk, src_bytes, dst_bytes
    )
    return header + payload


def build_tcp_packet(
    src_port: int, dst_port: int, seq: int, ack: int, flags: int, payload: bytes = b"", window: int = 64240
) -> bytes:
    data_offset = (5 << 4)
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
    flags = 0x0100
    header = struct.pack("!HHHHHH", tx_id, flags, 1, 0, 0, 0)
    qname = encode_dns_name(domain)
    qtail = struct.pack("!HH", qtype, 1)
    return header + qname + qtail


def generate_all_pcaps():
    base_t = time.time() - 300.0
    mac_host = "00:0c:29:ab:cd:01"
    mac_gateway = "00:50:56:ea:eb:ec"
    mac_attacker = "52:54:00:99:88:77"

    # 1. Reconnaissance Port Scan PCAP
    w_recon = PcapWriter("pcaps/recon_port_scan.pcap")
    recon_src = "10.42.9.88"
    recon_dst = "10.24.12.20"
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443, 9000, 9092]
    for idx, port in enumerate(scan_ports):
        t_scan = base_t + (idx * 0.02)
        tcp_pkt = build_tcp_packet(src_port=50000 + idx, dst_port=port, seq=1000 + idx, ack=0, flags=0x02)
        ip_pkt = build_ipv4_packet(recon_src, recon_dst, 6, tcp_pkt, ip_id=100 + idx)
        w_recon.add_packet(t_scan, build_ethernet_frame(mac_host, mac_gateway, 0x0800, ip_pkt))
    w_recon.write()

    # 2. Volumetric SYN Flood DDoS PCAP
    w_ddos = PcapWriter("pcaps/syn_flood_ddos.pcap")
    target_ip = "192.168.1.10"
    for idx in range(80):
        t_flood = base_t + (idx * 0.005)
        src_ip = f"203.0.113.{(idx % 20) + 1}"
        tcp_syn = build_tcp_packet(src_port=30000 + idx, dst_port=80, seq=50000 + idx, ack=0, flags=0x02)
        ip_flood = build_ipv4_packet(src_ip, target_ip, 6, tcp_syn, ip_id=500 + idx)
        w_ddos.add_packet(t_flood, build_ethernet_frame(mac_attacker, mac_gateway, 0x0800, ip_flood))
    w_ddos.write()

    # 3. Botnet C2 Beaconing PCAP
    w_c2 = PcapWriter("pcaps/botnet_c2_beacon.pcap")
    c2_ip = "198.51.100.77"
    bot_ip = "192.168.1.150"
    for i in range(6):
        t_beacon = base_t + (i * 15.0)
        syn_pkt = build_tcp_packet(52140, 8443, seq=10000 + (i * 100), ack=0, flags=0x02)
        w_c2.add_packet(t_beacon, build_ethernet_frame(mac_host, mac_gateway, 0x0800, build_ipv4_packet(bot_ip, c2_ip, 6, syn_pkt, 400 + i)))
        beacon_data = b"BEACON_HEARTBEAT_STATUS_OK"
        psh_pkt = build_tcp_packet(52140, 8443, seq=10001 + (i * 100), ack=50001, flags=0x18, payload=beacon_data)
        w_c2.add_packet(t_beacon + 0.02, build_ethernet_frame(mac_host, mac_gateway, 0x0800, build_ipv4_packet(bot_ip, c2_ip, 6, psh_pkt, 450 + i)))
    w_c2.write()

    # 4. DGA & DNS Tunneling PCAP
    w_dns = PcapWriter("pcaps/dga_dns_tunnel.pcap")
    dga_domains = [
        "v8xq9p2m1k0z4w7y9l3n6c5b2r8t.tunnel-exfil.biz",
        "k92mf84la01nqwzp73v5x9.exfil-data.info",
        "z091823719283719283719283.malicious-dns.org"
    ]
    for idx, domain in enumerate(dga_domains):
        t_dns = base_t + (idx * 2.0)
        dns_q = build_dns_query(domain, qtype=16, tx_id=0x7000 + idx)
        udp_q = build_udp_packet(54321, 53, dns_q)
        ip_q = build_ipv4_packet("192.168.1.75", "8.8.8.8", 17, udp_q, 800 + idx)
        w_dns.add_packet(t_dns, build_ethernet_frame(mac_host, mac_gateway, 0x0800, ip_q))
    w_dns.write()

    # 5. Encrypted Malware (JA3 Malicious TLS) PCAP
    w_malware = PcapWriter("pcaps/encrypted_malware.pcap")
    malware_src = "10.24.15.80"
    malware_c2 = "185.220.101.5"
    for idx in range(4):
        t_m = base_t + (idx * 3.0)
        # Construct realistic TLS ClientHello frame with malicious SNI
        tls_payload = b"\x16\x03\x01\x00\x64\x01\x00\x00\x60\x03\x03" + os.urandom(32) + b"\x00\x00\x04\xc0\x2f\xc0\x30\x01\x00\x00\x33\x00\x00\x00\x1a\x00\x18\x00\x00\x15cobalt-c2-node.darknet"
        tcp_tls = build_tcp_packet(49152 + idx, 443, seq=20000 + idx, ack=1000, flags=0x18, payload=tls_payload)
        ip_tls = build_ipv4_packet(malware_src, malware_c2, 6, tcp_tls, 900 + idx)
        w_malware.add_packet(t_m, build_ethernet_frame(mac_host, mac_gateway, 0x0800, ip_tls))
    w_malware.write()

    # 6. Data Exfiltration PCAP
    w_exfil = PcapWriter("pcaps/data_exfiltration.pcap")
    exfil_src = "10.24.22.150"
    exfil_dst = "198.51.100.99"
    for idx in range(12):
        t_ex = base_t + (idx * 0.05)
        exfil_data = b"CONFIDENTIAL_FINANCIAL_DATABASE_EXPORT_CHUNK_" + os.urandom(1200)
        tcp_ex = build_tcp_packet(55120, 8443, seq=30000 + (idx * 1250), ack=2000, flags=0x18, payload=exfil_data)
        ip_ex = build_ipv4_packet(exfil_src, exfil_dst, 6, tcp_ex, 1100 + idx)
        w_exfil.add_packet(t_ex, build_ethernet_frame(mac_host, mac_gateway, 0x0800, ip_ex))
    w_exfil.write()

    print("[ThreatLens] Successfully generated all 6 specialized PCAP samples in pcaps/")


if __name__ == "__main__":
    generate_all_pcaps()
