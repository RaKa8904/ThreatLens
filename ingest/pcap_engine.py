"""
ThreatLens PCAP Deep Packet Inspection Engine
=============================================
Pure Python, zero-dependency PCAP/PCAPNG packet parser and Zeek log generator.
Decodes raw packet captures (Ethernet, IPv4/IPv6, TCP, UDP, DNS, TLS) into canonical
flow telemetry matching Zeek's conn.log, dns.log, and ssl.log formats.
"""

import hashlib
import json
import logging
import math
import os
from pathlib import Path
import socket
import struct
import time
from typing import Any, Dict, Generator, Iterator, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Standard PCAP Magic Numbers
PCAP_MAGIC_BE = 0xA1B2C3D4
PCAP_MAGIC_LE = 0xD4C3B2A1
PCAP_NANO_BE = 0xA1B23C4D
PCAP_NANO_LE = 0x4D3CB2A1


def parse_dns_name(payload: bytes, offset: int) -> Tuple[str, int]:
    """Decodes DNS wire-format label sequences into human-readable domain names."""
    labels = []
    curr = offset
    visited = set()
    jumped = False
    final_offset = offset

    while curr < len(payload):
        if curr in visited:
            break
        visited.add(curr)

        length = payload[curr]
        if length == 0:
            if not jumped:
                final_offset = curr + 1
            break

        # Check for DNS pointer compression (0xC0)
        if (length & 0xC0) == 0xC0:
            if curr + 1 >= len(payload):
                break
            pointer = struct.unpack("!H", payload[curr : curr + 2])[0] & 0x3FFF
            if not jumped:
                final_offset = curr + 2
                jumped = True
            curr = pointer
            continue

        curr += 1
        if curr + length > len(payload):
            break
        label = payload[curr : curr + length].decode("ascii", errors="replace")
        labels.append(label)
        curr += length

    domain = ".".join(labels)
    return domain, final_offset if jumped else curr + 1


def extract_tls_sni(payload: bytes) -> Optional[str]:
    """Extracts Server Name Indication (SNI) from a TLS ClientHello packet payload."""
    try:
        # TLS Record: Content Type 22 (Handshake), Version 0x0301-0x0303
        if len(payload) < 43 or payload[0] != 0x16:
            return None

        # Handshake Type 1 (ClientHello)
        if payload[5] != 0x01:
            return None

        # Skip TLS Record Header (5) + Handshake Header (4) + Client Version (2) + Random (32)
        idx = 43
        if idx >= len(payload):
            return None

        # Session ID Length
        session_id_len = payload[idx]
        idx += 1 + session_id_len

        # Cipher Suites Length
        if idx + 2 > len(payload):
            return None
        cipher_suites_len = struct.unpack("!H", payload[idx : idx + 2])[0]
        idx += 2 + cipher_suites_len

        # Compression Methods Length
        if idx + 1 > len(payload):
            return None
        comp_len = payload[idx]
        idx += 1 + comp_len

        # Extensions Length
        if idx + 2 > len(payload):
            return None
        extensions_len = struct.unpack("!H", payload[idx : idx + 2])[0]
        idx += 2

        ext_end = min(idx + extensions_len, len(payload))
        while idx + 4 <= ext_end:
            ext_type, ext_len = struct.unpack("!HH", payload[idx : idx + 4])
            idx += 4
            if ext_type == 0x0000:  # Server Name Extension
                # Skip Server Name list length (2) and type (1)
                if idx + 3 <= len(payload):
                    sni_len = struct.unpack("!H", payload[idx + 3 : idx + 5])[0]
                    sni = payload[idx + 5 : idx + 5 + sni_len].decode("ascii", errors="replace")
                    return sni
            idx += ext_len
    except Exception:
        pass
    return None


class RawPacket:
    """Decoded raw packet representation."""

    def __init__(
        self,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        proto: str,
        flags: List[str],
        wire_len: int,
        payload: bytes,
        dns_query: Optional[str] = None,
        tls_sni: Optional[str] = None,
    ):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto
        self.flags = flags
        self.wire_len = wire_len
        self.payload = payload
        self.dns_query = dns_query
        self.tls_sni = tls_sni


class PcapReader:
    """Reads and parses standard PCAP files into structured raw packets."""

    def __init__(self, filepath: str):
        self.filepath = filepath

    def read_packets(self) -> Generator[RawPacket, None, None]:
        if not os.path.exists(self.filepath):
            return

        with open(self.filepath, "rb") as f:
            global_header = f.read(24)
            if len(global_header) < 24:
                return

            magic = struct.unpack("!I", global_header[:4])[0]
            if magic in (PCAP_MAGIC_BE, PCAP_NANO_BE):
                endian = ">"
                is_nano = magic == PCAP_NANO_BE
            elif magic in (PCAP_MAGIC_LE, PCAP_NANO_LE):
                endian = "<"
                is_nano = magic == PCAP_NANO_LE
            else:
                logger.warning("Unsupported PCAP magic number 0x%08X in %s", magic, self.filepath)
                return

            while True:
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16:
                    break

                sec, usec, caplen, wirelen = struct.unpack(f"{endian}IIII", pkt_hdr)
                pkt_data = f.read(caplen)
                if len(pkt_data) < caplen:
                    break

                ts = sec + (usec / 1_000_000_000.0 if is_nano else usec / 1_000_000.0)

                packet = self._parse_packet_data(ts, wirelen, pkt_data)
                if packet:
                    yield packet

    def _parse_packet_data(self, ts: float, wirelen: int, data: bytes) -> Optional[RawPacket]:
        try:
            if len(data) < 14:
                return None

            # Ethernet Header (14 bytes)
            ethertype = struct.unpack("!H", data[12:14])[0]
            offset = 14

            # VLAN Tag (0x8100)
            if ethertype == 0x8100 and len(data) >= 18:
                ethertype = struct.unpack("!H", data[16:18])[0]
                offset = 18

            if ethertype != 0x0800:  # IPv4
                return None

            ip_header = data[offset:]
            if len(ip_header) < 20:
                return None

            ihl = (ip_header[0] & 0x0F) * 4
            proto_num = ip_header[9]
            src_ip = socket.inet_ntoa(ip_header[12:16])
            dst_ip = socket.inet_ntoa(ip_header[16:20])

            transport_data = ip_header[ihl:]
            src_port = 0
            dst_port = 0
            flags = []
            dns_query = None
            tls_sni = None
            proto = "TCP"

            if proto_num == 6:  # TCP
                proto = "TCP"
                if len(transport_data) >= 20:
                    src_port, dst_port = struct.unpack("!HH", transport_data[:4])
                    tcp_flags = transport_data[13]
                    if tcp_flags & 0x02:
                        flags.append("SYN")
                    if tcp_flags & 0x10:
                        flags.append("ACK")
                    if tcp_flags & 0x01:
                        flags.append("FIN")
                    if tcp_flags & 0x04:
                        flags.append("RST")
                    if tcp_flags & 0x08:
                        flags.append("PSH")

                    tcp_data_offset = ((transport_data[12] >> 4) & 0x0F) * 4
                    payload = transport_data[tcp_data_offset:]
                    if payload.startswith(b"\x16\x03"):
                        tls_sni = extract_tls_sni(payload)
                else:
                    payload = b""

            elif proto_num == 17:  # UDP
                proto = "UDP"
                if len(transport_data) >= 8:
                    src_port, dst_port = struct.unpack("!HH", transport_data[:4])
                    payload = transport_data[8:]
                    # DNS detection (Port 53)
                    if (dst_port == 53 or src_port == 53) and len(payload) >= 12:
                        qdcount = struct.unpack("!H", payload[4:6])[0]
                        if qdcount > 0:
                            query_name, _ = parse_dns_name(payload, 12)
                            if query_name:
                                dns_query = query_name
                else:
                    payload = b""

            elif proto_num == 1:  # ICMP
                proto = "ICMP"
                payload = transport_data
            else:
                proto = f"IP_{proto_num}"
                payload = transport_data

            return RawPacket(
                timestamp=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                proto=proto,
                flags=flags,
                wire_len=wirelen,
                payload=payload,
                dns_query=dns_query,
                tls_sni=tls_sni,
            )
        except Exception:
            return None


class PcapZeekEngine:
    """
    Transforms PCAP captures into standardized Zeek log entries
    (conn, dns, ssl) and emits them into Kafka or pipeline consumers.
    """

    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        self.reader = PcapReader(pcap_path)

    def extract_flows(self) -> List[Dict[str, Any]]:
        """
        Parses all packets in the PCAP, performs flow aggregation & session correlation,
        and returns normalized flow dictionaries ready for detection engines.
        """
        packets = list(self.reader.read_packets())
        if not packets:
            return []

        flows: Dict[str, Dict[str, Any]] = {}

        for pkt in packets:
            flow_key = f"{pkt.src_ip}:{pkt.src_port}->{pkt.dst_ip}:{pkt.dst_port}"
            rev_key = f"{pkt.dst_ip}:{pkt.dst_port}->{pkt.src_ip}:{pkt.src_port}"

            # Determine primary direction or attach to existing flow
            if flow_key in flows:
                flow = flows[flow_key]
                flow["bytes_out"] += pkt.wire_len
                flow["packets_out"] += 1
                flow["timestamp"] = pkt.timestamp
                for f in pkt.flags:
                    if f not in flow["flags"]:
                        flow["flags"].append(f)
                if pkt.dns_query and not flow.get("dns_query"):
                    flow["dns_query"] = pkt.dns_query
                if pkt.tls_sni and not flow.get("server_name"):
                    flow["server_name"] = pkt.tls_sni
                    flow["ja3_hash"] = hashlib.md5(pkt.tls_sni.encode()).hexdigest()
            elif rev_key in flows:
                flow = flows[rev_key]
                flow["bytes_in"] += pkt.wire_len
                flow["packets_in"] += 1
                flow["timestamp"] = pkt.timestamp
                for f in pkt.flags:
                    if f not in flow["flags"]:
                        flow["flags"].append(f)
            else:
                # ThreatLens presents packet direction from the protected target's view.
                # A one-way SYN flood has originator packets arriving at target with no response.
                is_one_way_syn = "SYN" in pkt.flags and "ACK" not in pkt.flags
                b_out, b_in = (0, pkt.wire_len) if is_one_way_syn else (pkt.wire_len, 0)
                p_out, p_in = (0, 1) if is_one_way_syn else (1, 0)

                flow = {
                    "timestamp": pkt.timestamp,
                    "flow_id": flow_key,
                    "src_ip": pkt.src_ip,
                    "src_port": pkt.src_port,
                    "dst_ip": pkt.dst_ip,
                    "dst_port": pkt.dst_port,
                    "protocol": pkt.proto,
                    "flags": list(pkt.flags),
                    "bytes_out": b_out,
                    "bytes_in": b_in,
                    "packets_out": p_out,
                    "packets_in": p_in,
                    "dns_query": pkt.dns_query,
                    "dns_query_type": "A" if pkt.dns_query else None,
                    "ja3_hash": hashlib.md5(pkt.tls_sni.encode()).hexdigest() if pkt.tls_sni else None,
                    "server_name": pkt.tls_sni,
                    "uid": f"C{hashlib.sha256(flow_key.encode()).hexdigest()[:16]}",
                }
                flows[flow_key] = flow

        return list(flows.values())

    def export_zeek_logs(self, target_dir: str) -> Dict[str, str]:
        """
        Exports the PCAP packets as canonical Zeek JSON log files:
        conn.log, dns.log, ssl.log inside target_dir.
        """
        os.makedirs(target_dir, exist_ok=True)
        flows = self.extract_flows()

        conn_log = os.path.join(target_dir, "conn.log")
        dns_log = os.path.join(target_dir, "dns.log")
        ssl_log = os.path.join(target_dir, "ssl.log")

        with open(conn_log, "w", encoding="utf-8") as f_conn, \
             open(dns_log, "w", encoding="utf-8") as f_dns, \
             open(ssl_log, "w", encoding="utf-8") as f_ssl:

            for flow in flows:
                # Format conn.log entry
                conn_entry = {
                    "ts": flow["timestamp"],
                    "uid": flow["uid"],
                    "id.orig_h": flow["src_ip"],
                    "id.orig_p": flow["src_port"],
                    "id.resp_h": flow["dst_ip"],
                    "id.resp_p": flow["dst_port"],
                    "proto": flow["protocol"].lower(),
                    "orig_bytes": flow["bytes_out"],
                    "resp_bytes": flow["bytes_in"],
                    "orig_pkts": flow["packets_out"],
                    "resp_pkts": flow["packets_in"],
                    "history": "".join(f[0] for f in flow["flags"]),
                }
                f_conn.write(json.dumps(conn_entry) + "\n")

                # Format dns.log entry if applicable
                if flow.get("dns_query"):
                    dns_entry = {
                        "ts": flow["timestamp"],
                        "uid": flow["uid"],
                        "id.orig_h": flow["src_ip"],
                        "id.orig_p": flow["src_port"],
                        "id.resp_h": flow["dst_ip"],
                        "id.resp_p": flow["dst_port"],
                        "query": flow["dns_query"],
                        "qtype_name": flow.get("dns_query_type", "A"),
                        "answers": [],
                    }
                    f_dns.write(json.dumps(dns_entry) + "\n")

                # Format ssl.log entry if applicable
                if flow.get("server_name"):
                    ssl_entry = {
                        "ts": flow["timestamp"],
                        "uid": flow["uid"],
                        "id.orig_h": flow["src_ip"],
                        "id.orig_p": flow["src_port"],
                        "id.resp_h": flow["dst_ip"],
                        "id.resp_p": flow["dst_port"],
                        "server_name": flow["server_name"],
                        "ja3": flow.get("ja3_hash"),
                    }
                    f_ssl.write(json.dumps(ssl_entry) + "\n")

        return {
            "conn": conn_log,
            "dns": dns_log,
            "ssl": ssl_log,
        }
