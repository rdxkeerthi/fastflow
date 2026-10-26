"""
Generates realistic, standards-compliant PCAP test datasets for FastFlow.

Creates:
1. tests/data/sample_web_traffic.pcap: Real HTTP/DNS/TLS web browsing session
2. tests/data/syn_scan.pcap: Reconnaissance vertical port scan against 16 distinct ports
3. tests/data/dns_exfiltration.pcap: Tunneling / DGA domain queries with high entropy
4. tests/data/malformed_corrupt.pcap: Adversarial packets (truncated, bad options, DNS loops)
"""

import os
import struct


def compute_ipv4_checksum(header: bytes) -> int:
    """Computes RFC 791 internet checksum over IPv4 header."""
    if len(header) % 2 != 0:
        header += b"\x00"
    s = sum(struct.unpack(f"!{len(header) // 2}H", header))
    while (s >> 16) > 0:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def pcap_global_header() -> bytes:
    return struct.pack(
        "<IHHIIII",
        0xA1B2C3D4,  # magic (microseconds, LE)
        2, 4,        # major, minor
        0, 0,        # thiszone, sigfigs
        65535,       # snaplen
        1,           # linktype: LINKTYPE_ETHERNET
    )


def pcap_record(ts_sec: int, ts_usec: int, payload: bytes) -> bytes:
    hdr = struct.pack("<IIII", ts_sec, ts_usec, len(payload), len(payload))
    return hdr + payload


def make_eth(dst_mac: str, src_mac: str, eth_type: int = 0x0800) -> bytes:
    dst_b = bytes.fromhex(dst_mac.replace(":", ""))
    src_b = bytes.fromhex(src_mac.replace(":", ""))
    return dst_b + src_b + struct.pack("!H", eth_type)


def make_ipv4(src_ip: str, dst_ip: str, proto: int, payload_len: int, ttl: int = 64) -> bytes:
    src_b = bytes(int(x) for x in src_ip.split("."))
    dst_b = bytes(int(x) for x in dst_ip.split("."))
    total_len = 20 + payload_len
    # Header without checksum
    hdr_no_cs = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0x00, total_len,
        0x1234, 0x4000, ttl, proto, 0,
        src_b, dst_b
    )
    cs = compute_ipv4_checksum(hdr_no_cs)
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0x00, total_len,
        0x1234, 0x4000, ttl, proto, cs,
        src_b, dst_b
    )


def make_tcp(src_port: int, dst_port: int, seq: int, ack: int, flags: int, payload: bytes = b"", options: bytes = b"") -> bytes:
    offset = (20 + len(options)) // 4
    data_offset_flags = (offset << 12) | flags
    tcp_hdr = struct.pack(
        "!HHIIHHHH",
        src_port, dst_port,
        seq, ack,
        data_offset_flags,
        64240, 0, 0
    )
    return tcp_hdr + options + payload


def make_udp(src_port: int, dst_port: int, payload: bytes = b"") -> bytes:
    length = 8 + len(payload)
    return struct.pack("!HHHH", src_port, dst_port, length, 0) + payload


def encode_dns_qname(name: str) -> bytes:
    res = bytearray()
    for part in name.strip(".").split("."):
        res.append(len(part))
        res.extend(part.encode("ascii"))
    res.append(0)
    return bytes(res)


def make_dns_query(tx_id: int, domain: str, qtype: int = 1) -> bytes:
    # Flags: 0x0100 = Standard Query, Recursion Desired
    hdr = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    qname = encode_dns_qname(domain)
    q_suffix = struct.pack("!HH", qtype, 1)  # QType, QClass (IN)
    return hdr + qname + q_suffix


def make_dns_response(tx_id: int, domain: str, answer_ip: str) -> bytes:
    # Flags: 0x8180 = Standard response, No error
    hdr = struct.pack("!HHHHHH", tx_id, 0x8180, 1, 1, 0, 0)
    qname = encode_dns_qname(domain)
    question = qname + struct.pack("!HH", 1, 1)
    # Answer using compression pointer to question name (0xc00c)
    ans_name = struct.pack("!H", 0xC00C)
    ip_bytes = bytes(int(x) for x in answer_ip.split("."))
    answer = ans_name + struct.pack("!HHIH", 1, 1, 300, 4) + ip_bytes
    return hdr + question + answer


def build_sample_web_traffic(out_path: str):
    """Creates realistic Web session (DNS query/response + HTTP/TLS 3-way handshake + GET)."""
    client_ip = "192.168.1.45"
    dns_server = "1.1.1.1"
    web_server = "104.21.28.10"
    client_mac = "00:0c:29:4f:8e:35"
    router_mac = "00:50:56:c0:00:08"

    frames = []
    base_ts = 1718000000

    # 1. DNS Query for example.com
    dns_q = make_dns_query(0x1a2b, "example.com")
    udp_dns = make_udp(51234, 53, dns_q)
    ip_dns = make_ipv4(client_ip, dns_server, 17, len(udp_dns))
    eth_dns = make_eth(router_mac, client_mac)
    frames.append((base_ts, 100000, eth_dns + ip_dns + udp_dns))

    # 2. DNS Response
    dns_r = make_dns_response(0x1a2b, "example.com", web_server)
    udp_dns_r = make_udp(53, 51234, dns_r)
    ip_dns_r = make_ipv4(dns_server, client_ip, 17, len(udp_dns_r))
    eth_dns_r = make_eth(client_mac, router_mac)
    frames.append((base_ts, 115000, eth_dns_r + ip_dns_r + udp_dns_r))

    # 3. TCP SYN (Port 443)
    tcp_syn = make_tcp(49152, 443, 1000, 0, 0x02, options=b"\x02\x04\x05\xb4\x01\x03\x03\x07")
    ip_syn = make_ipv4(client_ip, web_server, 6, len(tcp_syn))
    frames.append((base_ts, 120000, eth_dns + ip_syn + tcp_syn))

    # 4. TCP SYN-ACK
    tcp_synack = make_tcp(443, 49152, 5000, 1001, 0x12, options=b"\x02\x04\x05\xb4")
    ip_synack = make_ipv4(web_server, client_ip, 6, len(tcp_synack))
    frames.append((base_ts, 135000, eth_dns_r + ip_synack + tcp_synack))

    # 5. TCP ACK
    tcp_ack = make_tcp(49152, 443, 1001, 5001, 0x10)
    ip_ack = make_ipv4(client_ip, web_server, 6, len(tcp_ack))
    frames.append((base_ts, 136000, eth_dns + ip_ack + tcp_ack))

    # 6. HTTP GET Application Data
    http_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    tcp_data = make_tcp(49152, 443, 1001, 5001, 0x18, payload=http_payload)
    ip_data = make_ipv4(client_ip, web_server, 6, len(tcp_data))
    frames.append((base_ts, 140000, eth_dns + ip_data + tcp_data))

    # 7. HTTP 200 OK Response
    resp_payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\n<h1>FastFlow</h1>"
    tcp_resp = make_tcp(443, 49152, 5001, 1001 + len(http_payload), 0x18, payload=resp_payload)
    ip_resp = make_ipv4(web_server, client_ip, 6, len(tcp_resp))
    frames.append((base_ts, 160000, eth_dns_r + ip_resp + tcp_resp))

    # 8. Client FIN
    tcp_fin = make_tcp(49152, 443, 1001 + len(http_payload), 5001 + len(resp_payload), 0x11)
    ip_fin = make_ipv4(client_ip, web_server, 6, len(tcp_fin))
    frames.append((base_ts, 170000, eth_dns + ip_fin + tcp_fin))

    # 9. Server FIN-ACK
    tcp_finack = make_tcp(443, 49152, 5001 + len(resp_payload), 1002 + len(http_payload), 0x11)
    ip_finack = make_ipv4(web_server, client_ip, 6, len(tcp_finack))
    frames.append((base_ts, 175000, eth_dns_r + ip_finack + tcp_finack))

    with open(out_path, "wb") as f:
        f.write(pcap_global_header())
        f.writelines(pcap_record(sec, usec, pkt) for sec, usec, pkt in frames)


def build_syn_scan(out_path: str):
    """Simulates reconnaissance vertical port scan: single attacker probing 16 ports."""
    attacker_ip = "192.168.1.150"
    target_ip = "10.0.0.50"
    target_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443]

    frames = []
    base_ts = 1718001000

    for idx, port in enumerate(target_ports):
        tcp_syn = make_tcp(50000 + idx, port, 1000 + idx, 0, 0x02)
        ip = make_ipv4(attacker_ip, target_ip, 6, len(tcp_syn))
        eth = make_eth("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff")
        frames.append((base_ts, idx * 5000, eth + ip + tcp_syn))

    with open(out_path, "wb") as f:
        f.write(pcap_global_header())
        f.writelines(pcap_record(sec, usec, pkt) for sec, usec, pkt in frames)


def build_dns_exfiltration(out_path: str):
    """Simulates high-entropy DGA & DNS exfiltration tunneling queries."""
    client_ip = "10.10.20.100"
    dns_server = "8.8.4.4"

    high_entropy_domains = [
        "c2f9d8a1b7e641c883e0a3f9124cb11a.tunnel.evil-attacker.org",
        "a904fb31ce8104de01f98bc149301dae.tunnel.evil-attacker.org",
        "q3k8m1z9x4w7p2r6v5t0y1u8i3o9l2j5.beacon.malware-dga.biz",
        "8f4b2c1d9e7a6350f2e1d4c7b9a80123.exfil.data-drop.net",
        "7719abde0102456789abcdef01234567.exfil.data-drop.net",
    ]

    frames = []
    base_ts = 1718002000

    for idx, domain in enumerate(high_entropy_domains):
        dns_query = make_dns_query(0x2000 + idx, domain, qtype=16)  # TXT record query
        udp = make_udp(40000 + idx, 53, dns_query)
        ip = make_ipv4(client_ip, dns_server, 17, len(udp))
        eth = make_eth("00:50:56:c0:00:08", "00:0c:29:12:34:56")
        frames.append((base_ts, idx * 100000, eth + ip + udp))

    with open(out_path, "wb") as f:
        f.write(pcap_global_header())
        f.writelines(pcap_record(sec, usec, pkt) for sec, usec, pkt in frames)


def build_malformed_corrupt(out_path: str):
    """Creates edge-case and malformed frames to verify memory safety and zero-crash guarantee."""
    frames = []
    base_ts = 1718003000

    # Frame 1: Valid Ethernet frame with truncated IPv4 header (only 8 bytes instead of 20)
    eth1 = make_eth("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff")
    trunc_ip = bytes([0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00])
    frames.append((base_ts, 1000, eth1 + trunc_ip))

    # Frame 2: IPv4 packet with TCP header containing invalid TCP option length < 2 (CVE attack simulation)
    # Kind = 2 (MSS), Length = 0 (causes infinite loop without security guard)
    bad_opts = bytes([0x02, 0x00])
    tcp2 = make_tcp(1234, 80, 100, 0, 0x02, options=bad_opts)
    ip2 = make_ipv4("192.168.1.1", "192.168.1.2", 6, len(tcp2))
    frames.append((base_ts, 2000, eth1 + ip2 + tcp2))

    # Frame 3: DNS packet with cyclic compression pointer loop (0xC00C pointing to itself)
    # Header: ID 0x9999, Flags 0x8180, QD 1, AN 1
    dns_hdr = struct.pack("!HHHHHH", 0x9999, 0x8180, 1, 1, 0, 0)
    qname = encode_dns_qname("loop.test")
    q = qname + struct.pack("!HH", 1, 1)
    # Pointer 0xC00C points to offset 12 in DNS payload (which is 0xC00C itself -> infinite cycle!)
    cycle_ptr = struct.pack("!H", 0xC00C) + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([1, 2, 3, 4])
    dns_payload = dns_hdr + q + cycle_ptr
    udp3 = make_udp(53, 53, dns_payload)
    ip3 = make_ipv4("10.0.0.1", "10.0.0.2", 17, len(udp3))
    frames.append((base_ts, 3000, eth1 + ip3 + udp3))

    # Frame 4: Packet with capture length smaller than wire length (packet truncation / snaplen hit)
    full_payload = eth1 + make_ipv4("1.2.3.4", "5.6.7.8", 17, 100) + bytes(100)
    # We record incl_len = 34, orig_len = len(full_payload)
    rec4_hdr = struct.pack("<IIII", base_ts, 4000, 34, len(full_payload))
    frame4_raw = rec4_hdr + full_payload[:34]

    with open(out_path, "wb") as f:
        f.write(pcap_global_header())
        f.writelines(pcap_record(sec, usec, pkt) for sec, usec, pkt in frames)
        f.write(frame4_raw)


def main():
    out_dir = os.path.join(os.path.dirname(__file__), "data")
    os.makedirs(out_dir, exist_ok=True)

    files = [
        ("sample_web_traffic.pcap", build_sample_web_traffic),
        ("syn_scan.pcap", build_syn_scan),
        ("dns_exfiltration.pcap", build_dns_exfiltration),
        ("malformed_corrupt.pcap", build_malformed_corrupt),
    ]

    for filename, builder in files:
        target = os.path.join(out_dir, filename)
        builder(target)
        size = os.path.getsize(target)
        print(f"Generated {target} ({size} bytes)")


if __name__ == "__main__":
    main()
