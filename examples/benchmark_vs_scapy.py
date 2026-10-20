#!/usr/bin/env python3
"""
Benchmark comparison script between FastFlow (Rust) and standard Python tools.
"""

import struct
import tempfile
import time

from fastflow import FlowAggregator


def generate_synthetic_pcap(filepath: str, num_packets: int = 100_000):
    print(f"[*] Generating synthetic PCAP with {num_packets:,} packets...")
    global_hdr = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    eth = bytes.fromhex("001122334455aabbccddeeff0800")
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 40, 1, 0x4000, 64, 6, 0,
        bytes([192, 168, 1, 100]),
        bytes([10, 0, 0, 1])
    )
    tcp = struct.pack("!HHIIBBHHH", 443, 12345, 1, 0, (5 << 4), 0x02, 65535, 0, 0)
    pkt = eth + ip + tcp
    rec_hdr = struct.pack("<IIII", 1700000000, 0, len(pkt), len(pkt))

    with open(filepath, "wb") as f:
        f.write(global_hdr)
        for _ in range(num_packets):
            f.write(rec_hdr)
            f.write(pkt)
    print(f"[+] File ready: {filepath}")

def main():
    packet_count = 100_000
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        pcap_path = tmp.name

    generate_synthetic_pcap(pcap_path, packet_count)

    print("\n--- BENCHMARKING FASTFLOW (RUST ZERO-COPY) ---")
    start = time.perf_counter()
    agg = FlowAggregator(pcap_path)
    records = agg.parse_all()
    duration = time.perf_counter() - start
    pps = len(records) / duration

    print(f"Time Taken  : {duration:.4f} seconds")
    print(f"Throughput  : {pps:,.0f} packets/second")

if __name__ == "__main__":
    main()
