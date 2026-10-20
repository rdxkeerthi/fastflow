#!/usr/bin/env python3
"""
Example script demonstrating FastFlow telemetry ingestion and analysis.
"""

import sys
import time

from fastflow import FlowAggregator


def main():
    if len(sys.argv) < 2:
        print("Usage: python analyze_pcap.py <path_to_pcap>")
        sys.exit(1)

    pcap_path = sys.argv[1]
    print(f"[*] Opening PCAP file: {pcap_path}")

    start = time.perf_counter()
    aggregator = FlowAggregator(pcap_path)
    count = aggregator.packet_count()
    elapsed = time.perf_counter() - start

    print(f"[+] Total Packets: {count:,} (Indexed in {elapsed * 1000:.2f} ms)")

    # Parallel parsing
    start = time.perf_counter()
    records = aggregator.parse_all()
    parse_time = time.perf_counter() - start
    pps = count / parse_time if parse_time > 0 else 0
    print(f"[+] Parsed {len(records):,} records in {parse_time:.4f}s ({pps:,.0f} pkts/sec)")

    # Top Talkers
    print("\n--- TOP TALKERS (BY PACKET COUNT) ---")
    top_talkers = aggregator.top_talkers(limit=10)
    for rank, (ip, pkts) in enumerate(top_talkers, 1):
        print(f"  #{rank:<2} {ip:<20} {pkts:>10,} packets")

    # Protocol Distribution
    print("\n--- PROTOCOL DISTRIBUTION ---")
    protos = aggregator.protocol_distribution()
    proto_names = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
    for proto_id, cnt in sorted(protos.items(), key=lambda x: x[1], reverse=True):
        name = proto_names.get(proto_id, f"Unknown ({proto_id})")
        print(f"  {name:<15} {cnt:>10,} packets")

if __name__ == "__main__":
    main()
