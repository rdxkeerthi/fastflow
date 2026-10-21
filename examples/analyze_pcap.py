#!/usr/bin/env python3
"""
Example script demonstrating FastFlow telemetry ingestion, flow metrics, and security anomaly detection.
"""

import os
import sys
import time

from fastflow import FlowAggregator, shannon_entropy


def main():
    if len(sys.argv) >= 2:
        pcap_path = sys.argv[1]
    else:
        # Default to bundled real test PCAP
        default_pcap = os.path.join(os.path.dirname(__file__), "..", "tests", "data", "sample_web_traffic.pcap")
        pcap_path = os.path.abspath(default_pcap)
        if not os.path.exists(pcap_path):
            print("Usage: python analyze_pcap.py <path_to_pcap>")
            sys.exit(1)
        print(f"[*] No PCAP specified, defaulting to real sample: {pcap_path}")

    print(f"[*] Opening PCAP file: {pcap_path}")

    start = time.perf_counter()
    aggregator = FlowAggregator(pcap_path)
    count = aggregator.packet_count()
    elapsed = time.perf_counter() - start

    print(f"[+] Total Packets: {count:,} (Indexed in {elapsed * 1000:.2f} ms)")

    # Parallel parsing releasing GIL
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

    # Security Anomaly Detection
    print("\n--- SECURITY ANOMALIES & THREAT DETECTION ---")
    alerts = aggregator.detect_anomalies()
    if alerts:
        for alert in alerts:
            print(f"  [ALERT] {alert.anomaly_type} from {alert.source_ip} -> {alert.target_ip or 'Broadcast'}: {alert.details}")
    else:
        print("  [+] No malicious patterns (SYN floods, port scans, subnet sweeps) detected.")

    # Bandwidth Timeline
    timeline = aggregator.bandwidth_timeline(bucket_secs=1.0)
    if timeline:
        print("\n--- BANDWIDTH TIMELINE (1s BUCKETS) ---")
        for bucket in timeline[:5]:
            bps_formatted = f"{bucket.bandwidth_bps / 1000:.1f} Kbps" if bucket.bandwidth_bps < 1_000_000 else f"{bucket.bandwidth_bps / 1_000_000:.2f} Mbps"
            print(f"  [{bucket.start_time:.3f} - {bucket.end_time:.3f}] Packets: {bucket.packet_count:<5} Bytes: {bucket.byte_count:<6} Throughput: {bps_formatted}")

    # Streaming Iterator Demonstration
    print("\n--- STREAMING ITERATOR (ZERO EXTRA HEAP ALLOCATION) ---")
    stream_count = 0
    for pkt in aggregator:
        stream_count += 1
    print(f"  [+] Streamed {stream_count} packets sequentially via `for pkt in aggregator:`")


if __name__ == "__main__":
    main()
