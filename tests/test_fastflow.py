import os
import struct
import tempfile

import fastflow
import pytest


def get_data_path(filename: str) -> str:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(current_dir, "data", filename)


def create_sample_pcap(filepath: str) -> None:
    # Global header (24 bytes): LE, microseconds, snaplen 65535, Ethernet (linktype 1)
    global_hdr = struct.pack(
        "<IHHIIII",
        0xA1B2C3D4,  # magic
        2, 4,        # major, minor
        0, 0,        # tz, sigfigs
        65535, 1     # snaplen, linktype Ethernet
    )

    # Frame 1: Ethernet + IPv4 + TCP SYN
    eth1 = bytes.fromhex("001122334455aabbccddeeff0800")
    ip1 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0x00, 40,
        1, 0x4000, 64, 6, 0,
        bytes([192, 168, 1, 100]),
        bytes([10, 0, 0, 1])
    )
    tcp1 = struct.pack(
        "!HHIIBBHHH",
        443, 12345, 1000, 0, (5 << 4), 0x02, 65535, 0, 0
    )
    pkt1 = eth1 + ip1 + tcp1
    rec1_hdr = struct.pack("<IIII", 1700000000, 500000, len(pkt1), len(pkt1))

    # Frame 2: Ethernet + IPv4 + UDP (DNS)
    eth2 = bytes.fromhex("aabbccddeeff0011223344550800")
    ip2 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0x00, 28,
        2, 0x4000, 64, 17, 0,
        bytes([10, 0, 0, 1]),
        bytes([8, 8, 8, 8])
    )
    udp2 = struct.pack("!HHHH", 53535, 53, 8, 0)
    pkt2 = eth2 + ip2 + udp2
    rec2_hdr = struct.pack("<IIII", 1700000001, 250000, len(pkt2), len(pkt2))

    with open(filepath, "wb") as f:
        f.write(global_hdr)
        f.write(rec1_hdr)
        f.write(pkt1)
        f.write(rec2_hdr)
        f.write(pkt2)


def test_flow_aggregator_basic():
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        pcap_path = tmp.name

    try:
        create_sample_pcap(pcap_path)

        agg = fastflow.FlowAggregator(pcap_path)
        assert agg.packet_count() == 2

        records = agg.parse_all()
        assert len(records) == 2

        # Packet 1
        r1 = records[0]
        assert r1.src_ip == "192.168.1.100"
        assert r1.dst_ip == "10.0.0.1"
        assert r1.src_port == 443
        assert r1.dst_port == 12345
        assert r1.protocol == 6
        assert r1.tcp_flags == 0x02
        assert r1.timestamp == pytest.approx(1700000000.5, rel=1e-6)

        # To dict integration
        d = r1.to_dict()
        assert d["src_ip"] == "192.168.1.100"
        assert d["protocol"] == 6

        # Top talkers
        talkers = agg.top_talkers(limit=5)
        assert len(talkers) == 2
        ips = [ip for ip, _ in talkers]
        assert "192.168.1.100" in ips
        assert "10.0.0.1" in ips

        # Filter by port
        dns_pkts = agg.filter_by_port(53)
        assert len(dns_pkts) == 1
        assert dns_pkts[0].dst_ip == "8.8.8.8"

        # Filter by IP
        ip_pkts = agg.filter_by_ip("10.0.0.1")
        assert len(ip_pkts) == 2
    finally:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)


def test_streaming_iterator():
    sample_path = get_data_path("sample_web_traffic.pcap")
    assert os.path.exists(sample_path)

    agg = fastflow.FlowAggregator(sample_path)
    count = 0
    total_bytes = 0

    for pkt in agg:
        count += 1
        total_bytes += pkt.captured_len
        assert pkt.timestamp > 1700000000.0
        assert pkt.captured_len > 0

    assert count == 9
    assert total_bytes > 0

    # Also test iter_packets() directly
    iter_pkts = list(agg.iter_packets())
    assert len(iter_pkts) == 9


def test_real_web_traffic_pcap():
    sample_path = get_data_path("sample_web_traffic.pcap")
    agg = fastflow.FlowAggregator(sample_path)

    assert agg.packet_count() == 9
    records = agg.parse_all()
    assert len(records) == 9

    # Check talkers
    talkers = agg.top_talkers(5)
    assert len(talkers) >= 2
    client_ip, count = talkers[0]
    assert client_ip == "192.168.1.45"
    assert count == 5

    # Check protocol distribution (6 = TCP, 17 = UDP)
    dist = agg.protocol_distribution()
    assert 6 in dist
    assert 17 in dist
    assert dist[6] == 7  # 7 TCP packets
    assert dist[17] == 2 # 2 DNS UDP packets

    # Check bandwidth timeline
    timeline = agg.bandwidth_timeline(bucket_secs=1.0)
    assert len(timeline) >= 1
    assert timeline[0].packet_count == 9
    assert timeline[0].bandwidth_bps > 0
    t_dict = timeline[0].to_dict()
    assert "bandwidth_bps" in t_dict


def test_syn_scan_anomaly_detection():
    scan_path = get_data_path("syn_scan.pcap")
    agg = fastflow.FlowAggregator(scan_path)

    assert agg.packet_count() == 16
    alerts = agg.detect_anomalies()
    assert len(alerts) >= 1

    scan_alert = alerts[0]
    assert scan_alert.anomaly_type == "VerticalPortScan"
    assert scan_alert.source_ip == "192.168.1.150"
    assert scan_alert.target_ip == "10.0.0.50"
    assert "16 distinct" in scan_alert.details

    # Test alert dictionary representation
    alert_dict = scan_alert.to_dict()
    assert alert_dict["anomaly_type"] == "VerticalPortScan"
    assert alert_dict["source_ip"] == "192.168.1.150"


def test_shannon_entropy_detection():
    # Low entropy standard domains
    normal_entropy = fastflow.compute_shannon_entropy("google.com")
    assert 2.0 < normal_entropy < 3.0

    wikipedia_entropy = fastflow.shannon_entropy("wikipedia.org")
    assert 2.0 < wikipedia_entropy < 3.5

    # High entropy DGA / DNS exfiltration domain names
    dga_domain = "c2f9d8a1b7e641c883e0a3f9124cb11a.tunnel.evil-attacker.org"
    dga_entropy = fastflow.shannon_entropy(dga_domain)
    assert dga_entropy > 4.0

    # Empty string edge case
    assert fastflow.compute_shannon_entropy("") == 0.0


def test_dns_exfiltration_pcap():
    dns_path = get_data_path("dns_exfiltration.pcap")
    agg = fastflow.FlowAggregator(dns_path)
    assert agg.packet_count() == 5

    records = agg.parse_all()
    assert len(records) == 5
    for r in records:
        assert r.protocol == 17  # UDP
        assert r.dst_port == 53


def test_malformed_corrupt_pcap_safety():
    """Verifies that corrupt, truncated, or cyclic packets do NOT crash or hang FastFlow."""
    corrupt_path = get_data_path("malformed_corrupt.pcap")
    agg = fastflow.FlowAggregator(corrupt_path)

    # File contains 4 edge-case packets:
    # 1. Truncated IP
    # 2. Malicious TCP option with len < 2
    # 3. DNS pointer cycle loop
    # 4. Truncated capture length
    count = agg.packet_count()
    assert count == 4

    # parse_all must complete without panic, infinite loop, or memory leak
    records = agg.parse_all()
    assert len(records) == 4

    # Streaming iterator must also terminate cleanly without crash
    streamed = list(agg)
    assert len(streamed) == 4


def test_invalid_pcap_file():
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(b"not a valid pcap header content here")
        pcap_path = tmp.name

    try:
        with pytest.raises(ValueError):
            fastflow.FlowAggregator(pcap_path)
    finally:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)


def test_package_version():
    assert fastflow.__version__ == "0.2.0"

