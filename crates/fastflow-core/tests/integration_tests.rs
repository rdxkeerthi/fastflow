use fastflow_core::aggregator::TrafficAggregator;
use fastflow_core::pcap::PcapEngine;
use std::io::Write;
use tempfile::NamedTempFile;

fn create_test_pcap_file() -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("Create tempfile");

    // 24-byte PCAP header (Microseconds, Little-Endian, Snaplen 65535, LinkType 1 = Ethernet)
    let pcap_header: [u8; 24] = [
        0xd4, 0xc3, 0xb2, 0xa1, // magic (little endian microsecond)
        0x02, 0x00, // major 2
        0x04, 0x00, // minor 4
        0x00, 0x00, 0x00, 0x00, // tz
        0x00, 0x00, 0x00, 0x00, // sigfigs
        0xff, 0xff, 0x00, 0x00, // snaplen 65535
        0x01, 0x00, 0x00, 0x00, // linktype 1 (Ethernet)
    ];
    file.write_all(&pcap_header).unwrap();

    // Packet 1: 54 bytes (14 eth + 20 ipv4 + 20 tcp)
    let packet1_body = [
        // Ethernet: Dst 00:11:22:33:44:55, Src aa:bb:cc:dd:ee:ff, Type IPv4 (0x0800)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x00,
        // IPv4: Ver 4, IHL 5, len 40, TTL 64, TCP (6), Src 192.168.1.50, Dst 10.0.0.1
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 168, 1, 50, 10,
        0, 0, 1,
        // TCP: Src 443, Dst 54321, Seq 100, Ack 0, Offset 5 (20 bytes), Flags SYN (0x02), Win 65535
        0x01, 0xbb, 0xd4, 0x31, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff,
        0xff, 0x00, 0x00, 0x00, 0x00,
    ];

    // Packet 1 Record Header (16 bytes)
    let p1_rec: [u8; 16] = [
        100,
        0,
        0,
        0, // ts_sec = 100
        50,
        0,
        0,
        0, // ts_usec = 50
        packet1_body.len() as u8,
        0,
        0,
        0, // caplen
        packet1_body.len() as u8,
        0,
        0,
        0, // origlen
    ];
    file.write_all(&p1_rec).unwrap();
    file.write_all(&packet1_body).unwrap();

    // Packet 2: 54 bytes (reverse flow from 10.0.0.1:54321 to 192.168.1.50:443, SYN+ACK)
    let packet2_body = [
        // Ethernet
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
        // IPv4: Src 10.0.0.1, Dst 192.168.1.50
        0x45, 0x00, 0x00, 0x28, 0x00, 0x02, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1, 192,
        168, 1, 50,
        // TCP: Src 54321, Dst 443, Seq 200, Ack 101, Offset 5, Flags SYN+ACK (0x12)
        0xd4, 0x31, 0x01, 0xbb, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x65, 0x50, 0x12, 0xff,
        0xff, 0x00, 0x00, 0x00, 0x00,
    ];

    let p2_rec: [u8; 16] = [
        100,
        0,
        0,
        0, // ts_sec = 100
        150,
        0,
        0,
        0, // ts_usec = 150
        packet2_body.len() as u8,
        0,
        0,
        0,
        packet2_body.len() as u8,
        0,
        0,
        0,
    ];
    file.write_all(&p2_rec).unwrap();
    file.write_all(&packet2_body).unwrap();

    file.flush().unwrap();
    file
}

#[test]
fn test_pcap_engine_end_to_end() {
    let temp_file = create_test_pcap_file();
    let engine = PcapEngine::open(temp_file.path()).expect("Open PCAP");

    assert_eq!(engine.header.major_version, 2);
    assert_eq!(engine.header.minor_version, 4);

    let offsets = engine.locate_record_offsets();
    assert_eq!(offsets.len(), 2);

    let records = engine.parse_all_records_parallel();
    assert_eq!(records.len(), 2);

    // Verify record 1
    assert_eq!(records[0].src_ip.unwrap().to_string(), "192.168.1.50");
    assert_eq!(records[0].dst_ip.unwrap().to_string(), "10.0.0.1");
    assert_eq!(records[0].src_port, Some(443));
    assert_eq!(records[0].dst_port, Some(54321));
    assert_eq!(records[0].protocol, Some(6));

    // Verify record 2
    assert_eq!(records[1].src_ip.unwrap().to_string(), "10.0.0.1");
    assert_eq!(records[1].dst_ip.unwrap().to_string(), "192.168.1.50");
    assert_eq!(records[1].src_port, Some(54321));
    assert_eq!(records[1].dst_port, Some(443));

    // Verify aggregator
    let mut agg = TrafficAggregator::new();
    agg.ingest_batch(&records);

    assert_eq!(agg.total_packets(), 2);
    assert_eq!(agg.total_bytes(), 108);

    // Canonical bidirectional flow should group both packets into 1 flow
    let top_flows = agg.top_flows(10);
    assert_eq!(top_flows.len(), 1);
    assert_eq!(top_flows[0].1.packet_count, 2);
    assert_eq!(top_flows[0].1.syn_count, 2); // Both had SYN flag set

    let top_talkers = agg.top_talkers_by_packets(5);
    assert_eq!(top_talkers.len(), 2);
}
