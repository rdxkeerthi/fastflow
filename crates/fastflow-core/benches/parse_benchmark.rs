use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use fastflow_core::protocols::ethernet::EthernetFrame;
use fastflow_core::protocols::ipv4::Ipv4Header;
use fastflow_core::protocols::tcp::TcpHeader;

fn build_benchmark_packet() -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);
    // Ethernet Header (14 bytes)
    packet.extend_from_slice(&[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // src
        0x08, 0x00, // IPv4
    ]);
    // IPv4 Header (20 bytes)
    packet.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x32, // Ver/IHL, len 50
        0x12, 0x34, 0x40, 0x00, // ID, flags (DF)
        0x40, 0x06, 0x00, 0x00, // TTL 64, TCP
        192, 168, 1, 100, // src IP
        10, 0, 0, 1, // dst IP
    ]);
    // TCP Header (20 bytes)
    packet.extend_from_slice(&[
        0x1f, 0x90, 0x01, 0xbb, // src 8080, dst 443
        0x00, 0x00, 0x00, 0x01, // seq
        0x00, 0x00, 0x00, 0x02, // ack
        0x50, 0x18, 0x72, 0x10, // data offset 5, PSH+ACK, window
        0x00, 0x00, 0x00, 0x00, // checksum, urgent pointer
    ]);
    // Payload (10 bytes)
    packet.extend_from_slice(b"FASTFLOW10");
    packet
}

fn bench_ethernet_parse(c: &mut Criterion) {
    let packet = build_benchmark_packet();
    let mut group = c.benchmark_group("zero_copy_parsing");
    group.throughput(Throughput::Bytes(packet.len() as u64));

    group.bench_function("parse_ethernet_frame", |b| {
        b.iter(|| {
            let frame = EthernetFrame::parse(black_box(&packet)).unwrap();
            black_box(frame);
        })
    });

    group.bench_function("parse_ipv4_header", |b| {
        let ip_slice = &packet[14..];
        b.iter(|| {
            let ip = Ipv4Header::parse(black_box(ip_slice)).unwrap();
            black_box(ip);
        })
    });

    group.bench_function("parse_tcp_header", |b| {
        let tcp_slice = &packet[34..];
        b.iter(|| {
            let tcp = TcpHeader::parse(black_box(tcp_slice)).unwrap();
            black_box(tcp);
        })
    });

    group.bench_function("parse_full_packet_stack", |b| {
        b.iter(|| {
            let eth = EthernetFrame::parse(black_box(&packet)).unwrap();
            let ip = Ipv4Header::parse(eth.payload).unwrap();
            let tcp = TcpHeader::parse(ip.payload).unwrap();
            black_box((eth, ip, tcp));
        })
    });

    group.finish();
}

criterion_group!(benches, bench_ethernet_parse);
criterion_main!(benches);
