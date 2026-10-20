#![no_main]
use libfuzzer_sys::fuzz_target;
use fastflow_core::protocols::dns::DnsMessage;
use fastflow_core::protocols::ethernet::EthernetFrame;
use fastflow_core::protocols::icmp::IcmpHeader;
use fastflow_core::protocols::ipv4::Ipv4Header;
use fastflow_core::protocols::ipv6::Ipv6Header;
use fastflow_core::protocols::tcp::TcpHeader;
use fastflow_core::protocols::udp::UdpHeader;

fuzz_target!(|data: &[u8]| {
    // Protocol parsers must NEVER panic, crash, or enter an infinite loop
    let _ = EthernetFrame::parse(data);
    let _ = Ipv4Header::parse(data);
    let _ = Ipv6Header::parse(data);
    let _ = TcpHeader::parse(data);
    let _ = UdpHeader::parse(data);
    let _ = IcmpHeader::parse(data);
    let _ = DnsMessage::parse(data);
});
