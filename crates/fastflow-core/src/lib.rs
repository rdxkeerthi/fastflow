//! # FastFlow Core (`fastflow-core`)
//!
//! Ultra-high-performance zero-copy network packet and telemetry parsing engine written in Rust.
//!
//! Designed for high-speed packet ingestion, Security Operations Centers (SOCs),
//! SIEM event collectors, and AI observability pipelines.
//!
//! ## Core Architecture Guarantees
//! - **Zero Heap Allocations in Hot Path:** Protocol headers borrow directly from underlying buffer slices (`&'a [u8]`).
//! - **Guaranteed Zero-Panic:** All slice boundaries, frame truncations, and malformed inputs are strictly validated.
//! - **SIMD & Multi-Core Scaling:** Transparent parallel batch packet parsing across all CPU threads via Rayon.
//! - **Memory-Mapped I/O:** Powered by `memmap2` to parse multi-gigabyte PCAP captures in milliseconds.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod aggregator;
pub mod error;
pub mod pcap;
pub mod protocols;
pub mod zero_copy;

// Convenient top-level re-exports
pub use aggregator::{FlowKey, FlowMetrics, TrafficAggregator};
pub use error::{FastFlowError, Result};
pub use pcap::{PacketRecord, PcapEngine, PcapHeader, TimestampResolution};
pub use protocols::dns::{DnsHeader, DnsMessage, DnsQuestion, DnsRecord, DnsType};
pub use protocols::ethernet::{EtherType, EthernetFrame, MacAddress};
pub use protocols::icmp::{IcmpHeader, IcmpType};
pub use protocols::ipv4::Ipv4Header;
pub use protocols::ipv6::Ipv6Header;
pub use protocols::tcp::{TcpFlags, TcpHeader};
pub use protocols::udp::UdpHeader;
pub use zero_copy::ByteCursor;
