# fastflow-core ⚡

[![Crates.io](https://img.shields.io/crates/v/fastflow-core.svg)](https://crates.io/crates/fastflow-core)
[![Documentation](https://docs.rs/fastflow-core/badge.svg)](https://docs.rs/fastflow-core)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/rdxkeerthi/fastflow)

Ultra-high-performance, zero-copy network packet parsing and flow telemetry aggregation engine written in pure Rust.

Designed for modern **Security Operations Centers (SOCs)**, **Network Threat Hunting**, and **High-Frequency Ingestion Systems**.

---

## ⚡ Features

- **Zero-Copy Slicing**: Direct byte-slice borrows (`&[u8]`) from memory-mapped PCAP buffers.
- **Multi-Core Rayon Engine**: Parallel packet parsing scaling across all available CPU cores.
- **Built-in Security Hardening**:
  - RFC 1035 cyclic DNS pointer detection bitset (prevents infinite loop attacks).
  - TCP option length bounds checks (`CVE-Guard` halting on option length `< 2`).
  - Bounded IPv6 extension header traversal (depth limit 8).
  - `#![deny(unsafe_op_in_unsafe_fn)]` with zero `unsafe` in protocol decoders.
- **Streaming Iterator**: `PcapIter` zero-allocation packet stream processing.
- **Traffic Telemetry & Flow Metrics**: Bidirectional 5-tuple flow canonicalization, top talkers, and bandwidth time-sliced bucketing.
- **Automated Anomaly Detection**: Built-in heuristic identification for SYN floods, vertical port scans, and horizontal subnet sweeps.
- **Threat Intelligence**: Shannon entropy computation for detecting DGA domains and DNS tunneling exfiltration.

---

## 📦 Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
fastflow-core = "0.2"
```

### Example: Parsing & Aggregation

```rust
use fastflow_core::pcap::PcapEngine;
use fastflow_core::aggregator::TrafficAggregator;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let engine = PcapEngine::open("capture.pcap")?;
    println!("Indexed {} packets in capture", engine.locate_record_offsets().len());

    // Multi-core parallel parsing
    let records = engine.parse_all_records_parallel();

    // Flow aggregation & telemetry
    let mut aggregator = TrafficAggregator::new();
    aggregator.ingest_batch(&records);

    // Top talkers
    for (ip, count) in aggregator.top_talkers_by_packets(5) {
        println!("{ip}: {count} packets");
    }

    // Security anomaly detection
    for alert in aggregator.detect_anomalies() {
        println!("Security Alert: {:?}", alert);
    }

    Ok(())
}
```

---

## 📄 License

Dual-licensed under MIT or Apache-2.0.
