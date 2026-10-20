use crate::pcap::PacketRecord;
use std::collections::HashMap;
use std::net::IpAddr;

/// 5-Tuple flow identifier (Network flow key).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

impl FlowKey {
    /// Creates a bidirectional canonical flow key such that packets from A->B
    /// and B->A map to the same flow key.
    pub fn canonical(&self) -> Self {
        if self.src_ip < self.dst_ip
            || (self.src_ip == self.dst_ip && self.src_port <= self.dst_port)
        {
            *self
        } else {
            Self {
                src_ip: self.dst_ip,
                dst_ip: self.src_ip,
                src_port: self.dst_port,
                dst_port: self.src_port,
                protocol: self.protocol,
            }
        }
    }
}

/// Aggregated metrics for a single network flow.
#[derive(Debug, Clone, Default)]
pub struct FlowMetrics {
    pub packet_count: u64,
    pub byte_count: u64,
    pub first_seen_secs: u32,
    pub first_seen_sub: u32,
    pub last_seen_secs: u32,
    pub last_seen_sub: u32,
    pub syn_count: u32,
    pub fin_count: u32,
    pub rst_count: u32,
}

impl FlowMetrics {
    pub fn update(&mut self, record: &PacketRecord) {
        if self.packet_count == 0 {
            self.first_seen_secs = record.timestamp_secs;
            self.first_seen_sub = record.timestamp_sub;
        }
        self.last_seen_secs = record.timestamp_secs;
        self.last_seen_sub = record.timestamp_sub;

        self.packet_count += 1;
        self.byte_count += record.captured_len as u64;

        if let Some(flags) = record.tcp_flags {
            if (flags & 0x0002) != 0 {
                self.syn_count += 1;
            }
            if (flags & 0x0001) != 0 {
                self.fin_count += 1;
            }
            if (flags & 0x0004) != 0 {
                self.rst_count += 1;
            }
        }
    }

    pub fn duration_seconds(&self) -> f64 {
        let start = (self.first_seen_secs as f64) + ((self.first_seen_sub as f64) / 1_000_000.0);
        let end = (self.last_seen_secs as f64) + ((self.last_seen_sub as f64) / 1_000_000.0);
        (end - start).max(0.0)
    }
}

/// High-throughput telemetry and traffic aggregator.
#[derive(Debug, Default)]
pub struct TrafficAggregator {
    flows: HashMap<FlowKey, FlowMetrics>,
    ip_packet_counts: HashMap<IpAddr, u64>,
    ip_byte_counts: HashMap<IpAddr, u64>,
    protocol_counts: HashMap<u8, u64>,
    port_counts: HashMap<u16, u64>,
    total_packets: u64,
    total_bytes: u64,
}

impl TrafficAggregator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingests a single packet record into all aggregate metrics.
    pub fn ingest(&mut self, record: &PacketRecord) {
        self.total_packets += 1;
        self.total_bytes += record.captured_len as u64;

        if let Some(src) = record.src_ip {
            *self.ip_packet_counts.entry(src).or_insert(0) += 1;
            *self.ip_byte_counts.entry(src).or_insert(0) += record.captured_len as u64;
        }

        if let Some(proto) = record.protocol {
            *self.protocol_counts.entry(proto).or_insert(0) += 1;
        }

        if let Some(dst_port) = record.dst_port {
            *self.port_counts.entry(dst_port).or_insert(0) += 1;
        }

        if let (Some(src_ip), Some(dst_ip), Some(src_port), Some(dst_port), Some(protocol)) = (
            record.src_ip,
            record.dst_ip,
            record.src_port,
            record.dst_port,
            record.protocol,
        ) {
            let key = FlowKey {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol,
            }
            .canonical();

            self.flows.entry(key).or_default().update(record);
        }
    }

    /// Batch ingest an entire slice of packet records.
    pub fn ingest_batch(&mut self, records: &[PacketRecord]) {
        for record in records {
            self.ingest(record);
        }
    }

    /// Returns top talkers ranked by total transmitted packets.
    pub fn top_talkers_by_packets(&self, limit: usize) -> Vec<(IpAddr, u64)> {
        let mut sorted: Vec<(IpAddr, u64)> = self
            .ip_packet_counts
            .iter()
            .map(|(&ip, &c)| (ip, c))
            .collect();
        sorted.sort_unstable_by_key(|a| std::cmp::Reverse(a.1));
        sorted.truncate(limit);
        sorted
    }

    /// Returns top talkers ranked by total transmitted bytes.
    pub fn top_talkers_by_bytes(&self, limit: usize) -> Vec<(IpAddr, u64)> {
        let mut sorted: Vec<(IpAddr, u64)> = self
            .ip_byte_counts
            .iter()
            .map(|(&ip, &c)| (ip, c))
            .collect();
        sorted.sort_unstable_by_key(|a| std::cmp::Reverse(a.1));
        sorted.truncate(limit);
        sorted
    }

    /// Returns the top canonical flow conversations ranked by volume.
    pub fn top_flows(&self, limit: usize) -> Vec<(FlowKey, FlowMetrics)> {
        let mut sorted: Vec<(FlowKey, FlowMetrics)> =
            self.flows.iter().map(|(&k, m)| (k, m.clone())).collect();
        sorted.sort_unstable_by_key(|a| std::cmp::Reverse(a.1.byte_count));
        sorted.truncate(limit);
        sorted
    }

    /// Returns protocol distribution (protocol number -> count).
    pub fn protocol_distribution(&self) -> &HashMap<u8, u64> {
        &self.protocol_counts
    }

    /// Returns port distribution (destination port -> count).
    pub fn port_distribution(&self) -> &HashMap<u16, u64> {
        &self.port_counts
    }

    pub fn total_packets(&self) -> u64 {
        self.total_packets
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}
