use crate::error::{FastFlowError, Result};
use crate::protocols::ethernet::{EtherType, EthernetFrame};
use crate::protocols::ipv4::Ipv4Header;
use crate::protocols::ipv6::Ipv6Header;
use crate::protocols::tcp::TcpHeader;
use crate::protocols::udp::UdpHeader;
use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::File;
use std::net::IpAddr;
use std::path::Path;

// Standard PCAP magic numbers
pub const PCAP_MAGIC_MICROS_SAME: u32 = 0xA1B2C3D4;
pub const PCAP_MAGIC_MICROS_SWAP: u32 = 0xD4C3B2A1;
pub const PCAP_MAGIC_NANOS_SAME: u32 = 0xA1B23C4D;
pub const PCAP_MAGIC_NANOS_SWAP: u32 = 0x4D3CB2A1;
pub const PCAP_MAGIC_MOD_SAME: u32 = 0xA1B2CD34;
pub const PCAP_MAGIC_MOD_SWAP: u32 = 0x34CDB2A1;

// Link types
pub const LINKTYPE_NULL: u32 = 0;
pub const LINKTYPE_ETHERNET: u32 = 1;
pub const LINKTYPE_RAW: u32 = 12;
pub const LINKTYPE_RAW_ALT: u32 = 101;
pub const LINKTYPE_LOOP: u32 = 108;
pub const LINKTYPE_LINUX_SLL: u32 = 113;
pub const LINKTYPE_LINUX_SLL2: u32 = 276;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteOrder {
    BigEndian,
    LittleEndian,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampResolution {
    Microseconds,
    Nanoseconds,
}

/// Global 24-byte PCAP file header.
#[derive(Debug, Clone, Copy)]
pub struct PcapHeader {
    pub magic: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub tz_offset: i32,
    pub sigfigs: u32,
    pub snaplen: u32,
    pub link_type: u32,
    pub byte_order: ByteOrder,
    pub resolution: TimestampResolution,
}

impl PcapHeader {
    pub const HEADER_LEN: usize = 24;

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::HEADER_LEN {
            return Err(FastFlowError::InvalidPcapHeader(
                "File smaller than 24-byte PCAP header",
            ));
        }

        let magic_raw = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let (byte_order, resolution) = match magic_raw {
            PCAP_MAGIC_MICROS_SAME => (
                if cfg!(target_endian = "big") {
                    ByteOrder::BigEndian
                } else {
                    ByteOrder::LittleEndian
                },
                TimestampResolution::Microseconds,
            ),
            PCAP_MAGIC_MICROS_SWAP => (
                if cfg!(target_endian = "big") {
                    ByteOrder::LittleEndian
                } else {
                    ByteOrder::BigEndian
                },
                TimestampResolution::Microseconds,
            ),
            PCAP_MAGIC_NANOS_SAME => (
                if cfg!(target_endian = "big") {
                    ByteOrder::BigEndian
                } else {
                    ByteOrder::LittleEndian
                },
                TimestampResolution::Nanoseconds,
            ),
            PCAP_MAGIC_NANOS_SWAP => (
                if cfg!(target_endian = "big") {
                    ByteOrder::LittleEndian
                } else {
                    ByteOrder::BigEndian
                },
                TimestampResolution::Nanoseconds,
            ),
            PCAP_MAGIC_MOD_SAME => (
                if cfg!(target_endian = "big") {
                    ByteOrder::BigEndian
                } else {
                    ByteOrder::LittleEndian
                },
                TimestampResolution::Microseconds,
            ),
            PCAP_MAGIC_MOD_SWAP => (
                if cfg!(target_endian = "big") {
                    ByteOrder::LittleEndian
                } else {
                    ByteOrder::BigEndian
                },
                TimestampResolution::Microseconds,
            ),
            _ => {
                return Err(FastFlowError::InvalidPcapHeader(
                    "Unrecognized PCAP magic number",
                ))
            }
        };

        let (major, minor, tz, sigfigs, snaplen, link_type) = match byte_order {
            ByteOrder::BigEndian => (
                u16::from_be_bytes([bytes[4], bytes[5]]),
                u16::from_be_bytes([bytes[6], bytes[7]]),
                i32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
                u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
                u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
                u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]),
            ),
            ByteOrder::LittleEndian => (
                u16::from_le_bytes([bytes[4], bytes[5]]),
                u16::from_le_bytes([bytes[6], bytes[7]]),
                i32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
                u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
                u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
                u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]),
            ),
        };

        Ok(Self {
            magic: magic_raw,
            major_version: major,
            minor_version: minor,
            tz_offset: tz,
            sigfigs,
            snaplen,
            link_type,
            byte_order,
            resolution,
        })
    }
}

/// Normalized parsed packet summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketRecord {
    pub timestamp_secs: u32,
    pub timestamp_sub: u32,
    pub captured_len: u32,
    pub original_len: u32,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub protocol: Option<u8>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<u16>,
    pub payload_len: usize,
}

impl PacketRecord {
    #[inline(always)]
    pub fn timestamp_float(&self, resolution: TimestampResolution) -> f64 {
        let frac_divisor = match resolution {
            TimestampResolution::Microseconds => 1_000_000.0,
            TimestampResolution::Nanoseconds => 1_000_000_000.0,
        };
        (self.timestamp_secs as f64) + ((self.timestamp_sub as f64) / frac_divisor)
    }
}

/// Zero-copy, memory-mapped PCAP parsing engine.
pub struct PcapEngine {
    mmap: Mmap,
    pub header: PcapHeader,
}

impl PcapEngine {
    /// Opens and memory-maps a PCAP file with validation.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };

        if mmap.len() < PcapHeader::HEADER_LEN {
            return Err(FastFlowError::InvalidPcapHeader(
                "File is smaller than PCAP header",
            ));
        }

        let header = PcapHeader::parse(&mmap[..PcapHeader::HEADER_LEN])?;
        Ok(Self { mmap, header })
    }

    /// Creates an engine from in-memory byte buffer (useful for testing or network socket buffers).
    pub fn from_mmap(mmap: Mmap) -> Result<Self> {
        if mmap.len() < PcapHeader::HEADER_LEN {
            return Err(FastFlowError::InvalidPcapHeader(
                "Buffer is smaller than PCAP header",
            ));
        }
        let header = PcapHeader::parse(&mmap[..PcapHeader::HEADER_LEN])?;
        Ok(Self { mmap, header })
    }

    /// Access raw memory-mapped buffer.
    #[inline(always)]
    pub fn bytes(&self) -> &[u8] {
        &self.mmap[..]
    }

    /// Scans packet record offsets sequentially without heap allocations.
    ///
    /// Guarantees termination and bounds safety even on corrupted captures.
    pub fn locate_record_offsets(&self) -> Vec<usize> {
        let mut offsets = Vec::with_capacity(65_536);
        let mut cursor = PcapHeader::HEADER_LEN;
        let data_len = self.mmap.len();
        let bytes = &self.mmap[..];
        let bo = self.header.byte_order;

        while cursor + 16 <= data_len {
            let caplen = match bo {
                ByteOrder::BigEndian => u32::from_be_bytes([
                    bytes[cursor + 8],
                    bytes[cursor + 9],
                    bytes[cursor + 10],
                    bytes[cursor + 11],
                ]) as usize,
                ByteOrder::LittleEndian => u32::from_le_bytes([
                    bytes[cursor + 8],
                    bytes[cursor + 9],
                    bytes[cursor + 10],
                    bytes[cursor + 11],
                ]) as usize,
            };

            // Bounds check for record body
            let next_cursor = match cursor.checked_add(16).and_then(|c| c.checked_add(caplen)) {
                Some(next) => next,
                None => break, // Overflow prevention
            };

            if next_cursor > data_len {
                break; // Truncated final packet
            }

            offsets.push(cursor);
            cursor = next_cursor;
        }

        offsets
    }

    /// Parses a single packet record at the specified byte offset.
    #[inline]
    pub fn parse_record_at(&self, offset: usize) -> Result<PacketRecord> {
        let bytes = &self.mmap[..];
        if offset + 16 > bytes.len() {
            return Err(FastFlowError::BufferUnderflow {
                needed: 16,
                available: bytes.len().saturating_sub(offset),
            });
        }

        let bo = self.header.byte_order;
        let (ts_sec, ts_sub, caplen, origlen) = match bo {
            ByteOrder::BigEndian => (
                u32::from_be_bytes([
                    bytes[offset],
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                ]),
                u32::from_be_bytes([
                    bytes[offset + 4],
                    bytes[offset + 5],
                    bytes[offset + 6],
                    bytes[offset + 7],
                ]),
                u32::from_be_bytes([
                    bytes[offset + 8],
                    bytes[offset + 9],
                    bytes[offset + 10],
                    bytes[offset + 11],
                ]),
                u32::from_be_bytes([
                    bytes[offset + 12],
                    bytes[offset + 13],
                    bytes[offset + 14],
                    bytes[offset + 15],
                ]),
            ),
            ByteOrder::LittleEndian => (
                u32::from_le_bytes([
                    bytes[offset],
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                ]),
                u32::from_le_bytes([
                    bytes[offset + 4],
                    bytes[offset + 5],
                    bytes[offset + 6],
                    bytes[offset + 7],
                ]),
                u32::from_le_bytes([
                    bytes[offset + 8],
                    bytes[offset + 9],
                    bytes[offset + 10],
                    bytes[offset + 11],
                ]),
                u32::from_le_bytes([
                    bytes[offset + 12],
                    bytes[offset + 13],
                    bytes[offset + 14],
                    bytes[offset + 15],
                ]),
            ),
        };

        let body_start = offset + 16;
        let body_end = body_start
            .checked_add(caplen as usize)
            .ok_or(FastFlowError::IntegerOverflow("record body overflow"))?;
        if body_end > bytes.len() {
            return Err(FastFlowError::BufferUnderflow {
                needed: caplen as usize,
                available: bytes.len() - body_start,
            });
        }

        let packet_slice = &bytes[body_start..body_end];
        let (src_ip, dst_ip, protocol, src_port, dst_port, tcp_flags, payload_len) =
            decode_packet_layers(self.header.link_type, packet_slice);

        Ok(PacketRecord {
            timestamp_secs: ts_sec,
            timestamp_sub: ts_sub,
            captured_len: caplen,
            original_len: origlen,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            tcp_flags,
            payload_len,
        })
    }

    /// Parallel processing of packet headers across all CPU threads via Rayon.
    pub fn parse_all_records_parallel(&self) -> Vec<PacketRecord> {
        let offsets = self.locate_record_offsets();
        let bytes = &self.mmap[..];
        let bo = self.header.byte_order;
        let link_type = self.header.link_type;

        offsets
            .par_iter()
            .map(|&offset| {
                let (ts_sec, ts_sub, caplen, origlen) = match bo {
                    ByteOrder::BigEndian => (
                        u32::from_be_bytes([
                            bytes[offset],
                            bytes[offset + 1],
                            bytes[offset + 2],
                            bytes[offset + 3],
                        ]),
                        u32::from_be_bytes([
                            bytes[offset + 4],
                            bytes[offset + 5],
                            bytes[offset + 6],
                            bytes[offset + 7],
                        ]),
                        u32::from_be_bytes([
                            bytes[offset + 8],
                            bytes[offset + 9],
                            bytes[offset + 10],
                            bytes[offset + 11],
                        ]),
                        u32::from_be_bytes([
                            bytes[offset + 12],
                            bytes[offset + 13],
                            bytes[offset + 14],
                            bytes[offset + 15],
                        ]),
                    ),
                    ByteOrder::LittleEndian => (
                        u32::from_le_bytes([
                            bytes[offset],
                            bytes[offset + 1],
                            bytes[offset + 2],
                            bytes[offset + 3],
                        ]),
                        u32::from_le_bytes([
                            bytes[offset + 4],
                            bytes[offset + 5],
                            bytes[offset + 6],
                            bytes[offset + 7],
                        ]),
                        u32::from_le_bytes([
                            bytes[offset + 8],
                            bytes[offset + 9],
                            bytes[offset + 10],
                            bytes[offset + 11],
                        ]),
                        u32::from_le_bytes([
                            bytes[offset + 12],
                            bytes[offset + 13],
                            bytes[offset + 14],
                            bytes[offset + 15],
                        ]),
                    ),
                };

                let body_start = offset + 16;
                let body_end = body_start + (caplen as usize);
                let packet_slice = &bytes[body_start..body_end];

                let (src_ip, dst_ip, protocol, src_port, dst_port, tcp_flags, payload_len) =
                    decode_packet_layers(link_type, packet_slice);

                PacketRecord {
                    timestamp_secs: ts_sec,
                    timestamp_sub: ts_sub,
                    captured_len: caplen,
                    original_len: origlen,
                    src_ip,
                    dst_ip,
                    protocol,
                    src_port,
                    dst_port,
                    tcp_flags,
                    payload_len,
                }
            })
            .collect()
    }
}

pub type DecodedLayers = (
    Option<IpAddr>,
    Option<IpAddr>,
    Option<u8>,
    Option<u16>,
    Option<u16>,
    Option<u16>,
    usize,
);

/// Helper function to unpack protocol layers zero-copy.
#[inline]
fn decode_packet_layers(link_type: u32, packet_slice: &[u8]) -> DecodedLayers {
    let mut ip_payload: &[u8] = &[];
    let mut src_ip = None;
    let mut dst_ip = None;
    let mut proto = None;

    match link_type {
        LINKTYPE_ETHERNET => {
            if let Ok(eth) = EthernetFrame::parse(packet_slice) {
                match eth.ether_type {
                    EtherType::Ipv4 => {
                        if let Ok(ip) = Ipv4Header::parse(eth.payload) {
                            src_ip = Some(IpAddr::V4(ip.src_addr));
                            dst_ip = Some(IpAddr::V4(ip.dst_addr));
                            proto = Some(ip.protocol);
                            ip_payload = ip.payload;
                        }
                    }
                    EtherType::Ipv6 => {
                        if let Ok(ip) = Ipv6Header::parse(eth.payload) {
                            src_ip = Some(IpAddr::V6(ip.src_addr));
                            dst_ip = Some(IpAddr::V6(ip.dst_addr));
                            proto = Some(ip.next_header);
                            ip_payload = ip.payload;
                        }
                    }
                    _ => {}
                }
            }
        }
        LINKTYPE_RAW | LINKTYPE_RAW_ALT => {
            if !packet_slice.is_empty() {
                let ver = packet_slice[0] >> 4;
                if ver == 4 {
                    if let Ok(ip) = Ipv4Header::parse(packet_slice) {
                        src_ip = Some(IpAddr::V4(ip.src_addr));
                        dst_ip = Some(IpAddr::V4(ip.dst_addr));
                        proto = Some(ip.protocol);
                        ip_payload = ip.payload;
                    }
                } else if ver == 6 {
                    if let Ok(ip) = Ipv6Header::parse(packet_slice) {
                        src_ip = Some(IpAddr::V6(ip.src_addr));
                        dst_ip = Some(IpAddr::V6(ip.dst_addr));
                        proto = Some(ip.next_header);
                        ip_payload = ip.payload;
                    }
                }
            }
        }
        LINKTYPE_LINUX_SLL if packet_slice.len() >= 16 => {
            let proto_type = u16::from_be_bytes([packet_slice[14], packet_slice[15]]);
            let inner = &packet_slice[16..];
            if proto_type == 0x0800 {
                if let Ok(ip) = Ipv4Header::parse(inner) {
                    src_ip = Some(IpAddr::V4(ip.src_addr));
                    dst_ip = Some(IpAddr::V4(ip.dst_addr));
                    proto = Some(ip.protocol);
                    ip_payload = ip.payload;
                }
            } else if proto_type == 0x86DD {
                if let Ok(ip) = Ipv6Header::parse(inner) {
                    src_ip = Some(IpAddr::V6(ip.src_addr));
                    dst_ip = Some(IpAddr::V6(ip.dst_addr));
                    proto = Some(ip.next_header);
                    ip_payload = ip.payload;
                }
            }
        }
        _ => {}
    }

    let mut src_port = None;
    let mut dst_port = None;
    let mut tcp_flags = None;
    let mut payload_len = 0;

    if let Some(p) = proto {
        match p {
            6 => {
                // TCP
                if let Ok(tcp) = TcpHeader::parse(ip_payload) {
                    src_port = Some(tcp.src_port);
                    dst_port = Some(tcp.dst_port);
                    tcp_flags = Some(tcp.flags.0);
                    payload_len = tcp.payload.len();
                }
            }
            17 => {
                // UDP
                if let Ok(udp) = UdpHeader::parse(ip_payload) {
                    src_port = Some(udp.src_port);
                    dst_port = Some(udp.dst_port);
                    payload_len = udp.payload.len();
                }
            }
            _ => {
                payload_len = ip_payload.len();
            }
        }
    }

    (
        src_ip,
        dst_ip,
        proto,
        src_port,
        dst_port,
        tcp_flags,
        payload_len,
    )
}
