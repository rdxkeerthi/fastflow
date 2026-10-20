use crate::error::{FastFlowError, Result};
use std::net::Ipv6Addr;

/// Represents a parsed zero-copy IPv6 packet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Header<'a> {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_addr: Ipv6Addr,
    pub dst_addr: Ipv6Addr,
    pub payload: &'a [u8],
}

impl<'a> Ipv6Header<'a> {
    pub const HEADER_LEN: usize = 40;

    /// Parses an IPv6 packet header without allocations.
    #[inline(always)]
    pub fn parse(packet: &'a [u8]) -> Result<Self> {
        if packet.len() < Self::HEADER_LEN {
            return Err(FastFlowError::BufferUnderflow {
                needed: Self::HEADER_LEN,
                available: packet.len(),
            });
        }

        let first_word = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
        let version = ((first_word >> 28) & 0x0F) as u8;
        if version != 6 {
            return Err(FastFlowError::InvalidProtocolVersion {
                expected: 6,
                actual: version,
            });
        }

        let traffic_class = ((first_word >> 20) & 0xFF) as u8;
        let flow_label = first_word & 0x000F_FFFF;

        let payload_length = u16::from_be_bytes([packet[4], packet[5]]);
        let next_header = packet[6];
        let hop_limit = packet[7];

        let mut src_bytes = [0u8; 16];
        src_bytes.copy_from_slice(&packet[8..24]);
        let src_addr = Ipv6Addr::from(src_bytes);

        let mut dst_bytes = [0u8; 16];
        dst_bytes.copy_from_slice(&packet[24..40]);
        let dst_addr = Ipv6Addr::from(dst_bytes);

        let available_payload = packet.len() - Self::HEADER_LEN;
        let effective_len = std::cmp::min(payload_length as usize, available_payload);
        let payload = &packet[Self::HEADER_LEN..Self::HEADER_LEN + effective_len];

        Ok(Self {
            version,
            traffic_class,
            flow_label,
            payload_length,
            next_header,
            hop_limit,
            src_addr,
            dst_addr,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_ipv6_parse() {
        let mut raw = [0u8; 48];
        // Version 6, traffic class 0, flow label 0x12345
        let w0: u32 = (6 << 28) | (0x12345);
        raw[0..4].copy_from_slice(&w0.to_be_bytes());
        raw[4..6].copy_from_slice(&8u16.to_be_bytes()); // payload length 8
        raw[6] = 17; // UDP
        raw[7] = 64; // hop limit
                     // Loopback ::1 src
        raw[23] = 1;
        // Dst fe80::1
        raw[24] = 0xfe;
        raw[25] = 0x80;
        raw[39] = 1;
        // Payload 8 bytes
        raw[40..48].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

        let ip = Ipv6Header::parse(&raw).expect("Valid IPv6");
        assert_eq!(ip.version, 6);
        assert_eq!(ip.flow_label, 0x12345);
        assert_eq!(ip.next_header, 17);
        assert_eq!(ip.hop_limit, 64);
        assert_eq!(ip.src_addr, Ipv6Addr::LOCALHOST);
        assert_eq!(ip.payload.len(), 8);
    }
}
