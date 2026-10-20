use crate::error::{FastFlowError, Result};
use std::net::Ipv4Addr;

/// Represents a parsed zero-copy IPv4 packet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Header<'a> {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub options: &'a [u8],
    pub payload: &'a [u8],
}

impl<'a> Ipv4Header<'a> {
    pub const MIN_HEADER_LEN: usize = 20;

    /// Parses an IPv4 packet header without allocations.
    ///
    /// Validates version, header length, bounds, and saturates payload slices
    /// safely even on truncated captures.
    #[inline(always)]
    pub fn parse(packet: &'a [u8]) -> Result<Self> {
        if packet.len() < Self::MIN_HEADER_LEN {
            return Err(FastFlowError::BufferUnderflow {
                needed: Self::MIN_HEADER_LEN,
                available: packet.len(),
            });
        }

        let ver_ihl = packet[0];
        let version = ver_ihl >> 4;
        let ihl = ver_ihl & 0x0F;

        if version != 4 {
            return Err(FastFlowError::InvalidProtocolVersion {
                expected: 4,
                actual: version,
            });
        }

        if ihl < 5 {
            return Err(FastFlowError::InvalidHeaderLength {
                min: Self::MIN_HEADER_LEN,
                actual: (ihl as usize) * 4,
            });
        }

        let header_bytes = (ihl as usize) * 4;
        if packet.len() < header_bytes {
            return Err(FastFlowError::BufferUnderflow {
                needed: header_bytes,
                available: packet.len(),
            });
        }

        let tos = packet[1];
        let dscp = tos >> 2;
        let ecn = tos & 0x03;

        let total_length = u16::from_be_bytes([packet[2], packet[3]]);
        let identification = u16::from_be_bytes([packet[4], packet[5]]);

        let flags_fo = u16::from_be_bytes([packet[6], packet[7]]);
        let flags = ((flags_fo & 0xE000) >> 13) as u8;
        let fragment_offset = flags_fo & 0x1FFF;

        let ttl = packet[8];
        let protocol = packet[9];
        let checksum = u16::from_be_bytes([packet[10], packet[11]]);

        let src_addr = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dst_addr = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

        let options = &packet[Self::MIN_HEADER_LEN..header_bytes];

        let payload_len = (total_length as usize).saturating_sub(header_bytes);
        let available_payload = packet.len() - header_bytes;
        let slice_end = header_bytes + std::cmp::min(payload_len, available_payload);

        Ok(Self {
            version,
            ihl,
            dscp,
            ecn,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl,
            protocol,
            checksum,
            src_addr,
            dst_addr,
            options,
            payload: &packet[header_bytes..slice_end],
        })
    }

    /// Verifies the 16-bit one's complement Internet Checksum of the IPv4 header.
    #[inline]
    pub fn verify_checksum(&self, raw_header: &[u8]) -> bool {
        let header_bytes = (self.ihl as usize) * 4;
        if raw_header.len() < header_bytes {
            return false;
        }

        compute_internet_checksum(&raw_header[..header_bytes]) == 0
    }

    /// Returns `true` if the Don't Fragment (DF) flag is set.
    #[inline(always)]
    pub const fn dont_fragment(&self) -> bool {
        (self.flags & 0x02) != 0
    }

    /// Returns `true` if the More Fragments (MF) flag is set.
    #[inline(always)]
    pub const fn more_fragments(&self) -> bool {
        (self.flags & 0x01) != 0
    }

    /// Returns `true` if this packet is an IPv4 fragment.
    #[inline(always)]
    pub const fn is_fragment(&self) -> bool {
        self.more_fragments() || self.fragment_offset > 0
    }
}

/// Computes the 16-bit one's complement Internet Checksum across a byte slice.
#[inline]
#[allow(clippy::chunks_exact_to_as_chunks)]
pub fn compute_internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);

    for chunk in &mut chunks {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }

    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        sum = sum.wrapping_add((remainder[0] as u32) << 8);
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_ipv4_parse() {
        let raw = [
            0x45, 0x00, 0x00, 0x28, // Ver/IHL (0x45), Total Length (40)
            0x1c, 0x46, 0x40, 0x00, // ID, Flags (DF=1), Frag Offset (0)
            0x40, 0x06, 0x9b, 0x36, // TTL (64), Protocol (TCP=6), Checksum (0x9b36)
            0xc0, 0xa8, 0x01, 0x01, // Src: 192.168.1.1
            0xc0, 0xa8, 0x01, 0x02, // Dst: 192.168.1.2
            // 20 bytes payload
            0x00, 0x50, 0x1f, 0x90, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
            0x20, 0x00, 0x91, 0x7c, 0x00, 0x00,
        ];

        let ip = Ipv4Header::parse(&raw).expect("Valid IPv4 packet");
        assert_eq!(ip.version, 4);
        assert_eq!(ip.ihl, 5);
        assert_eq!(ip.total_length, 40);
        assert_eq!(ip.protocol, 6);
        assert_eq!(ip.src_addr, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(ip.dst_addr, Ipv4Addr::new(192, 168, 1, 2));
        assert!(ip.dont_fragment());
        assert!(!ip.is_fragment());
        assert_eq!(ip.payload.len(), 20);
        assert!(ip.verify_checksum(&raw));
    }

    #[test]
    fn test_invalid_version_and_underflow() {
        let short = [0x45, 0x00];
        assert!(Ipv4Header::parse(&short).is_err());

        let mut bad_version = [0u8; 20];
        bad_version[0] = 0x65; // Version 6 in IPv4 parser
        assert!(Ipv4Header::parse(&bad_version).is_err());
    }
}
