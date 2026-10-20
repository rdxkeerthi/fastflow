use crate::error::{FastFlowError, Result};

/// Represents a parsed zero-copy UDP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpHeader<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: &'a [u8],
}

impl<'a> UdpHeader<'a> {
    pub const HEADER_LEN: usize = 8;

    /// Parses a UDP header without allocations.
    #[inline(always)]
    pub fn parse(packet: &'a [u8]) -> Result<Self> {
        if packet.len() < Self::HEADER_LEN {
            return Err(FastFlowError::BufferUnderflow {
                needed: Self::HEADER_LEN,
                available: packet.len(),
            });
        }

        let src_port = u16::from_be_bytes([packet[0], packet[1]]);
        let dst_port = u16::from_be_bytes([packet[2], packet[3]]);
        let length = u16::from_be_bytes([packet[4], packet[5]]);
        let checksum = u16::from_be_bytes([packet[6], packet[7]]);

        let payload_len = (length as usize).saturating_sub(Self::HEADER_LEN);
        let available = packet.len() - Self::HEADER_LEN;
        let effective_len = std::cmp::min(payload_len, available);

        Ok(Self {
            src_port,
            dst_port,
            length,
            checksum,
            payload: &packet[Self::HEADER_LEN..Self::HEADER_LEN + effective_len],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_udp_parse() {
        let raw = [
            0x00, 0x35, // src: 53 (DNS)
            0xd0, 0x01, // dst: 53249
            0x00, 0x0c, // len: 12 (8 header + 4 payload)
            0x00, 0x00, // checksum
            0x01, 0x02, 0x03, 0x04, // payload
        ];

        let udp = UdpHeader::parse(&raw).expect("Valid UDP");
        assert_eq!(udp.src_port, 53);
        assert_eq!(udp.dst_port, 53249);
        assert_eq!(udp.length, 12);
        assert_eq!(udp.payload, &[0x01, 0x02, 0x03, 0x04]);
    }
}
