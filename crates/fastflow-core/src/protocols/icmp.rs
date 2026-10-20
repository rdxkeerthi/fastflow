use crate::error::{FastFlowError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpType {
    EchoReply,
    DestinationUnreachable,
    SourceQuench,
    Redirect,
    EchoRequest,
    TimeExceeded,
    ParameterProblem,
    Timestamp,
    TimestampReply,
    Unknown(u8),
}

impl From<u8> for IcmpType {
    #[inline(always)]
    fn from(val: u8) -> Self {
        match val {
            0 => IcmpType::EchoReply,
            3 => IcmpType::DestinationUnreachable,
            4 => IcmpType::SourceQuench,
            5 => IcmpType::Redirect,
            8 => IcmpType::EchoRequest,
            11 => IcmpType::TimeExceeded,
            12 => IcmpType::ParameterProblem,
            13 => IcmpType::Timestamp,
            14 => IcmpType::TimestampReply,
            other => IcmpType::Unknown(other),
        }
    }
}

/// Represents a parsed zero-copy ICMP packet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpHeader<'a> {
    pub icmp_type: IcmpType,
    pub raw_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub rest_of_header: [u8; 4],
    pub payload: &'a [u8],
}

impl<'a> IcmpHeader<'a> {
    pub const HEADER_LEN: usize = 8;

    /// Parses an ICMP packet header without allocations.
    #[inline(always)]
    pub fn parse(packet: &'a [u8]) -> Result<Self> {
        if packet.len() < Self::HEADER_LEN {
            return Err(FastFlowError::BufferUnderflow {
                needed: Self::HEADER_LEN,
                available: packet.len(),
            });
        }

        let raw_type = packet[0];
        let code = packet[1];
        let checksum = u16::from_be_bytes([packet[2], packet[3]]);
        let rest_of_header = [packet[4], packet[5], packet[6], packet[7]];
        let payload = &packet[Self::HEADER_LEN..];

        Ok(Self {
            icmp_type: IcmpType::from(raw_type),
            raw_type,
            code,
            checksum,
            rest_of_header,
            payload,
        })
    }

    /// For Echo Request/Reply: returns (identifier, sequence_number).
    #[inline(always)]
    pub fn echo_id_and_seq(&self) -> Option<(u16, u16)> {
        match self.icmp_type {
            IcmpType::EchoRequest | IcmpType::EchoReply => {
                let id = u16::from_be_bytes([self.rest_of_header[0], self.rest_of_header[1]]);
                let seq = u16::from_be_bytes([self.rest_of_header[2], self.rest_of_header[3]]);
                Some((id, seq))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_icmp_echo() {
        let raw = [
            0x08, 0x00, // type: Echo Request, code: 0
            0x4d, 0x58, // checksum
            0x12, 0x34, // id
            0x00, 0x01, // seq
            0x61, 0x62, 0x63, // payload "abc"
        ];

        let icmp = IcmpHeader::parse(&raw).expect("Valid ICMP");
        assert_eq!(icmp.icmp_type, IcmpType::EchoRequest);
        assert_eq!(icmp.code, 0);
        assert_eq!(icmp.echo_id_and_seq(), Some((0x1234, 1)));
        assert_eq!(icmp.payload, b"abc");
    }
}
