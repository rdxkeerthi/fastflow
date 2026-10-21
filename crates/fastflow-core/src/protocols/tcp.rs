use crate::error::{FastFlowError, Result};

/// TCP control flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags(pub u16);

impl TcpFlags {
    pub const FIN: u16 = 0x0001;
    pub const SYN: u16 = 0x0002;
    pub const RST: u16 = 0x0004;
    pub const PSH: u16 = 0x0008;
    pub const ACK: u16 = 0x0010;
    pub const URG: u16 = 0x0020;
    pub const ECE: u16 = 0x0040;
    pub const CWR: u16 = 0x0080;
    pub const NS: u16 = 0x0100;

    #[inline(always)]
    pub const fn is_fin(&self) -> bool {
        (self.0 & Self::FIN) != 0
    }

    #[inline(always)]
    pub const fn is_syn(&self) -> bool {
        (self.0 & Self::SYN) != 0
    }

    #[inline(always)]
    pub const fn is_rst(&self) -> bool {
        (self.0 & Self::RST) != 0
    }

    #[inline(always)]
    pub const fn is_psh(&self) -> bool {
        (self.0 & Self::PSH) != 0
    }

    #[inline(always)]
    pub const fn is_ack(&self) -> bool {
        (self.0 & Self::ACK) != 0
    }

    #[inline(always)]
    pub const fn is_urg(&self) -> bool {
        (self.0 & Self::URG) != 0
    }

    #[inline(always)]
    pub const fn is_ece(&self) -> bool {
        (self.0 & Self::ECE) != 0
    }

    #[inline(always)]
    pub const fn is_cwr(&self) -> bool {
        (self.0 & Self::CWR) != 0
    }

    #[inline(always)]
    pub const fn is_ns(&self) -> bool {
        (self.0 & Self::NS) != 0
    }
}

/// Represents a parsed zero-copy TCP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpHeader<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub sequence_number: u32,
    pub ack_number: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: &'a [u8],
    pub payload: &'a [u8],
}

/// Parsed TCP Option according to RFC 793 and RFC 7323.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpOption<'a> {
    EndOfOptions,
    NoOperation,
    MaximumSegmentSize(u16),
    WindowScale(u8),
    SackPermitted,
    Sack(Vec<(u32, u32)>),
    Timestamp { val: u32, echo: u32 },
    Unknown { kind: u8, data: &'a [u8] },
}

impl<'a> TcpHeader<'a> {
    pub const MIN_HEADER_LEN: usize = 20;

    /// Parses a TCP segment header without allocations.
    #[inline(always)]
    pub fn parse(packet: &'a [u8]) -> Result<Self> {
        if packet.len() < Self::MIN_HEADER_LEN {
            return Err(FastFlowError::BufferUnderflow {
                needed: Self::MIN_HEADER_LEN,
                available: packet.len(),
            });
        }

        let src_port = u16::from_be_bytes([packet[0], packet[1]]);
        let dst_port = u16::from_be_bytes([packet[2], packet[3]]);
        let sequence_number = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
        let ack_number = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);

        let data_offset_byte = packet[12];
        let data_offset = data_offset_byte >> 4;
        let header_len = (data_offset as usize) * 4;

        if header_len < Self::MIN_HEADER_LEN {
            return Err(FastFlowError::InvalidHeaderLength {
                min: Self::MIN_HEADER_LEN,
                actual: header_len,
            });
        }

        if packet.len() < header_len {
            return Err(FastFlowError::BufferUnderflow {
                needed: header_len,
                available: packet.len(),
            });
        }

        let raw_flags = (((data_offset_byte as u16 & 0x01) << 8) | (packet[13] as u16)) & 0x01FF;
        let flags = TcpFlags(raw_flags);

        let window_size = u16::from_be_bytes([packet[14], packet[15]]);
        let checksum = u16::from_be_bytes([packet[16], packet[17]]);
        let urgent_pointer = u16::from_be_bytes([packet[18], packet[19]]);

        let options = &packet[Self::MIN_HEADER_LEN..header_len];
        let payload = &packet[header_len..];

        Ok(Self {
            src_port,
            dst_port,
            sequence_number,
            ack_number,
            data_offset,
            flags,
            window_size,
            checksum,
            urgent_pointer,
            options,
            payload,
        })
    }

    /// Parses TCP options with strict validation against infinite loops and underflows.
    pub fn parse_options(&self) -> Result<Vec<TcpOption<'a>>> {
        let mut opts = Vec::new();
        let mut cursor = 0;
        let data = self.options;

        while cursor < data.len() {
            let kind = data[cursor];
            if kind == 0 {
                opts.push(TcpOption::EndOfOptions);
                break;
            }
            if kind == 1 {
                opts.push(TcpOption::NoOperation);
                cursor += 1;
                continue;
            }

            if cursor + 1 >= data.len() {
                return Err(FastFlowError::BufferUnderflow {
                    needed: 2,
                    available: data.len() - cursor,
                });
            }

            let len = data[cursor + 1] as usize;
            if len < 2 {
                // SECURITY GUARD: Option length < 2 causes infinite loop (Denial of Service)
                return Err(FastFlowError::MalformedFrame(
                    "Invalid TCP option length (< 2 bytes)",
                ));
            }

            if cursor + len > data.len() {
                return Err(FastFlowError::BufferUnderflow {
                    needed: len,
                    available: data.len() - cursor,
                });
            }

            let opt_data = &data[cursor + 2..cursor + len];
            let opt = match (kind, opt_data.len()) {
                (2, 2) => {
                    TcpOption::MaximumSegmentSize(u16::from_be_bytes([opt_data[0], opt_data[1]]))
                }
                (3, 1) => TcpOption::WindowScale(opt_data[0]),
                (4, 0) => TcpOption::SackPermitted,
                (8, 8) => TcpOption::Timestamp {
                    val: u32::from_be_bytes([opt_data[0], opt_data[1], opt_data[2], opt_data[3]]),
                    echo: u32::from_be_bytes([opt_data[4], opt_data[5], opt_data[6], opt_data[7]]),
                },
                _ => TcpOption::Unknown {
                    kind,
                    data: opt_data,
                },
            };

            opts.push(opt);
            cursor += len;
        }

        Ok(opts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_tcp_parse() {
        let raw = [
            0x01, 0xbb, // src_port: 443
            0xc0, 0x00, // dst_port: 49152
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x02, // ack
            0x50, 0x12, // offset: 5 (20 bytes), flags: SYN (0x02) | ACK (0x10)
            0x72, 0x10, // window: 29200
            0x00, 0x00, // checksum
            0x00, 0x00, // urgent pointer
            0xde, 0xad, 0xbe, 0xef, // payload (4 bytes)
        ];

        let tcp = TcpHeader::parse(&raw).expect("Valid TCP");
        assert_eq!(tcp.src_port, 443);
        assert_eq!(tcp.dst_port, 49152);
        assert_eq!(tcp.sequence_number, 1);
        assert_eq!(tcp.ack_number, 2);
        assert_eq!(tcp.data_offset, 5);
        assert!(tcp.flags.is_syn());
        assert!(tcp.flags.is_ack());
        assert!(!tcp.flags.is_fin());
        assert!(!tcp.flags.is_rst());
        assert_eq!(tcp.window_size, 29200);
        assert_eq!(tcp.payload, &[0xde, 0xad, 0xbe, 0xef]);
    }
}
