use crate::error::{FastFlowError, Result};

/// DNS Record Types (RFC 1035 / RFC 3596).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsType {
    A,
    Ns,
    Cname,
    Soa,
    Ptr,
    Mx,
    Txt,
    Aaaa,
    Srv,
    Any,
    Unknown(u16),
}

impl From<u16> for DnsType {
    #[inline]
    fn from(val: u16) -> Self {
        match val {
            1 => DnsType::A,
            2 => DnsType::Ns,
            5 => DnsType::Cname,
            6 => DnsType::Soa,
            12 => DnsType::Ptr,
            15 => DnsType::Mx,
            16 => DnsType::Txt,
            28 => DnsType::Aaaa,
            33 => DnsType::Srv,
            255 => DnsType::Any,
            other => DnsType::Unknown(other),
        }
    }
}

/// 12-byte standard DNS Header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    pub qr: bool, // false = query, true = response
    pub opcode: u8,
    pub aa: bool,  // Authoritative Answer
    pub tc: bool,  // Truncation
    pub rd: bool,  // Recursion Desired
    pub ra: bool,  // Recursion Available
    pub rcode: u8, // Response Code
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DnsHeader {
    pub const HEADER_LEN: usize = 12;

    #[inline]
    pub fn parse(packet: &[u8]) -> Result<Self> {
        if packet.len() < Self::HEADER_LEN {
            return Err(FastFlowError::BufferUnderflow {
                needed: Self::HEADER_LEN,
                available: packet.len(),
            });
        }

        let id = u16::from_be_bytes([packet[0], packet[1]]);
        let flags = u16::from_be_bytes([packet[2], packet[3]]);

        let qr = (flags & 0x8000) != 0;
        let opcode = ((flags >> 11) & 0x0F) as u8;
        let aa = (flags & 0x0400) != 0;
        let tc = (flags & 0x0200) != 0;
        let rd = (flags & 0x0100) != 0;
        let ra = (flags & 0x0080) != 0;
        let rcode = (flags & 0x000F) as u8;

        let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
        let ancount = u16::from_be_bytes([packet[6], packet[7]]);
        let nscount = u16::from_be_bytes([packet[8], packet[9]]);
        let arcount = u16::from_be_bytes([packet[10], packet[11]]);

        Ok(Self {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        })
    }
}

/// Parsed DNS Question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: DnsType,
    pub qclass: u16,
}

/// Parsed DNS Resource Record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord<'a> {
    pub name: String,
    pub rtype: DnsType,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: &'a [u8],
}

/// High-level DNS message view.
#[derive(Debug, Clone)]
pub struct DnsMessage<'a> {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord<'a>>,
}

const MAX_DNS_POINTER_DEPTH: usize = 16;
const MAX_DNS_NAME_LENGTH: usize = 255;
const MAX_DNS_LABEL_LENGTH: usize = 63;

/// Computes the Shannon entropy of a string (e.g. domain name).
///
/// Commonly used in SOC environments to detect Domain Generation Algorithms (DGA)
/// and DNS tunneling/data exfiltration (entropy typically > 3.8).
pub fn compute_shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    let mut len = 0usize;
    for &b in s.as_bytes() {
        if b != b'.' {
            counts[b as usize] += 1;
            len += 1;
        }
    }
    if len == 0 {
        return 0.0;
    }
    let len_f = len as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / len_f;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Reads a domain name safely from a DNS packet with compression pointer support,
/// visited offset cycle tracking, and RFC 1035 length enforcement.
pub fn read_dns_name(packet: &[u8], mut offset: usize) -> Result<(String, usize)> {
    let mut name = String::with_capacity(64);
    let mut jumps = 0usize;
    let mut initial_consumed = 0usize;
    let mut has_jumped = false;
    let mut visited_offsets = [0usize; MAX_DNS_POINTER_DEPTH];

    loop {
        if offset >= packet.len() {
            return Err(FastFlowError::BufferUnderflow {
                needed: 1,
                available: 0,
            });
        }

        let len = packet[offset];

        // Compression pointer (two leading bits 11)
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= packet.len() {
                return Err(FastFlowError::BufferUnderflow {
                    needed: 2,
                    available: packet.len() - offset,
                });
            }

            if jumps >= MAX_DNS_POINTER_DEPTH {
                return Err(FastFlowError::DnsPointerLoop(offset));
            }

            let pointer_target = (((len & 0x3F) as usize) << 8) | (packet[offset + 1] as usize);
            if pointer_target >= packet.len() {
                return Err(FastFlowError::DnsParsingError(
                    "Pointer target outside DNS packet bounds",
                ));
            }

            // Explicit visited cycle detection
            if visited_offsets[..jumps].contains(&pointer_target) {
                return Err(FastFlowError::DnsPointerLoop(pointer_target));
            }
            visited_offsets[jumps] = pointer_target;
            jumps += 1;

            if !has_jumped {
                initial_consumed = offset + 2;
                has_jumped = true;
            }

            offset = pointer_target;
            continue;
        }

        // Null terminator: end of domain name
        if len == 0 {
            if !has_jumped {
                initial_consumed = offset + 1;
            }
            break;
        }

        // Standard label
        let label_len = len as usize;
        if label_len > MAX_DNS_LABEL_LENGTH {
            return Err(FastFlowError::DnsParsingError(
                "DNS label exceeds RFC 1035 max length (63 bytes)",
            ));
        }

        if name.len() + label_len + 1 > MAX_DNS_NAME_LENGTH {
            return Err(FastFlowError::DnsParsingError(
                "DNS total domain name exceeds RFC 1035 max length (255 bytes)",
            ));
        }

        offset += 1;

        if offset + label_len > packet.len() {
            return Err(FastFlowError::BufferUnderflow {
                needed: label_len,
                available: packet.len() - offset,
            });
        }

        if !name.is_empty() {
            name.push('.');
        }

        let label_bytes = &packet[offset..offset + label_len];
        if let Ok(label_str) = std::str::from_utf8(label_bytes) {
            name.push_str(label_str);
        } else {
            // Safe fallback for binary/non-utf8 label
            for &b in label_bytes {
                if b.is_ascii_graphic() {
                    name.push(b as char);
                } else {
                    name.push('?');
                }
            }
        }

        offset += label_len;
    }

    Ok((name, initial_consumed))
}

impl<'a> DnsMessage<'a> {
    /// Parses a complete DNS message from payload with loop and bounds protections.
    pub fn parse(packet: &'a [u8]) -> Result<Self> {
        let header = DnsHeader::parse(packet)?;
        let mut cursor = DnsHeader::HEADER_LEN;

        let mut questions = Vec::with_capacity(header.qdcount as usize);
        for _ in 0..header.qdcount {
            let (qname, next_cursor) = read_dns_name(packet, cursor)?;
            cursor = next_cursor;

            if cursor + 4 > packet.len() {
                return Err(FastFlowError::BufferUnderflow {
                    needed: 4,
                    available: packet.len().saturating_sub(cursor),
                });
            }

            let qtype = DnsType::from(u16::from_be_bytes([packet[cursor], packet[cursor + 1]]));
            let qclass = u16::from_be_bytes([packet[cursor + 2], packet[cursor + 3]]);
            cursor += 4;

            questions.push(DnsQuestion {
                qname,
                qtype,
                qclass,
            });
        }

        let mut answers = Vec::with_capacity(header.ancount as usize);
        for _ in 0..header.ancount {
            if cursor >= packet.len() {
                break;
            }

            let (name, next_cursor) = read_dns_name(packet, cursor)?;
            cursor = next_cursor;

            if cursor + 10 > packet.len() {
                break;
            }

            let rtype = DnsType::from(u16::from_be_bytes([packet[cursor], packet[cursor + 1]]));
            let rclass = u16::from_be_bytes([packet[cursor + 2], packet[cursor + 3]]);
            let ttl = u32::from_be_bytes([
                packet[cursor + 4],
                packet[cursor + 5],
                packet[cursor + 6],
                packet[cursor + 7],
            ]);
            let rdlength = u16::from_be_bytes([packet[cursor + 8], packet[cursor + 9]]) as usize;
            cursor += 10;

            if cursor + rdlength > packet.len() {
                break;
            }

            let rdata = &packet[cursor..cursor + rdlength];
            cursor += rdlength;

            answers.push(DnsRecord {
                name,
                rtype,
                rclass,
                ttl,
                rdata,
            });
        }

        Ok(Self {
            header,
            questions,
            answers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_header_and_query_parse() {
        // DNS query for "example.com" type A
        let packet = [
            0x12, 0x34, // ID
            0x01, 0x00, // Flags: Standard Query, RD=1
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            // QNAME: 7example3com0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
        ];

        let dns = DnsMessage::parse(&packet).expect("Valid DNS query");
        assert_eq!(dns.header.id, 0x1234);
        assert!(!dns.header.qr);
        assert!(dns.header.rd);
        assert_eq!(dns.questions.len(), 1);
        assert_eq!(dns.questions[0].qname, "example.com");
        assert_eq!(dns.questions[0].qtype, DnsType::A);
    }

    #[test]
    fn test_dns_pointer_cycle_detection() {
        // Cyclic compression pointer pointing directly to itself
        let bad_packet = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0,
            0x0C, // points to offset 12 (itself)
            0x00, 0x01, 0x00, 0x01,
        ];

        let result = DnsMessage::parse(&bad_packet);
        assert!(result.is_err());
    }
}
