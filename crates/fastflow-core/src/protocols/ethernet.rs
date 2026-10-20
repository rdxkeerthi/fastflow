use crate::error::{FastFlowError, Result};
use std::fmt;

/// 6-byte IEEE 802.3 MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub const BROADCAST: Self = Self([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    pub const ZERO: Self = Self([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    #[inline(always)]
    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    #[inline(always)]
    pub const fn octets(&self) -> [u8; 6] {
        self.0
    }

    #[inline(always)]
    pub fn is_multicast(&self) -> bool {
        (self.0[0] & 0x01) != 0
    }

    #[inline(always)]
    pub fn is_broadcast(&self) -> bool {
        self.0 == Self::BROADCAST.0
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

/// Standard EtherType values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EtherType {
    Ipv4,
    Ipv6,
    Arp,
    VlanTagged,
    ProviderBridging,
    Lldp,
    Unknown(u16),
}

impl From<u16> for EtherType {
    #[inline(always)]
    fn from(val: u16) -> Self {
        match val {
            0x0800 => EtherType::Ipv4,
            0x86DD => EtherType::Ipv6,
            0x0806 => EtherType::Arp,
            0x8100 => EtherType::VlanTagged,
            0x88A8 => EtherType::ProviderBridging,
            0x88CC => EtherType::Lldp,
            other => EtherType::Unknown(other),
        }
    }
}

impl EtherType {
    #[inline(always)]
    pub const fn raw(&self) -> u16 {
        match self {
            EtherType::Ipv4 => 0x0800,
            EtherType::Ipv6 => 0x86DD,
            EtherType::Arp => 0x0806,
            EtherType::VlanTagged => 0x8100,
            EtherType::ProviderBridging => 0x88A8,
            EtherType::Lldp => 0x88CC,
            EtherType::Unknown(v) => *v,
        }
    }
}

/// Represents a parsed zero-copy Ethernet II frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthernetFrame<'a> {
    pub dst_mac: MacAddress,
    pub src_mac: MacAddress,
    pub vlan_id: Option<u16>,
    pub ether_type: EtherType,
    pub payload: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    pub const HEADER_LEN: usize = 14;

    /// Parses an Ethernet II frame from a byte buffer without heap allocations.
    ///
    /// Automatically handles standard 802.1Q single and double (QinQ) VLAN tags,
    /// extracting the inner EtherType and payload safely with strict bounds checking.
    #[inline]
    pub fn parse(packet: &'a [u8]) -> Result<Self> {
        if packet.len() < Self::HEADER_LEN {
            return Err(FastFlowError::BufferUnderflow {
                needed: Self::HEADER_LEN,
                available: packet.len(),
            });
        }

        let dst_mac = MacAddress([
            packet[0], packet[1], packet[2], packet[3], packet[4], packet[5],
        ]);
        let src_mac = MacAddress([
            packet[6], packet[7], packet[8], packet[9], packet[10], packet[11],
        ]);

        let mut offset = 12;
        let mut raw_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        offset += 2;

        let mut vlan_id = None;

        // Check for 802.1Q (0x8100) or 802.1ad QinQ (0x88A8)
        while raw_type == 0x8100 || raw_type == 0x88A8 {
            if packet.len() < offset + 4 {
                return Err(FastFlowError::BufferUnderflow {
                    needed: offset + 4,
                    available: packet.len(),
                });
            }
            let tci = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
            vlan_id = Some(tci & 0x0FFF);
            offset += 2;

            raw_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
            offset += 2;
        }

        let ether_type = EtherType::from(raw_type);
        let payload = &packet[offset..];

        Ok(Self {
            dst_mac,
            src_mac,
            vlan_id,
            ether_type,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethernet_basic_parse() {
        let frame_bytes = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // src
            0x08, 0x00, // IPv4
            0xDE, 0xAD, 0xBE, 0xEF, // payload
        ];

        let frame = EthernetFrame::parse(&frame_bytes).expect("Valid Ethernet frame");
        assert_eq!(frame.dst_mac.to_string(), "00:11:22:33:44:55");
        assert_eq!(frame.src_mac.to_string(), "aa:bb:cc:dd:ee:ff");
        assert_eq!(frame.ether_type, EtherType::Ipv4);
        assert_eq!(frame.vlan_id, None);
        assert_eq!(frame.payload, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_ethernet_vlan_parse() {
        let frame_bytes = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // src
            0x81, 0x00, // 802.1Q
            0x00, 0x64, // VLAN ID 100
            0x08, 0x00, // IPv4
            0x12, 0x34, // payload
        ];

        let frame = EthernetFrame::parse(&frame_bytes).expect("Valid VLAN frame");
        assert_eq!(frame.vlan_id, Some(100));
        assert_eq!(frame.ether_type, EtherType::Ipv4);
        assert_eq!(frame.payload, &[0x12, 0x34]);
    }

    #[test]
    fn test_underflow() {
        let short = [0x00, 0x11, 0x22];
        assert!(EthernetFrame::parse(&short).is_err());
    }
}
