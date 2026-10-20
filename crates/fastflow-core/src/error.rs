use thiserror::Error;

/// Exhaustive error taxonomy for fastflow parsing engine.
///
/// Designed to guarantee zero-panic parsing: all malformed inputs, truncated
/// buffers, integer overflows, and corrupted packet headers are returned as
/// structured, non-fatal errors.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum FastFlowError {
    #[error("Buffer underflow: needed {needed} bytes, but only {available} bytes available")]
    BufferUnderflow { needed: usize, available: usize },

    #[error("Buffer overflow: requested {size} exceeds buffer capacity {capacity}")]
    BufferOverflow { size: usize, capacity: usize },

    #[error("Invalid protocol version: expected {expected}, encountered {actual}")]
    InvalidProtocolVersion { expected: u8, actual: u8 },

    #[error("Invalid header length: minimum {min} bytes required, but got {actual} bytes")]
    InvalidHeaderLength { min: usize, actual: usize },

    #[error("Invalid PCAP global header: {0}")]
    InvalidPcapHeader(&'static str),

    #[error("Invalid PCAP packet record: {0}")]
    InvalidPacketRecord(&'static str),

    #[error("Malformed frame: {0}")]
    MalformedFrame(&'static str),

    #[error("Unsupported EtherType: 0x{0:04x}")]
    UnsupportedEtherType(u16),

    #[error("Unsupported IP protocol: {0}")]
    UnsupportedProtocol(u8),

    #[error("DNS parsing error: {0}")]
    DnsParsingError(&'static str),

    #[error("Cyclic or excessively deep DNS compression pointer detected at offset {0}")]
    DnsPointerLoop(usize),

    #[error("Integer overflow detected during calculation: {0}")]
    IntegerOverflow(&'static str),

    #[error("I/O error: {0}")]
    IoError(String),
}

impl From<std::io::Error> for FastFlowError {
    fn from(err: std::io::Error) -> Self {
        FastFlowError::IoError(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, FastFlowError>;
