use fastflow_core::pcap::{PacketRecord, TimestampResolution};
use pyo3::prelude::*;

/// Python representation of a parsed network packet.
#[pyclass(name = "PacketRecord")]
#[derive(Debug, Clone)]
pub struct PyPacketRecord {
    #[pyo3(get)]
    pub timestamp: f64,
    #[pyo3(get)]
    pub captured_len: u32,
    #[pyo3(get)]
    pub original_len: u32,
    #[pyo3(get)]
    pub src_ip: Option<String>,
    #[pyo3(get)]
    pub dst_ip: Option<String>,
    #[pyo3(get)]
    pub protocol: Option<u8>,
    #[pyo3(get)]
    pub src_port: Option<u16>,
    #[pyo3(get)]
    pub dst_port: Option<u16>,
    #[pyo3(get)]
    pub tcp_flags: Option<u16>,
    #[pyo3(get)]
    pub payload_len: usize,
}

#[pymethods]
impl PyPacketRecord {
    fn __repr__(&self) -> String {
        format!(
            "PacketRecord(ts={:.6}, src={:?}:{:?}, dst={:?}:{:?}, proto={:?}, len={})",
            self.timestamp,
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
            self.protocol,
            self.captured_len
        )
    }

    /// Converts record to a Python dictionary for direct integration with Pandas/Polars.
    pub fn to_dict(&self, py: Python<'_>) -> PyResult<PyObject> {
        let dict = pyo3::types::PyDict::new_bound(py);
        dict.set_item("timestamp", self.timestamp)?;
        dict.set_item("captured_len", self.captured_len)?;
        dict.set_item("original_len", self.original_len)?;
        dict.set_item("src_ip", &self.src_ip)?;
        dict.set_item("dst_ip", &self.dst_ip)?;
        dict.set_item("protocol", self.protocol)?;
        dict.set_item("src_port", self.src_port)?;
        dict.set_item("dst_port", self.dst_port)?;
        dict.set_item("tcp_flags", self.tcp_flags)?;
        dict.set_item("payload_len", self.payload_len)?;
        Ok(dict.into())
    }
}

impl PyPacketRecord {
    pub fn from_record(rec: &PacketRecord, resolution: TimestampResolution) -> Self {
        Self {
            timestamp: rec.timestamp_float(resolution),
            captured_len: rec.captured_len,
            original_len: rec.original_len,
            src_ip: rec.src_ip.map(|ip| ip.to_string()),
            dst_ip: rec.dst_ip.map(|ip| ip.to_string()),
            protocol: rec.protocol,
            src_port: rec.src_port,
            dst_port: rec.dst_port,
            tcp_flags: rec.tcp_flags,
            payload_len: rec.payload_len,
        }
    }
}
