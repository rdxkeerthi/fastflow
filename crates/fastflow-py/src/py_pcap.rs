use crate::conversion::PyPacketRecord;
use fastflow_core::aggregator::TrafficAggregator;
use fastflow_core::pcap::PcapEngine;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use std::collections::HashMap;

/// Aggregated flow metrics exposed to Python.
#[pyclass(name = "FlowMetrics")]
#[derive(Debug, Clone)]
pub struct PyFlowMetrics {
    #[pyo3(get)]
    pub packet_count: u64,
    #[pyo3(get)]
    pub byte_count: u64,
    #[pyo3(get)]
    pub duration: f64,
    #[pyo3(get)]
    pub syn_count: u32,
    #[pyo3(get)]
    pub fin_count: u32,
    #[pyo3(get)]
    pub rst_count: u32,
}

#[pymethods]
impl PyFlowMetrics {
    fn __repr__(&self) -> String {
        format!(
            "FlowMetrics(packets={}, bytes={}, duration={:.4}s, syn={}, fin={}, rst={})",
            self.packet_count,
            self.byte_count,
            self.duration,
            self.syn_count,
            self.fin_count,
            self.rst_count
        )
    }
}

/// High-performance multi-core PCAP analyzer and flow aggregator.
#[pyclass(name = "FlowAggregator")]
pub struct FlowAggregator {
    inner: PcapEngine,
}

#[pymethods]
impl FlowAggregator {
    #[new]
    pub fn new(filepath: &str) -> PyResult<Self> {
        PcapEngine::open(filepath)
            .map(|engine| Self { inner: engine })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Returns the total number of packets detected in the file.
    pub fn packet_count(&self, py: Python<'_>) -> usize {
        py.allow_threads(|| self.inner.locate_record_offsets().len())
    }

    /// Parses all packet records in parallel releasing the Python GIL.
    pub fn parse_all(&self, py: Python<'_>) -> PyResult<Vec<PyPacketRecord>> {
        let resolution = self.inner.header.resolution;
        let records = py.allow_threads(|| self.inner.parse_all_records_parallel());

        let py_records = records
            .into_iter()
            .map(|r| PyPacketRecord::from_record(&r, resolution))
            .collect();

        Ok(py_records)
    }

    /// Returns top talkers ranked by packet volume releasing the GIL.
    pub fn top_talkers(&self, py: Python<'_>, limit: usize) -> PyResult<Vec<(String, u64)>> {
        let stats = py.allow_threads(|| {
            let records = self.inner.parse_all_records_parallel();
            let mut agg = TrafficAggregator::new();
            agg.ingest_batch(&records);
            agg.top_talkers_by_packets(limit)
                .into_iter()
                .map(|(ip, count)| (ip.to_string(), count))
                .collect()
        });

        Ok(stats)
    }

    /// Returns top talkers ranked by byte volume releasing the GIL.
    pub fn top_talkers_by_bytes(
        &self,
        py: Python<'_>,
        limit: usize,
    ) -> PyResult<Vec<(String, u64)>> {
        let stats = py.allow_threads(|| {
            let records = self.inner.parse_all_records_parallel();
            let mut agg = TrafficAggregator::new();
            agg.ingest_batch(&records);
            agg.top_talkers_by_bytes(limit)
                .into_iter()
                .map(|(ip, bytes)| (ip.to_string(), bytes))
                .collect()
        });

        Ok(stats)
    }

    /// Returns protocol distribution breakdown `{protocol_id: count}`.
    pub fn protocol_distribution(&self, py: Python<'_>) -> PyResult<HashMap<u8, u64>> {
        let dist = py.allow_threads(|| {
            let records = self.inner.parse_all_records_parallel();
            let mut agg = TrafficAggregator::new();
            agg.ingest_batch(&records);
            agg.protocol_distribution().clone()
        });

        Ok(dist)
    }

    /// Filters packets by destination port with multi-core parallel scanning.
    pub fn filter_by_port(&self, py: Python<'_>, port: u16) -> PyResult<Vec<PyPacketRecord>> {
        let resolution = self.inner.header.resolution;
        let filtered = py.allow_threads(|| {
            let records = self.inner.parse_all_records_parallel();
            records
                .into_iter()
                .filter(|r| r.src_port == Some(port) || r.dst_port == Some(port))
                .collect::<Vec<_>>()
        });

        Ok(filtered
            .into_iter()
            .map(|r| PyPacketRecord::from_record(&r, resolution))
            .collect())
    }

    /// Filters packets by source or destination IP.
    pub fn filter_by_ip(&self, py: Python<'_>, ip: &str) -> PyResult<Vec<PyPacketRecord>> {
        let target_ip: std::net::IpAddr = ip
            .parse()
            .map_err(|e| PyValueError::new_err(format!("Invalid IP address '{ip}': {e}")))?;

        let resolution = self.inner.header.resolution;
        let filtered = py.allow_threads(|| {
            let records = self.inner.parse_all_records_parallel();
            records
                .into_iter()
                .filter(|r| r.src_ip == Some(target_ip) || r.dst_ip == Some(target_ip))
                .collect::<Vec<_>>()
        });

        Ok(filtered
            .into_iter()
            .map(|r| PyPacketRecord::from_record(&r, resolution))
            .collect())
    }
}
