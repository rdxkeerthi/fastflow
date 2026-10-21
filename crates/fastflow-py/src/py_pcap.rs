use crate::conversion::PyPacketRecord;
use fastflow_core::aggregator::TrafficAggregator;
use fastflow_core::pcap::{ByteOrder, PcapEngine, PcapHeader};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;

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

    /// Converts flow metrics to dictionary representation.
    pub fn to_dict(&self, py: Python<'_>) -> PyResult<PyObject> {
        let dict = pyo3::types::PyDict::new_bound(py);
        dict.set_item("packet_count", self.packet_count)?;
        dict.set_item("byte_count", self.byte_count)?;
        dict.set_item("duration", self.duration)?;
        dict.set_item("syn_count", self.syn_count)?;
        dict.set_item("fin_count", self.fin_count)?;
        dict.set_item("rst_count", self.rst_count)?;
        Ok(dict.into())
    }
}

/// Security anomaly detected during PCAP analysis.
#[pyclass(name = "AnomalyAlert")]
#[derive(Debug, Clone)]
pub struct PyAnomalyAlert {
    #[pyo3(get)]
    pub anomaly_type: String,
    #[pyo3(get)]
    pub source_ip: String,
    #[pyo3(get)]
    pub target_ip: Option<String>,
    #[pyo3(get)]
    pub port: Option<u16>,
    #[pyo3(get)]
    pub details: String,
}

#[pymethods]
impl PyAnomalyAlert {
    fn __repr__(&self) -> String {
        format!(
            "AnomalyAlert(type={}, src={}, target={:?}, port={:?}, details={:?})",
            self.anomaly_type, self.source_ip, self.target_ip, self.port, self.details
        )
    }

    /// Converts alert to a Python dictionary.
    pub fn to_dict(&self, py: Python<'_>) -> PyResult<PyObject> {
        let dict = pyo3::types::PyDict::new_bound(py);
        dict.set_item("anomaly_type", &self.anomaly_type)?;
        dict.set_item("source_ip", &self.source_ip)?;
        dict.set_item("target_ip", &self.target_ip)?;
        dict.set_item("port", self.port)?;
        dict.set_item("details", &self.details)?;
        Ok(dict.into())
    }
}

/// Time-bucketed throughput metric.
#[pyclass(name = "TimeBucket")]
#[derive(Debug, Clone)]
pub struct PyTimeBucket {
    #[pyo3(get)]
    pub start_time: f64,
    #[pyo3(get)]
    pub end_time: f64,
    #[pyo3(get)]
    pub packet_count: u64,
    #[pyo3(get)]
    pub byte_count: u64,
    #[pyo3(get)]
    pub bandwidth_bps: f64,
}

#[pymethods]
impl PyTimeBucket {
    fn __repr__(&self) -> String {
        format!(
            "TimeBucket(start={:.4}, end={:.4}, packets={}, bytes={}, bps={:.2})",
            self.start_time, self.end_time, self.packet_count, self.byte_count, self.bandwidth_bps
        )
    }

    /// Converts bucket to a Python dictionary.
    pub fn to_dict(&self, py: Python<'_>) -> PyResult<PyObject> {
        let dict = pyo3::types::PyDict::new_bound(py);
        dict.set_item("start_time", self.start_time)?;
        dict.set_item("end_time", self.end_time)?;
        dict.set_item("packet_count", self.packet_count)?;
        dict.set_item("byte_count", self.byte_count)?;
        dict.set_item("bandwidth_bps", self.bandwidth_bps)?;
        Ok(dict.into())
    }
}

/// Streaming zero-allocation iterator over packet records in a PCAP buffer.
#[pyclass(name = "PacketIterator")]
pub struct PyPacketIterator {
    inner: Arc<PcapEngine>,
    cursor: usize,
}

#[pymethods]
impl PyPacketIterator {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(mut slf: PyRefMut<'_, Self>, _py: Python<'_>) -> Option<PyPacketRecord> {
        let engine = Arc::clone(&slf.inner);
        let resolution = engine.header.resolution;
        let bo = engine.header.byte_order;
        let bytes = engine.bytes();

        loop {
            if slf.cursor + 16 > bytes.len() {
                return None;
            }

            let caplen = match bo {
                ByteOrder::BigEndian => u32::from_be_bytes([
                    bytes[slf.cursor + 8],
                    bytes[slf.cursor + 9],
                    bytes[slf.cursor + 10],
                    bytes[slf.cursor + 11],
                ]) as usize,
                ByteOrder::LittleEndian => u32::from_le_bytes([
                    bytes[slf.cursor + 8],
                    bytes[slf.cursor + 9],
                    bytes[slf.cursor + 10],
                    bytes[slf.cursor + 11],
                ]) as usize,
            };

            let next_cursor = match slf
                .cursor
                .checked_add(16)
                .and_then(|c| c.checked_add(caplen))
            {
                Some(nc) if nc <= bytes.len() => nc,
                _ => return None,
            };

            let current_offset = slf.cursor;
            slf.cursor = next_cursor;

            if let Ok(rec) = engine.parse_record_at(current_offset) {
                return Some(PyPacketRecord::from_record(&rec, resolution));
            }
        }
    }
}

/// High-performance multi-core PCAP analyzer and flow aggregator.
#[pyclass(name = "FlowAggregator")]
pub struct FlowAggregator {
    inner: Arc<PcapEngine>,
}

#[pymethods]
impl FlowAggregator {
    #[new]
    pub fn new(filepath: &str) -> PyResult<Self> {
        PcapEngine::open(filepath)
            .map(|engine| Self {
                inner: Arc::new(engine),
            })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Returns streaming iterator over packets without loading all into memory.
    pub fn iter_packets(&self) -> PyPacketIterator {
        PyPacketIterator {
            inner: Arc::clone(&self.inner),
            cursor: PcapHeader::HEADER_LEN,
        }
    }

    /// Allows `for packet in aggregator:` syntax in Python.
    pub fn __iter__(&self) -> PyPacketIterator {
        self.iter_packets()
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

    /// Evaluates traffic patterns to detect security anomalies (SYN floods, port scans, subnet sweeps).
    pub fn detect_anomalies(&self, py: Python<'_>) -> PyResult<Vec<PyAnomalyAlert>> {
        let alerts = py.allow_threads(|| {
            let records = self.inner.parse_all_records_parallel();
            let mut agg = TrafficAggregator::new();
            agg.ingest_batch(&records);
            agg.detect_anomalies()
        });

        Ok(alerts
            .into_iter()
            .map(|a| PyAnomalyAlert {
                anomaly_type: format!("{:?}", a.anomaly_type),
                source_ip: a.source_ip.to_string(),
                target_ip: a.target_ip.map(|ip| ip.to_string()),
                port: a.port,
                details: a.details,
            })
            .collect())
    }

    /// Computes time-bucketed bandwidth and throughput over specified interval (e.g. 1.0 second).
    pub fn bandwidth_timeline(
        &self,
        py: Python<'_>,
        bucket_secs: f64,
    ) -> PyResult<Vec<PyTimeBucket>> {
        if bucket_secs <= 0.0 {
            return Err(PyValueError::new_err("bucket_secs must be greater than 0"));
        }

        let buckets = py.allow_threads(|| {
            let records = self.inner.parse_all_records_parallel();
            let mut agg = TrafficAggregator::new();
            agg.ingest_batch(&records);
            agg.bandwidth_timeline(bucket_secs)
        });

        Ok(buckets
            .into_iter()
            .map(|b| PyTimeBucket {
                start_time: b.start_time,
                end_time: b.end_time,
                packet_count: b.packet_count,
                byte_count: b.byte_count,
                bandwidth_bps: b.bandwidth_bps,
            })
            .collect())
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
