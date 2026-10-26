pub mod conversion;
pub mod py_pcap;

use conversion::PyPacketRecord;
use py_pcap::{FlowAggregator, PyAnomalyAlert, PyFlowMetrics, PyPacketIterator, PyTimeBucket};
use pyo3::prelude::*;

/// Computes the Shannon entropy of a string (useful for DGA and DNS exfiltration detection).
#[pyfunction]
fn compute_shannon_entropy(s: &str) -> f64 {
    fastflow_core::protocols::dns::compute_shannon_entropy(s)
}

/// Alias for compute_shannon_entropy.
#[pyfunction]
fn shannon_entropy(s: &str) -> f64 {
    fastflow_core::protocols::dns::compute_shannon_entropy(s)
}

/// Native Python extension module powered by Rust.
#[pymodule]
fn fastflow(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<FlowAggregator>()?;
    m.add_class::<PyPacketRecord>()?;
    m.add_class::<PyFlowMetrics>()?;
    m.add_class::<PyAnomalyAlert>()?;
    m.add_class::<PyTimeBucket>()?;
    m.add_class::<PyPacketIterator>()?;
    m.add_function(wrap_pyfunction!(compute_shannon_entropy, m)?)?;
    m.add_function(wrap_pyfunction!(shannon_entropy, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
