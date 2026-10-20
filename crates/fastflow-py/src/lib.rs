pub mod conversion;
pub mod py_pcap;

use conversion::PyPacketRecord;
use py_pcap::{FlowAggregator, PyFlowMetrics};
use pyo3::prelude::*;

/// Native Python extension module powered by Rust.
#[pymodule]
fn fastflow(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<FlowAggregator>()?;
    m.add_class::<PyPacketRecord>()?;
    m.add_class::<PyFlowMetrics>()?;
    m.add("__version__", "0.1.0")?;
    Ok(())
}
