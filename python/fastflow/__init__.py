"""
FastFlow: Ultra-High-Performance Zero-Copy Network Telemetry & PCAP Engine.

Powered by Rust, Rayon, and PyO3 with zero heap allocations on the hot path.
"""

import os
import sys

# On Windows, ensure package directory is added to DLL search path for runtime dependencies
if sys.platform == "win32":
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.isdir(pkg_dir) and hasattr(os, "add_dll_directory"):
        try:
            os.add_dll_directory(pkg_dir)
        except OSError:
            pass

from .fastflow import FlowAggregator, FlowMetrics, PacketRecord, __version__

__all__ = [
    "FlowAggregator",
    "FlowMetrics",
    "PacketRecord",
    "__version__",
]
