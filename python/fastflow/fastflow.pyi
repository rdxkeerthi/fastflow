from typing import Any

__version__: str

class PacketRecord:
    timestamp: float
    captured_len: int
    original_len: int
    src_ip: str | None
    dst_ip: str | None
    protocol: int | None
    src_port: int | None
    dst_port: int | None
    tcp_flags: int | None
    payload_len: int

    def to_dict(self) -> dict[str, Any]: ...

class FlowMetrics:
    packet_count: int
    byte_count: int
    duration: float
    syn_count: int
    fin_count: int
    rst_count: int

class FlowAggregator:
    def __init__(self, filepath: str) -> None: ...
    def packet_count(self) -> int: ...
    def parse_all(self) -> list[PacketRecord]: ...
    def top_talkers(self, limit: int = 10) -> list[tuple[str, int]]: ...
    def top_talkers_by_bytes(self, limit: int = 10) -> list[tuple[str, int]]: ...
    def protocol_distribution(self) -> dict[int, int]: ...
    def filter_by_port(self, port: int) -> list[PacketRecord]: ...
    def filter_by_ip(self, ip: str) -> list[PacketRecord]: ...
