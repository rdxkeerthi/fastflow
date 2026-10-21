# FastFlow Test Suite & Real PCAP Test Datasets

This directory contains automated unit tests, integration tests, adversarial stress tests, and real-world PCAP datasets used to benchmark and validate **FastFlow**.

---

## 📁 Real PCAP Datasets (`tests/data/`)

FastFlow provides deterministic, RFC-compliant PCAP captures generated to test real network behaviors, anomaly detection rules, and memory-safety boundary conditions.

| File | Size | Packets | Protocols | Scenario / Behavioral Signature | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- |
| [`sample_web_traffic.pcap`](file:///tests/data/sample_web_traffic.pcap) | 869 B | 9 | Ethernet, IPv4, UDP, TCP, DNS, HTTP | Normal web session: DNS resolution, TCP 3-way handshake (`SYN` -> `SYN-ACK` -> `ACK`), HTTP `GET /index.html`, `200 OK` response, and 4-way teardown (`FIN` -> `FIN-ACK`). | Validates full protocol stack parsing, flow 5-tuple canonicalization, top talkers, and stream iteration. |
| [`syn_scan.pcap`](file:///tests/data/syn_scan.pcap) | 1,144 B | 16 | Ethernet, IPv4, TCP | Vertical reconnaissance scan: single attacker (`192.168.1.150`) probing 16 standard service ports (21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443) on `10.0.0.50`. | Validates automated detection of `AnomalyType::VerticalPortScan` and alert reporting. |
| [`dns_exfiltration.pcap`](file:///tests/data/dns_exfiltration.pcap) | 677 B | 5 | Ethernet, IPv4, UDP, DNS | DGA (Domain Generation Algorithm) & DNS tunneling exfiltration queries using high-entropy subdomains (Shannon entropy > 4.2) for TXT records. | Validates Shannon entropy computation (`fastflow.shannon_entropy`), DGA alerts, and DNS wire decoding. |
| [`malformed_corrupt.pcap`](file:///tests/data/malformed_corrupt.pcap) | 285 B | 4 | Ethernet, IPv4, TCP, DNS | Adversarial fuzz frames: truncated IP header (< 20 bytes), malicious TCP option length (`len < 2` DoS attack), cyclic DNS compression pointer loop (`0xC00C -> 0xC00C`), and snaplen truncation. | Validates zero-crash guarantee, error resilience, and infinite loop prevention. |

---

## 🛠️ Generating or Regenerating Datasets

All datasets in `tests/data/` are generated deterministically using:

```bash
# In project root
python tests/generate_test_pcaps.py
```

Output:
```text
Generated tests/data/sample_web_traffic.pcap (869 bytes)
Generated tests/data/syn_scan.pcap (1144 bytes)
Generated tests/data/dns_exfiltration.pcap (677 bytes)
Generated tests/data/malformed_corrupt.pcap (285 bytes)
```

---

## 🧪 Running the Test Suite

### 1. Python Test Suite (Pytest)
Runs end-to-end integration tests, anomaly detection checks, dictionary conversions, and filter validations:

```bash
pytest tests/ -v
```

### 2. Rust Core Test Suite (Cargo)
Runs zero-copy unit tests across all packet decoders, endianness conversions, checksum calculations, and pointer depth limits:

```bash
cargo test --workspace
```

### 3. Clippy & Linter Verification
Enforces strict compiler lints with zero warnings allowed:

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

---

## 🛡️ Security Vulnerability Verifications

FastFlow includes purpose-built unit tests for specific network parsing vulnerabilities:

1. **TCP Option Infinite Loop Attack (`CVE-Guard`)**:
   - Attack vector: Attacker crafts a TCP option where option length is `0` or `1`. In naive parsers, `offset += len` stalls or loops infinitely, causing 100% CPU denial of service.
   - FastFlow defense: Tested in `malformed_corrupt.pcap`. `crates/fastflow-core/src/protocols/tcp.rs` rejects option lengths `< 2` and halts option parsing cleanly.
2. **DNS Compression Pointer Loop (`Cycle Detection`)**:
   - Attack vector: RFC 1035 allows compression pointers (`0xC0XX`) pointing backwards in the DNS buffer. An attacker loops pointer `A -> B -> A`, causing infinite recursion or stack exhaustion.
   - FastFlow defense: `crates/fastflow-core/src/protocols/dns.rs` maintains a visited-offset bitset and limits pointer dereference depth to 16. Cycle detection halts immediately with `FastFlowError::MalformedFrame`.
3. **IPv6 Extension Header Loop / Exhaustion**:
   - Attack vector: Chained IPv6 extension headers exceeding memory bounds.
   - FastFlow defense: Bounded depth limit (max 8 extension headers) with bounds-checked slice slicing.
4. **Buffer Underflow & Out-of-Bounds Memory Safety**:
   - FastFlow defense: Rust memory-safety semantics ensure zero buffer over-reads. All slices are validated with `checked_add` and bounds checks before indexing.

---

## 🚀 Next Future Build Roadmap

The following next-generation capabilities are scheduled for subsequent major releases:

### 1. Hardware-Accelerated Vectorization (SIMD)
- **AVX2 / AVX-512 & ARM Neon Header Scanning**: SIMD vectorization for parallel magic number location, IP checksum computation, and batch IPv4 5-tuple extraction.
- **Target throughput**: > 5,000,000 packets/second on commodity x86_64.

### 2. Live Capture & Kernel Bypass
- **AF_PACKET / PACKET_MMAP (Linux)**: Zero-copy packet reception direct from kernel ring buffer.
- **eBPF / XDP Integration**: Ultra-fast in-kernel packet filtering before packets enter userspace.
- **Windows WinPcap / Npcap Driver Binding**: High-speed live wire capture on Windows platforms.

### 3. TLS 1.3 Client Hello Deep Inspection
- Zero-copy extraction of **SNI (Server Name Indication)** from TLS records.
- **JA3 / JA4 Fingerprinting**: Client cipher suite and extension hash generation for threat hunting without decrypting TLS payloads.

### 4. Zero-Copy Apache Arrow & Polars IPC Export
- Export multi-gigabyte PCAP flow summaries directly to **Apache Arrow IPC RecordBatches**.
- Instant zero-copy loading into **Polars** (`polars.from_arrow`) and **DuckDB** without Python object overhead.

### 5. PCAP-NG (Next Generation) Full Support
- Enhanced packet block (EPB) parsing.
- Multi-interface capture tracking.
- Interface description blocks (IDB) and custom metadata parsing.
