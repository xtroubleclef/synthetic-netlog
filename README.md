# Synthetic Network Log Dataset Generator

A reproducible synthetic network traffic dataset generator with ground-truth anomaly labels. Used for benchmarking anomaly detection algorithms.

## Overview

Real network intrusion datasets are often unlabeled, noisy, or legally restricted. This generator produces a clean, fully labeled dataset where every anomaly is explicitly tagged with its type, making it viable for training, evaluating, and comparing detection methods with known ground truth.

Three anomaly types simulated with realistic normal traffic:

| Anomaly Type | Description |
|---|---|
| `volume` | Sudden spike in bytes from a single source IP |
| `portscan` | One source IP hitting many destination ports in rapid succession |
| `beaconing` | Regular-interval connections simulating malware C2 check-in behavior |

## Dataset Schema

Every log entry is a JSON object with fields:

| Field | Type | Description |
|---|---|---|
| `timestamp` | string | ISO 8601 UTC timestamp |
| `src_ip` | string | Source IP address |
| `dst_ip` | string | Destination IP address |
| `port` | integer | Destination port |
| `bytes` | integer | Bytes transferred |
| `protocol` | string | `TCP` or `UDP` |
| `status` | string | Connection status (`OK`, `TIMEOUT`, `RESET`) |
| `label` | string | `normal` or `anomaly` |
| `anomaly_type` | string | `volume`, `portscan`, `beaconing`, or `""` for normal entries |

## Usage

*No dependencies beyond the Python standard library*

```bash
# Default: 20,000 entries, 5% anomaly rate
python synthetic_netlog_generator.py

# Custom parameters
python synthetic_netlog_generator.py --n 50000 --anomaly-rate 0.04 --out my_logs.jsonl

# Fixed seed for reproducibility
python synthetic_netlog_generator.py --seed 42
```

### Arguments

| Argument | Default | Description |
|---|---|---|
| `--n` | 20000 | Total number of log entries |
| `--anomaly-rate` | 0.05 | Fraction of entries that are anomalous |
| `--out` | `netlog_dataset.jsonl` | Output filename |
| `--seed` | 42 | Random seed for reproducibility |

### Output Files

Running the generator produces three files:

- `netlog_dataset.jsonl` — Full dataset, one JSON object per line
- `netlog_dataset.stats.json` — Summary statistics (entry counts, byte distributions, anomaly breakdown)
- `netlog_dataset.sample.csv` — 1,000-entry random sample for quick inspection

## Reproducibility

An identical dataset is produced on every run with the default seed (`--seed 42`). To reproduce the reference dataset:

```bash
python synthetic_netlog_generator.py --n 20000 --anomaly-rate 0.05 --seed 42
```

## Network Topology

Traffic is simulated across a synthetic internal network with three subnets (`192.168.1.x`, `192.168.2.x`, `10.0.0.x`) and a pool of external IPs (`203.0.113.x`). Normal traffic uses common ports (80, 443, 22, 3306, 5432, 8080, 53, 25). Port scan anomalies probe across the full 1–1024 port range.

Traffic volume follows a realistic diurnal pattern: business hours (08:00–18:00) generate approximately 3x the traffic of off-hours.

## Intended Use

- Benchmarking anomaly detection algorithms (Z-score, Isolation Forest, CUSUM, etc.)
- Teaching and demonstrations of network security concepts
- Prototyping log analysis pipelines before applying to real data
- Evaluation of detection precision, recall, and F1 against known ground truth

## Limitations

- Network topology and traffic patterns are simplified and do not reflect any real network
- Anomaly types are clearly separable by design — real-world anomalies are noisier
- No packet-level detail; entry-level aggregation only
- External IPs are drawn from the IANA documentation range (203.0.113.x) and are not routable

## Citation

If you use this dataset or generator in your research, please cite:

```
Rosario, A. (2026). Synthetic Network Log Dataset for Anomaly Detection Benchmarking.
Zenodo. https://doi.org/[DOI]
```

*(DOI will be updated upon Zenodo deposit)*

## License

MIT
