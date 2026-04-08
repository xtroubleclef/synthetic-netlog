"""
synthetic_netlog_generator.py

Generates a synthetic, anomaly-labeled network log dataset for research
and anomaly detection benchmarking.

Anomaly types:
  - volume:    sudden spike in bytes from a single source IP
  - portscan:  one source IP hitting many destination ports in a short window
  - beaconing: a source making requests at suspiciously regular intervals (C2 simulation)

Output: JSONL file (one JSON object per line) + CSV summary

Usage:
  python synthetic_netlog_generator.py
  python synthetic_netlog_generator.py --n 50000 --anomaly-rate 0.04 --out logs.jsonl
"""

import argparse
import json
import math
import random
import csv
from datetime import datetime, timedelta
from pathlib import Path


# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------

DEFAULT_N = 20000          # total log entries
DEFAULT_ANOMALY_RATE = 0.05  # fraction of entries that are anomalous
DEFAULT_OUT = "netlog_dataset.jsonl"
DEFAULT_SEED = 42

# Network topology (synthetic)
INTERNAL_SUBNETS = ["192.168.1", "192.168.2", "10.0.0"]
EXTERNAL_IPS = [f"203.0.113.{i}" for i in range(1, 30)]
COMMON_PORTS = [80, 443, 22, 3306, 5432, 8080, 8443, 53, 25, 587]
ALL_PORTS = list(range(1, 1025))

NORMAL_BYTES_MEAN = 1500
NORMAL_BYTES_STD = 800
VOLUME_ANOMALY_MULTIPLIER = (40, 100)   # bytes spike range

BEACON_INTERVALS = [30, 60, 120, 300]   # seconds, regular C2 check-in
BEACON_JITTER = 0.05                     # ±5% jitter on beacon interval

PROTOCOLS = ["TCP", "UDP"]
STATUSES = ["OK", "OK", "OK", "OK", "TIMEOUT", "RESET"]  # weighted toward OK


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def random_internal_ip(subnets=INTERNAL_SUBNETS):
    subnet = random.choice(subnets)
    return f"{subnet}.{random.randint(1, 254)}"


def random_external_ip():
    return random.choice(EXTERNAL_IPS)


def bytes_normal():
    return max(64, int(random.gauss(NORMAL_BYTES_MEAN, NORMAL_BYTES_STD)))


def bytes_spike():
    mult = random.uniform(*VOLUME_ANOMALY_MULTIPLIER)
    return int(NORMAL_BYTES_MEAN * mult)


def make_entry(timestamp, src_ip, dst_ip, port, byte_count, protocol, status, label, anomaly_type=None):
    return {
        "timestamp": timestamp.isoformat() + "Z",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "port": port,
        "bytes": byte_count,
        "protocol": protocol,
        "status": status,
        "label": label,                    # "normal" | "anomaly"
        "anomaly_type": anomaly_type or "", # "" | "volume" | "portscan" | "beaconing"
    }


# ---------------------------------------------------------------------------
# Normal traffic generator
# ---------------------------------------------------------------------------

def generate_normal(timestamp, src_ip=None):
    src = src_ip or random_internal_ip()
    dst = random.choice([random_internal_ip(), random_external_ip()])
    port = random.choice(COMMON_PORTS)
    return make_entry(
        timestamp=timestamp,
        src_ip=src,
        dst_ip=dst,
        port=port,
        byte_count=bytes_normal(),
        protocol=random.choice(PROTOCOLS),
        status=random.choice(STATUSES),
        label="normal",
    )


# ---------------------------------------------------------------------------
# Anomaly generators
# ---------------------------------------------------------------------------

def generate_volume_anomaly(timestamp, src_ip=None):
    """Single source sending a large burst of data."""
    src = src_ip or random_internal_ip()
    dst = random.choice(EXTERNAL_IPS)
    port = random.choice([80, 443, 22])
    return make_entry(
        timestamp=timestamp,
        src_ip=src,
        dst_ip=dst,
        port=port,
        byte_count=bytes_spike(),
        protocol="TCP",
        status="OK",
        label="anomaly",
        anomaly_type="volume",
    )


def generate_portscan_burst(start_time, src_ip, n_ports=30):
    """One source hitting many ports on a single target in quick succession."""
    dst = random_internal_ip()
    ports = random.sample(ALL_PORTS, min(n_ports, len(ALL_PORTS)))
    entries = []
    for i, port in enumerate(ports):
        ts = start_time + timedelta(seconds=i * random.uniform(0.1, 0.8))
        entry = make_entry(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst,
            port=port,
            byte_count=random.randint(40, 120),  # small probe packets
            protocol="TCP",
            status=random.choice(["RESET", "TIMEOUT", "OK"]),
            label="anomaly",
            anomaly_type="portscan",
        )
        entries.append(entry)
    return entries


def generate_beacon_sequence(start_time, src_ip, n_beacons=8):
    """Regular interval connections simulating malware C2 check-in."""
    interval = random.choice(BEACON_INTERVALS)
    dst = random.choice(EXTERNAL_IPS)
    port = random.choice([80, 443, 8080])
    entries = []
    ts = start_time
    for _ in range(n_beacons):
        jitter = interval * BEACON_JITTER * random.uniform(-1, 1)
        ts = ts + timedelta(seconds=interval + jitter)
        entry = make_entry(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst,
            port=port,
            byte_count=random.randint(200, 800),
            protocol="TCP",
            status="OK",
            label="anomaly",
            anomaly_type="beaconing",
        )
        entries.append(entry)
    return entries


# ---------------------------------------------------------------------------
# Dataset builder
# ---------------------------------------------------------------------------

def build_dataset(n=DEFAULT_N, anomaly_rate=DEFAULT_ANOMALY_RATE, seed=DEFAULT_SEED):
    random.seed(seed)

    start_time = datetime(2024, 1, 1, 0, 0, 0)
    duration_hours = 72
    end_time = start_time + timedelta(hours=duration_hours)

    entries = []
    anomaly_budget = int(n * anomaly_rate)
    normal_budget = n - anomaly_budget

    # --- Normal traffic ---
    print(f"Generating {normal_budget} normal entries...")
    for i in range(normal_budget):
        # spread timestamps across the window with some burstiness during business hours
        base_progress = i / normal_budget
        hour_of_day = (base_progress * duration_hours) % 24
        # business hours (8-18) get 3x more traffic
        if 8 <= hour_of_day < 18:
            ts_offset = base_progress * duration_hours * 3600 * random.uniform(0.95, 1.05)
        else:
            ts_offset = base_progress * duration_hours * 3600 * random.uniform(0.85, 1.15)
        ts_offset = min(ts_offset, (end_time - start_time).total_seconds() - 1)
        ts = start_time + timedelta(seconds=ts_offset)
        entries.append(generate_normal(ts))

    # --- Anomalies ---
    print(f"Generating anomalies (budget: {anomaly_budget} entries)...")

    # Volume anomalies — individual entries
    n_volume = anomaly_budget // 3
    volume_attacker = random_internal_ip()
    for _ in range(n_volume):
        offset = random.uniform(0, (end_time - start_time).total_seconds())
        ts = start_time + timedelta(seconds=offset)
        entries.append(generate_volume_anomaly(ts, src_ip=random.choice([volume_attacker, random_internal_ip()])))

    # Port scan bursts — grouped entries
    n_scans = max(1, anomaly_budget // 6 // 30)
    scan_attacker = random_internal_ip()
    for _ in range(n_scans):
        offset = random.uniform(0, (end_time - start_time).total_seconds() - 60)
        ts = start_time + timedelta(seconds=offset)
        entries.extend(generate_portscan_burst(ts, src_ip=scan_attacker, n_ports=30))

    # Beaconing sequences — grouped entries
    n_beacon_hosts = max(1, anomaly_budget // 6 // 8)
    for _ in range(n_beacon_hosts):
        offset = random.uniform(0, (end_time - start_time).total_seconds() - 3600)
        ts = start_time + timedelta(seconds=offset)
        beacon_src = random_internal_ip()
        entries.extend(generate_beacon_sequence(ts, src_ip=beacon_src, n_beacons=8))

    # Sort all entries by timestamp
    entries.sort(key=lambda e: e["timestamp"])

    print(f"Total entries generated: {len(entries)}")
    return entries


# ---------------------------------------------------------------------------
# Statistics summary
# ---------------------------------------------------------------------------

def compute_stats(entries):
    total = len(entries)
    anomalies = [e for e in entries if e["label"] == "anomaly"]
    by_type = {}
    for e in anomalies:
        t = e["anomaly_type"]
        by_type[t] = by_type.get(t, 0) + 1

    normal_bytes = [e["bytes"] for e in entries if e["label"] == "normal"]
    anomaly_bytes = [e["bytes"] for e in entries if e["label"] == "anomaly"]

    return {
        "total_entries": total,
        "normal_count": total - len(anomalies),
        "anomaly_count": len(anomalies),
        "anomaly_rate": round(len(anomalies) / total, 4),
        "anomaly_types": by_type,
        "normal_bytes_mean": round(sum(normal_bytes) / len(normal_bytes), 1) if normal_bytes else 0,
        "normal_bytes_max": max(normal_bytes) if normal_bytes else 0,
        "anomaly_bytes_mean": round(sum(anomaly_bytes) / len(anomaly_bytes), 1) if anomaly_bytes else 0,
        "anomaly_bytes_max": max(anomaly_bytes) if anomaly_bytes else 0,
        "unique_src_ips": len(set(e["src_ip"] for e in entries)),
        "unique_dst_ips": len(set(e["dst_ip"] for e in entries)),
        "unique_ports": len(set(e["port"] for e in entries)),
        "time_start": entries[0]["timestamp"] if entries else "",
        "time_end": entries[-1]["timestamp"] if entries else "",
    }


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------

def write_jsonl(entries, path):
    with open(path, "w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")
    print(f"Written: {path} ({Path(path).stat().st_size // 1024} KB)")


def write_stats(stats, path):
    with open(path, "w") as f:
        json.dump(stats, f, indent=2)
    print(f"Written: {path}")


def write_csv_sample(entries, path, n=1000):
    """Write a CSV sample for quick inspection."""
    sample = random.sample(entries, min(n, len(entries)))
    sample.sort(key=lambda e: e["timestamp"])
    if not sample:
        return
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=sample[0].keys())
        writer.writeheader()
        writer.writerows(sample)
    print(f"Written: {path} (sample of {len(sample)} entries)")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Synthetic network log generator")
    parser.add_argument("--n", type=int, default=DEFAULT_N, help="Total number of log entries")
    parser.add_argument("--anomaly-rate", type=float, default=DEFAULT_ANOMALY_RATE,
                        help="Fraction of entries that are anomalous (0.0–1.0)")
    parser.add_argument("--out", type=str, default=DEFAULT_OUT, help="Output JSONL filename")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="Random seed")
    args = parser.parse_args()

    print(f"\n=== Synthetic Network Log Generator ===")
    print(f"  N={args.n}, anomaly_rate={args.anomaly_rate}, seed={args.seed}\n")

    entries = build_dataset(n=args.n, anomaly_rate=args.anomaly_rate, seed=args.seed)

    out_path = Path(args.out)
    stats_path = out_path.with_suffix(".stats.json")
    sample_path = out_path.with_suffix(".sample.csv")

    write_jsonl(entries, out_path)
    stats = compute_stats(entries)
    write_stats(stats, stats_path)
    write_csv_sample(entries, sample_path)

    print(f"\n=== Dataset Summary ===")
    print(f"  Total:    {stats['total_entries']:,}")
    print(f"  Normal:   {stats['normal_count']:,}")
    print(f"  Anomaly:  {stats['anomaly_count']:,} ({stats['anomaly_rate']*100:.1f}%)")
    print(f"  Types:    {stats['anomaly_types']}")
    print(f"  Period:   {stats['time_start']} → {stats['time_end']}")
    print(f"\nDone. Deposit the JSONL and stats files on Zenodo to obtain a citable DOI.\n")

if __name__ == "__main__":
    main()
