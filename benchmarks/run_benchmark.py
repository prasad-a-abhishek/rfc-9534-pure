#!/usr/bin/env python3
"""RFC 9534 Pure — benchmark: parse + serialize throughput vs alternatives.

No competitor package exists for this specific RFC 9534 Micro-session ID TLV,
so this script benchmarks the library against itself across workload profiles.

Usage:
    python3 benchmarks/run_benchmark.py
"""

import json
import statistics
import sys
import time

sys.path.insert(0, "src")

from rfc9534pure import parse_micro_session_tlv, serialize_micro_session_tlv, MicroSessionIDTLV

# Profile configurations: (sender_id, reflector_id, description)
PROFILES = [
    (1, 2, "minimal"),
    (0, 0, "zeros"),
    (65535, 65535, "max_ids"),
    (256, 512, "typical"),
    (32768, 16384, "boundary"),
    (123, 456, "mid_range"),
    (100, 100, "symmetric"),
    (1, 65535, "mixed"),
    (0, 1, "sender_zero"),
    (1, 0, "reflector_zero"),
]

ITERATIONS = 50
OUTPUT_PATH = "benchmarks/BENCHMARK.md"


def benchmark_serialize(sender_id: int, reflector_id: int) -> dict:
    """Benchmark serialize_micro_session_tlv."""
    measurements = []
    for _ in range(ITERATIONS):
        t0 = time.perf_counter_ns()
        serialize_micro_session_tlv(sender_id, reflector_id)
        t1 = time.perf_counter_ns()
        measurements.append(t1 - t0)

    return {
        "iterations": ITERATIONS,
        "mean_ns": round(statistics.mean(measurements)),
        "p95_ns": round(statistics.quantiles(measurements, n=20)[18] if len(measurements) >= 20 else max(measurements)),
        "min_ns": min(measurements),
        "max_ns": max(measurements),
    }


def benchmark_parse(data: bytes) -> dict:
    """Benchmark parse_micro_session_tlv."""
    measurements = []
    for _ in range(ITERATIONS):
        t0 = time.perf_counter_ns()
        parse_micro_session_tlv(data)
        t1 = time.perf_counter_ns()
        measurements.append(t1 - t0)

    return {
        "iterations": ITERATIONS,
        "mean_ns": round(statistics.mean(measurements)),
        "p95_ns": round(statistics.quantiles(measurements, n=20)[18] if len(measurements) >= 20 else max(measurements)),
        "min_ns": min(measurements),
        "max_ns": max(measurements),
    }


def run() -> dict:
    results = {}
    for sender_id, reflector_id, desc in PROFILES:
        data = serialize_micro_session_tlv(sender_id, reflector_id)
        ser = benchmark_serialize(sender_id, reflector_id)
        par = benchmark_parse(data)
        results[desc] = {
            "sender_id": sender_id,
            "reflector_id": reflector_id,
            "serialize": ser,
            "parse": par,
        }

    return results


def format_ns(ns: int) -> str:
    """Format nanoseconds as microseconds."""
    return f"{ns / 1000:.2f} µs"


def generate_markdown(results: dict) -> str:
    lines = [
        "# RFC 9534 Pure — Benchmark Results",
        "",
        f"**Benchmark tool:** `benchmarks/run_benchmark.py`",
        f"**Iterations per profile:** {ITERATIONS}",
        f"**Environment:** Python 3.11 stdlib only",
        "",
        "## Benchmark Table",
        "",
        "| Profile | sender_id | reflector_id | Serialize Mean | Serialize P95 | Parse Mean | Parse P95 |",
        "|---------|-----------|--------------|----------------|---------------|------------|-----------|",
    ]

    for desc, data in results.items():
        s_mean = format_ns(data["serialize"]["mean_ns"])
        s_p95 = format_ns(data["serialize"]["p95_ns"])
        p_mean = format_ns(data["parse"]["mean_ns"])
        p_p95 = format_ns(data["parse"]["p95_ns"])
        lines.append(
            f"| {desc} | {data['sender_id']} | {data['reflector_id']} | "
            f"{s_mean} | {s_p95} | {p_mean} | {p_p95} |"
        )

    lines += [
        "",
        "## Notes",
        "",
        "- **No competitor package exists** for this specific RFC 9534 Micro-session ID TLV.",
        "  This benchmark demonstrates the library's own performance characteristics.",
        "- Measurements are in nanoseconds (ns) via `time.perf_counter_ns()`.",
        "- All operations are pure stdlib with no I/O or memory allocations beyond the TLV itself.",
        "- Serialize and Parse are symmetric in complexity (same 8-byte buffer).",
    ]

    return "\n".join(lines)


if __name__ == "__main__":
    results = run()
    md = generate_markdown(results)
    with open(OUTPUT_PATH, "w") as f:
        f.write(md + "\n")
    print(f"Benchmark written to {OUTPUT_PATH}")
    print(md)
