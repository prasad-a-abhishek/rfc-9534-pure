# RFC 9534 Pure — Benchmark Results

**Benchmark tool:** `benchmarks/run_benchmark.py`
**Iterations per profile:** 50
**Environment:** Python 3.11 stdlib only

## Benchmark Table

| Profile | sender_id | reflector_id | Serialize Mean | Serialize P95 | Parse Mean | Parse P95 |
|---------|-----------|--------------|----------------|---------------|------------|-----------|
| minimal | 1 | 2 | 0.53 µs | 1.23 µs | 0.61 µs | 1.56 µs |
| zeros | 0 | 0 | 0.43 µs | 0.52 µs | 0.48 µs | 0.60 µs |
| max_ids | 65535 | 65535 | 0.43 µs | 0.48 µs | 0.48 µs | 0.56 µs |
| typical | 256 | 512 | 0.42 µs | 0.46 µs | 0.46 µs | 0.54 µs |
| boundary | 32768 | 16384 | 0.42 µs | 0.46 µs | 0.46 µs | 0.50 µs |
| mid_range | 123 | 456 | 0.43 µs | 0.46 µs | 0.47 µs | 0.58 µs |
| symmetric | 100 | 100 | 0.65 µs | 0.67 µs | 0.48 µs | 0.56 µs |
| mixed | 1 | 65535 | 0.42 µs | 0.48 µs | 0.49 µs | 0.58 µs |
| sender_zero | 0 | 1 | 0.43 µs | 0.48 µs | 0.47 µs | 0.54 µs |
| reflector_zero | 1 | 0 | 0.42 µs | 0.50 µs | 0.47 µs | 0.52 µs |

## Notes

- **No competitor package exists** for this specific RFC 9534 Micro-session ID TLV.
  This benchmark demonstrates the library's own performance characteristics.
- Measurements are in nanoseconds (ns) via `time.perf_counter_ns()`.
- All operations are pure stdlib with no I/O or memory allocations beyond the TLV itself.
- Serialize and Parse are symmetric in complexity (same 8-byte buffer).
