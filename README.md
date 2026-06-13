# ePassport Issuance PQC Benchmark

A lightweight, reproducible benchmark that simulates the **cryptographic workload of a simplified ePassport issuance flow**, comparing a classical baseline with selected **post-quantum cryptography (PQC)** signature schemes.

## Why this exists

This project was built to explore performance trade-offs in an issuance-like workflow and provide a repeatable way to compare cryptographic costs across different approaches.

## What it does

The benchmark simulates representative cryptographic steps of an ePassport issuance flow, including:

- Input loading (MRZ, portrait, fingerprints, signature)
- DG blob construction (DG1, DG2, DG3, DG7)
- Hashing of DGs
- Issuance PKI setup (CSCA + Document Signer)
- SOD-like payload signing (Passive Authentication equivalent)
- Active Authentication (AA)
- Chip Authentication (CA)
- Optional simplified PACE

## What it does **not** do

This is **not** a full ePassport implementation.

- No real EF.COM / EF.SOD generation
- No ASN.1 encoding
- No strict ICAO compliance implementation
- No production PKI

The goal is to model **typical cryptographic workload**, not to reproduce the exact passport issuance stack.

## Cryptographic backends

- **Classical path**: Python `cryptography`
- **PQC path**: [`liboqs`](https://openquantumsafe.org/liboqs/) via [`liboqs-python`](https://github.com/open-quantum-safe/liboqs-python)
- **Fallback mode**: simulation if OQS is unavailable

## Important caveat

This is **not a strict apples-to-apples benchmark**.

The compared paths do not rely on identical implementation stacks. In practice, this means the results should be read as **prototype-level workload comparisons**, not as pure algorithm rankings.

In particular:

- The classical path uses Python-accessible cryptographic libraries.
- The PQC path uses the Open Quantum Safe ecosystem (`liboqs` / `liboqs-python`).
- Different languages, bindings, native backends, optimization levels, and implementation maturity can materially influence timing.

## Supported suites

Depending on the environment and OQS version, the benchmark targets:

- **ML-DSA** (Dilithium family / standardized naming)
- **SLH-DSA** (newer standardized naming related to SPHINCS+ lineage)

> Note: algorithm naming may vary across OQS versions.

## Usage

### Classical

```bash
python passport_issuance_pqc_benchmark_en.py   --mrz-file mrz.txt   --portrait face.jpg   --finger1 f1.wsq   --finger2 f2.wsq   --signature sig.jpg   --suite classic   --runs 5   --out report_classic.json
```

### PQC (ML-DSA / Dilithium-style suite)

```bash
python passport_issuance_pqc_benchmark_en.py   --mrz-file mrz.txt   --portrait face.jpg   --finger1 f1.wsq   --finger2 f2.wsq   --signature sig.jpg   --suite pqc-dilithium   --runs 5   --out report_dilithium.json
```

### PQC (SLH-DSA / SPHINCS+-style suite)

```bash
python passport_issuance_pqc_benchmark_en.py   --mrz-file mrz.txt   --portrait face.jpg   --finger1 f1.wsq   --finger2 f2.wsq   --signature sig.jpg   --suite pqc-sphincs   --runs 5   --out report_sphincs.json
```

## Output

The script produces JSON output with:

- Per-step timing
- Total timing
- Aggregate statistics across runs
- Basic environment metadata


## Example outputs

See sample outputs:

- sample_outputs/report_classic.json
- sample_outputs/report_classic_ecdsa.json
- sample_outputs/report_mldsa44.json
- sample_outputs/report_slh_dsa.json


## Intended use

This project is intended for:

- research
- experimentation
- exploratory benchmarking

It is **not** intended for production deployment or security-critical use.

## License

MIT License
