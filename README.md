# Packet Analyzer

This is a simple packet analysis project written in C++. It includes modules for:

- DPI engine (multi‑threaded)
- Packet parsing (Ethernet/IPv4/IPv6/TCP/UDP, VLAN, fragmentation, pcapng)
- Connection tracking with deterministic canonical flow keys
- Rule engine (IP, domain, app‑type)
- Metadata extraction (SNI, HTTP host)
- Minimal web/worker job orchestration prototype


## Building

```bash
mkdir build && cd build
cmake ..
make
```


## Monorepo and JavaScript components

This repository is managed as a pnpm workspace.  After installing Node
and pnpm (see below), bootstrap the workspace from the project root:

```bash
pnpm -w install         # install dependencies for all packages
pnpm -w -r test          # run tests in every JS package that defines a script
```

Packages include `web` and `worker` (see `package.json`/`packages`).
To operate on a single package use `--filter`, e.g.:

```bash
pnpm --filter web start
```

JavaScript development is optional; the core engine remains C++.

## Python utilities

The `generate_test_pcap.py` script uses [Scapy](https://scapy.net/). Install it with:

```bash
pip install scapy
```


## Running

After building, run `./packet_analyzer` from the build directory.

## Local infrastructure (Docker Compose)

A simple compose file is provided to stand up supporting services for
integration testing or development.

```yaml
# docker-compose.yml (at repo root)
# postgres, redis and an S3-compatible MinIO server
version: '3.8'

services:
  postgres: ...
```

Start the stack with:

```bash
docker-compose up -d
```

Postgres listens on port 5432, Redis on 6379, MinIO S3 API on 9000 and
console on 9001 (optional).

Expose the compose file locally with `docker-compose ps` to inspect.


### Dependencies

The C++ engine requires:

- A C++17‑capable compiler (clang/gcc).
- CMake 3.10 or newer.
- OpenSSL development headers (for SHA‑256).
- Internet access when running CMake the first time to fetch [nlohmann/json](https://github.com/nlohmann/json) (the project will automatically download the header-only library).

On macOS you can install the above with `xcode-select --install` and `brew install cmake openssl` (if brew is available).

### Example run

```bash
# build
mkdir build && cd build
cmake ..
make -j4

# run
./packet_analyzer --pcap ../test_dpi.pcap \
    --rules ../example_rules.json \
    --out-dir out

# outputs will appear in build/out/ (report.json, filtered.pcap, manifest.json)
```
