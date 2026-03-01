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


## Python utilities

### Web/worker prototype

The `web` and `worker` directories contain a lightweight Express/Node
prototype for job orchestration. To run it you'll need:

```bash
cd web && npm install express axios ioredis aws-sdk
# optionally install redis and set REDIS_URL, API_KEY, etc.
node index.js
```

The worker uses the DPI engine binary (`dpi_engine`) on the PATH and
expects Redis for the job queue and signed URLs for S3 interaction.


The `generate_test_pcap.py` script uses [Scapy](https://scapy.net/). Install it with:

```bash
pip install scapy
```


## Running

After building, run `./packet_analyzer` from the build directory.

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
