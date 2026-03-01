# Contributing to Deep Packet Analyzer

Thanks for your interest!  This document outlines basic setup and development
steps.

## Getting started

1. Clone the repository:

   ```bash
   git clone https://github.com/Rv9835/Deep-Packet-Analyzer.git
   cd "Deep Packet Analyzer"
   ```

2. Install prerequisites:
   * C++17 toolchain (clang/gcc)
   * CMake 3.10+
   * OpenSSL development headers
   * Node.js (for web/worker), pnpm if you use JavaScript
   * Python + scapy (optional, for test pcap generator)

3. Build the C++ engine:

   ```bash
   mkdir build && cd build
   cmake ..
   make -j4
   ```

4. (JS) bootstrap workspace:

   ```bash
   pnpm -w install   # requires pnpm
   ```

## Development commands

* `make` in `build/` to compile engine
* `./packet_analyzer --pcap path --rules rules.json --out-dir out` to run
* `pnpm -w -r test` to run JavaScript package tests

Feel free to open issues or pull requests.  Please follow the existing coding
style and keep changes minimal and focused.
