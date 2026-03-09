# Building and Testing Deep Packet Analyzer

This document covers building the C++ engine, running tests, and using sanitizers for debugging.

## Build Configuration

The project uses CMake with standardized output directories:

- **Binary output**: `engine/build/bin/`
- **Library output**: `engine/build/lib/`
- **Build caches**: `engine/build/` (git-ignored)

## Prerequisites

### macOS
```bash
xcode-select --install
brew install cmake openssl
```

### Linux (Ubuntu/Debian)
```bash
sudo apt-get install build-essential cmake libssl-dev
```

### Windows
- Install CMake from [cmake.org](https://cmake.org)
- Install OpenSSL development libraries
- Use Visual Studio 2017 or newer for C++17 support

## Building the Engine

### Standard Build (Release)

```bash
cd /path/to/Deep Packet Analyzer
mkdir -p engine/build
cd engine/build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)  # Linux/macOS
# or
cmake --build . --config Release  # Windows
```

The binary will be in `engine/build/bin/packet_analyzer`.

### Debug Build

```bash
cd engine/build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)
```

### Rebuild from Scratch

```bash
rm -rf engine/build
mkdir -p engine/build
cd engine/build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)
```

## Running Tests

Tests use the **Catch2** framework (v3.4.0) and are integrated with CMake's **ctest**.

### Run All Tests

```bash
# After building
cd engine/build
ctest --output-on-failure
```

### Run Specific Test

```bash
cd engine/build
ctest -R parser --output-on-failure  # Run tests matching "parser"
```

### Run Test Executable Directly

```bash
cd engine/build/bin
./test_parser      # Run parser tests
./test_rule_manager  # Run rule manager tests
./test_engine       # Run engine tests
./test_sni          # Run SNI extraction tests
./test_http         # Run HTTP extraction tests
./test_flowtracker  # Run flow tracking tests
./test_pcapng       # Run pcapng format tests
./test_golden       # Run golden file tests
```

### Verbose Test Output

```bash
cd engine/build
ctest -V --output-on-failure
```

### Custom Catch2 Arguments

You can pass Catch2 arguments to test executables:

```bash
./test_parser --help                    # Show Catch2 options
./test_parser -v                        # Verbose output
./test_parser "[parser]"                # Run tests with [parser] tag
./test_parser "PacketParser: Parse minimal"  # Run specific test by name
```

## Address and Undefined Behavior Sanitizers

Sanitizers are automatically enabled for **Debug builds on non-Windows platforms**. They help detect:

- **AddressSanitizer (ASan)**: Memory errors (use-after-free, buffer overflows, etc.)
- **UndefinedBehaviorSanitizer (UBSan)**: Undefined behavior (signed overflow, misaligned access, etc.)

### Running with Sanitizers

```bash
# Build in Debug mode (sanitizers enabled)
cd engine/build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)

# Run tests - sanitizers will catch errors
ctest --output-on-failure

# Or run directly
./bin/test_parser
```

### Interpreting Sanitizer Output

If a sanitizer detects an issue, you'll see output like:

```
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on unknown address 0x602000000010
READ of size 1 at 0x602000000010 thread T0
    #0 0x49ad4f in PacketParser::parse src/packet_parser.cpp:42:10
    #1 0x4b1234 in main tests/test_parser.cpp:15:5
    ...
```

**Key fields**:
- `ERROR`: Type of issue (AddressSanitizer, UndefinedBehaviorSanitizer)
- `Address` and `size`: Memory access details
- **Stack trace**: Shows where the error occurred

### Using GDB with Sanitizers

```bash
# Build with sanitizers and debug symbols
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)

# Run under gdb
gdb ./bin/test_parser

# Inside gdb:
(gdb) run
# Sanitizer will catch the issue and stop
```

### Disabling Sanitizers (if needed)

Edit `CMakeLists.txt` and comment out the sanitizer flags section or rebuild with Release mode:

```bash
cmake -DCMAKE_BUILD_TYPE=Release ..
```

## Available Test Commands

### From Root Directory

```bash
pnpm build:engine                  # Build C++ engine
pnpm test:engine                   # Run all engine tests
```

(These scripts may be defined in root `package.json` for convenience)

### From engine/build Directory

```bash
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)
ctest --output-on-failure
```

## Build Artifacts

After building, `engine/build/` contains:

```
engine/build/
├── bin/
│   ├── packet_analyzer           # Main executable
│   ├── test_parser
│   ├── test_rule_manager
│   ├── test_engine
│   ├── test_sni
│   ├── test_http
│   ├── test_flowtracker
│   ├── test_pcapng
│   └── test_golden
├── lib/
│   └── [static/shared libraries]
├── CMakeFiles/
├── CMakeCache.txt
└── Makefile (or Visual Studio solution on Windows)
```

## Troubleshooting

### CMake not found
```bash
# macOS
brew install cmake

# Linux
sudo apt-get install cmake

# Or download from cmake.org
```

### OpenSSL not found
```bash
# macOS
brew install openssl

# Linux
sudo apt-get install libssl-dev

# Then help CMake find it:
cmake -DOPENSSL_DIR=/usr/local/opt/openssl ..
```

### Sanitizer symbols not available
Ensure you're building with `-g` flag (enabled automatically in Debug mode):
```bash
cmake -DCMAKE_BUILD_TYPE=Debug ..
```

### Tests crash with SEGV
Run under sanitizer to get more details:
```bash
./bin/test_parser   # Sanitizer output will show the issue
```

### Catch2 not found
CMake will automatically fetch Catch2 via FetchContent on first run. Ensure you have internet access.

## Performance Profiling

For production builds without sanitizer overhead:

```bash
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS="-O3" ..
make -j$(nproc)

# Run and profile
perf record ./bin/packet_analyzer ...
perf report
```

## Next Steps

1. **Build the engine**: `cmake && make`
2. **Run tests**: `ctest`
3. **Review test results**: Look for PASSED/FAILED
4. **Debug failures**: Use sanitizers and stack traces
5. **Profile performance**: Use perf or Instruments (macOS)

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development guidelines.
