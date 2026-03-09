# Packet Analyzer

This is a simple packet analysis project written in C++. It includes modules for:

- DPI engine(multi‑threaded)
- Packet parsing (Ethernet/IPv4/IPv6/TCP/UDP, VLAN, fragmentation, pcapng)
- Connection tracking with deterministic canonical flow keys
- Rule engine (IP, domain, app‑type)
- Metadata extraction (SNI, HTTP host)
- Minimal web/worker job orchestration and prototype


## Building the C++ Engine

The C++ engine uses **CMake** with standardized output directories to `engine/build/`.

### Quick Start

```bash
cd /path/to/Deep\ Packet\ Analyzer
mkdir -p engine/build
cd engine/build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)  # or: cmake --build .
```

The binary is built to: `engine/build/bin/packet_analyzer`

### Running Tests

Tests use **Catch2** framework and are integrated with **ctest**:

```bash
cd engine/build
ctest --output-on-failure      # Run all tests
ctest -R parser --output-on-failure  # Run specific test
./bin/test_parser              # Run test directly
```

### Address and Undefined Behavior Sanitizers

**Debug builds automatically enable sanitizers** (AddressSanitizer + UndefinedBehaviorSanitizer) on non-Windows platforms to detect memory errors and undefined behavior:

```bash
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)
./bin/test_parser  # Sanitizers will catch memory issues
```

For complete build and testing documentation, see [docs/building.md](docs/building.md).



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

## Database Setup

This project uses [Prisma](https://www.prisma.io/) for database schema and migrations.
The database workspace is located in `packages/db`.

### Prerequisites

- PostgreSQL running (via Docker Compose: `docker-compose up -d`)
- Set `DATABASE_URL` environment variable (see `.env.example`)

### Quick Start

```bash
# Install dependencies (one-time)
pnpm -w install

# Create and apply migrations
pnpm db:migrate:dev

# Seed database with test data
pnpm db:seed

# View database UI
pnpm db:studio
```

### Database Scripts

All scripts can be run from the project root:

- **`pnpm db:migrate:dev`** - Create/apply migrations in development
- **`pnpm db:migrate`** - Apply migrations (production)
- **`pnpm db:reset`** - Reset database and re-run all migrations
- **`pnpm db:seed`** - Populate with test data (user, project, rules, etc.)
- **`pnpm db:studio`** - Open Prisma Studio (web UI for data inspection)

See [packages/db/README.md](packages/db/README.md) for detailed documentation.

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
