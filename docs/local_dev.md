# Local Development Guide

## 1) Prerequisites

Install:

-   CMake + C++17 compiler toolchain
-   Node.js (LTS) + `pnpm`
-   Docker + Docker Compose

macOS quick setup (example):

```bash
xcode-select --install
brew install cmake openssl pnpm
```

## 2) Clone and Install

From repository root:

```bash
pnpm -w install
```

## 3) Start Local Infrastructure

Bring up local services (Postgres, Redis, MinIO):

```bash
docker-compose up -d
```

Verify:

```bash
docker-compose ps
```

## 4) Build the C++ Engine

```bash
mkdir -p build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
cmake --build . -j
```

Run tests:

```bash
ctest --output-on-failure
```

## 5) Run Web + Worker

From repo root:

```bash
pnpm --filter web start
pnpm --filter worker start
```

Use separate terminals, or run your preferred process manager.

## 6) Lint/Format and Hooks

Manual commands:

```bash
pnpm lint
pnpm format
```

Pre-commit checks are enabled via Husky + lint-staged and run fast checks on staged files.

## 7) Typical Development Loop

1. Start infra (`docker-compose up -d`)
2. Build/test engine (`cmake`, `ctest`)
3. Run web + worker
4. Make changes
5. Stage + commit (pre-commit runs formatting/lint)

## 8) Troubleshooting

-   **Missing pnpm**: `npm i -g pnpm`
-   **CMake configure failures**: ensure compiler and OpenSSL are installed
-   **Port conflicts**: check `5432`, `6379`, `9000`, `9001`
-   **Hook not running**: run `pnpm install` to re-run `prepare` and reinstall Husky
