# Architecture Overview

## System Summary

Deep Packet Analyzer is a hybrid system with a C++ packet-analysis engine and optional JavaScript services for orchestration.

High-level components:

-   **Engine (C++)**: Reads pcap/pcapng, parses protocols, tracks flows, extracts metadata, applies rules, writes analysis artifacts.
-   **Web API (Node.js/Express)**: Accepts analysis jobs and exposes endpoints for job lifecycle.
-   **Worker (Node.js)**: Consumes jobs and coordinates execution/updates.
-   **Database (Prisma/Postgres)**: Stores operational metadata and workflow state.
-   **Object Storage (MinIO/S3-compatible)**: Stores uploaded captures and generated artifacts.

## Data Flow

1. Client creates a job via Web API.
2. Capture file and rules are referenced by key/path.
3. Worker picks the job and invokes analysis logic.
4. Engine processes packets and emits outputs (report, optional filtered pcap, manifest).
5. Worker marks job complete and stores output references.

## Engine Internals

The C++ engine is organized around:

-   `pcap_reader`: source packet ingestion
-   `packet_parser`: protocol decoding (Ethernet/IP/TCP/UDP/etc.)
-   `flow_tracker` and `connection_tracker`: flow/session state
-   `sni_extractor` and `http_extractor`: metadata extraction
-   `rule_manager`: policy matching
-   `dpi_engine`: pipeline orchestration

## Runtime Surfaces

-   **CLI path**: run engine directly against capture + rules.
-   **Service path**: web/worker pipeline for asynchronous execution.

## Non-Goals (Current State)

-   Multi-tenant authorization model
-   Long-term distributed queue guarantees
-   Horizontal autoscaling policy (prototype-level orchestration)
