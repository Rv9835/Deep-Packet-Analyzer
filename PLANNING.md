# Phase 1 & 2 Planning for DPI Engine MVP

This document executes the planning tasks step by step in the order specified in the Phase 1 planning list.

## 1. MVP user journey (Upload → Rules → Run → Report → Download)

### 1.1 Personas & primary scenario

**Personas:**

- **DPI engineer**
  - *One job to be done:* "As a DPI engineer I want to analyse a PCAP with a custom ruleset so I can verify firewall/IDS behaviour."
- **Security researcher**
  - *One job to be done:* "As a researcher I want to run deterministic analysis on a capture to reproduce an exploit and share the report."
- **Networking student**
  - *One job to be done:* "As a student I want to upload a trace and see which applications and domains appear so I can learn about traffic patterns."

**Primary MVP persona:** DPI engineer.

### 1.2 Workflow state machine

**States:**

```
draft → uploaded → queued → running → succeeded/failed → archived
```

**Allowed transitions:**

1. *draft → uploaded* – user selects file & metadata recorded.
2. *uploaded → queued* – user clicks "Start job"; system freezes config & enqueues.
3. *queued → running* – worker picks job from Redis.
4. *running → succeeded* – engine completes with outputs.
   or *running → failed* – unrecoverable error.
5. *succeeded/failed → archived* – manual or automated archival.

**Retry behaviour:**

- Automatic: transient network errors downloading/uploading objects, Redis timeouts.
- No retry: corrupted PCAP, invalid ruleset, job logic errors.

### 1.3 Screen / API interactions

#### Upload page requirements

- File picker with size validation message.
- Basic upload progress UI.
- Capture PCAP metadata (filename, size, sha256).

#### Rules selection requirements

- Select an existing ruleset/profile.
- Preview ruleset contents before running.
- Validate ruleset schema before submission.

#### Run analysis requirements

- "Start job" action creates immutable job config snapshot.
- Show job status updates (polling MVP).

#### Report view requirements

- Summary stats (packets, flows, top domains/apps).
- Flow table (sortable, deterministic ordering).
- Filtering controls (client-side only in MVP).

#### Download outputs requirements

- Download filtered PCAP.
- Download report JSON.
- Show hashes (report hash + output PCAP hash).

### 1.4 Engine data artifacts

- `report.json` (canonical schema, deterministic order).
- `filtered.pcap`.
- `engine.log` (optional but recommended).
- `manifest.json` (version + hashes + config snapshot).

### 1.5 Happy & failure paths

- **Happy path:** valid PCAP + valid rules → outputs produced.

**Failure catalog:**

| Failure type                   | Policy                                |
|-------------------------------|---------------------------------------|
| corrupted/unsupported PCAP    | job fails                             |
| exceeds size/flow limits      | job fails                             |
| parsing error in packet       | skip packet, continue                 |
| worker timeout                | job fails; allow manual retry         |


Policies defined as above.

## 2. Determinism specification

### 2.1 Scope

Deterministic outputs: `filtered.pcap`, `report.json`, `manifest.json`.
UI ordering must mirror report order but need not be bitwise deterministic.

### 2.2 Flow identity canonicalization

- 5-tuple: `(src_ip:u32, dst_ip:u32, src_port:u16, dst_port:u16, l4_proto:{TCP,UDP})`.
- Canonical direction: reorder endpoints lexicographically (Option B).
- Comparison: ip → ip → port → port → proto.
- Preserve original direction stats in `client_*`/`server_*` fields.

### 2.3 Stable ordering rules

Sort lists by:

1. canonical 5‑tuple lexicographic
2. `first_seen` timestamp
3. packet index

Apply to flows, domains, app types, rules applied.

### 2.4 Stable timestamp handling

- Normalize to microseconds (`u64`).
- Invalid/missing timestamps cause job failure.
- Duration = `last_seen - first_seen`.

### 2.5 Stable report JSON formatting

- Explicit key ordering.
- No floats; integers only.
- Line ending `\n`.
- Deterministic pretty-print (2‑space indent).

### 2.6 Stable classification precedence

1. domain rules
2. IP rules
3. app-type rules
4. default action

Tie-break: first-match wins. Domains lowercased, trailing dot removed.

### 2.7 Multi-thread determinism rules

- Merge shards by sorting on stable flow key.
- Outputs must not depend on timing.

## 3. Parsing scope for MVP

### 3.1 Link-layer

- Ethernet II required.
- Single 802.1Q VLAN tag; stacked VLANs skipped with warning.

### 3.2 Network-layer

- IPv4 only.
- Validate IHL ≥5, total length ≥ header length.
- Ignore checksum.
- IP options parsed minimally.

### 3.3 Transport-layer

- TCP with data offset ≥5; recognise flags.
- UDP with length validation.

### 3.4 Fragmentation

Option A: no reassembly. Count under `fragmented_packets_skipped`. Pass-through filtering.

### 3.5 Payload extraction

- TCP: raw segment payload (no reassembly).
- UDP: datagram payload.
- Inspect up to 4 KiB per packet.

### 3.6 Error-handling policy

Table of error codes mapping to skip/fail decisions.

## 4. Rule model for MVP

### 4.1 Rule types

- IP rule: allow/deny, direction src|dst|both, CIDR.
- Domain rule: allow/deny, source tls_sni|http_host|either, pattern (exact/wildcard).
- App-type rule: allow/deny, enum value.

### 4.2 Ruleset structure

Metadata, ordered rules list, default action, deterministic hash.

### 4.3 Normalization rules

IPs canonical; domains lowercase trimmed; ports optional.

### 4.4 Matching algorithm & precedence

First-match-wins; evaluate SNI→Host→IP→app→default.

### 4.5 Rule evaluation outputs

Each flow records matched rule id, reason, decision.

## 5. Acceptance criteria

### 5.1 Deterministic hashes

SHA-256 on bytes of `filtered.pcap` and `report.json`.

### 5.2 Version pinning

Engine version and schema version in manifest; tests run against fixed commit.

### 5.3 Golden test suite

Fixtures: HTTP, TLS, mixed, malformed, fragmented. Each with ruleset and expected outputs.

### 5.4 Tolerance policy

Skipped packet counts reported; heuristics deterministic.

### 5.5 Performance guardrails

Configurable limits for flows, packets, runtime; exceeding ⇒ job failure.
