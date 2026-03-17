# Engine Contract

## Purpose

Defines the expected inputs and outputs of the packet analysis engine so web/worker integrations can call it consistently.

## Inputs

Required:

-   **PCAP path/key**: source capture file (`.pcap` or `.pcapng`)
-   **Rules JSON path/key**: detection/filtering rules

Optional:

-   **Output directory**: destination for generated artifacts
-   **Mode flags**: optional runtime behavior (debug/verbose/filters)

## Rules Format (Conceptual)

Rules are JSON-based and may include criteria such as:

-   source/destination IP matching
-   domain/SNI matching
-   application/protocol type matching
-   action decision (allow/block/tag)

Example (conceptual):

```json
{
    "rules": [
        {
            "id": "rule-1",
            "match": { "domain": "example.com" },
            "action": "tag"
        }
    ]
}
```

## Outputs

Primary artifacts:

-   **`report.json`**: structured analysis output (flows, matches, metadata)
-   **`manifest.json`**: artifact/index metadata
-   **`filtered.pcap`** (optional): subset output when filtering/export is enabled

## Exit/Status Semantics

-   **Success**: process exits `0` and required artifacts are produced.
-   **Failure**: non-zero exit and error details logged to stderr/log stream.

## Error Categories

-   Invalid input path or unreadable file
-   Malformed packet content / unsupported record
-   Invalid rules JSON or schema mismatch
-   Write failure for output artifacts

## Integration Notes

-   Callers should validate existence/access for input files before execution.
-   Callers should treat `report.json` as the source of truth for analytics.
-   If `filtered.pcap` is absent, treat filtering as disabled or not applicable.
