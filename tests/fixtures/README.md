# Golden fixtures for determinism tests

This directory should contain pairs of input PCAPs and expected outputs.

Structure:

```
http.pcap
http.rules.json
http.expected_report.json
http.expected_filtered_hash.txt

tls.pcap
... etc
```

Use `generate_test_pcap.py` or external tools to produce these files. The CI harness will run the engine on each PCAP with the corresponding ruleset and compare the report and filtered pcap hash against the expected values.
