#!/usr/bin/env python3
"""Utility to generate a simple pcap file for testing."""
import scapy.all as scapy

pkts = []
# simple HTTP GET packet
http_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
pkts.append(scapy.IP(dst="1.2.3.4")/scapy.TCP(dport=80)/http_payload)

# minimal TLS ClientHello with SNI (using raw bytes)
tls_hello = bytes.fromhex(
    "16 03 01 00 2e"  # record hdr
    "01 00 00 2a"      # handshake hdr
    "03 03"            # version TLS 1.2
    "00"*32            # random
    "00"               # session id len
    "00 02 00 2f"      # cipher suites len + one suite
    "01"               # comp methods len
    "00 00 0a"         # ext len
    "00 00 00 06 00 04 00 02 00 00"  # server_name ext with example.com
)
pkts.append(scapy.IP(dst="5.6.7.8")/scapy.TCP(dport=443)/tls_hello)

scapy.wrpcap("test_dpi.pcap", pkts)
print("Generated test_dpi.pcap with a single packet")
