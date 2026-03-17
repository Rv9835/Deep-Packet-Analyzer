#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <cstdint>
#include <vector>
#include <optional>
#include <array>

// Minimal parsed packet representation used by DPI engine.

enum class L3Proto { IPv4, Unknown };
enum class L4Proto { TCP, UDP, Unknown };

enum class ParseError {
    None = 0,
    PacketTooShortForEthernet,
    VlanHeaderTruncated,
    UnsupportedEtherType,
    IPv4HeaderTooShort,
    IPv4InvalidIHL,
    IPv4Truncated,
    IPv4InvalidTotalLength,
    TCPHeaderTooShort,
    TCPInvalidHeaderLength,
    UDPHeaderTooShort,
    UDPInvalidLength
};

struct RawPacket {
    uint64_t timestamp_us = 0;
    std::vector<uint8_t> bytes;
};

struct ParsedPacket {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint64_t ts_us = 0;
    // original raw bytes
    std::vector<uint8_t> raw;

    // parsed fields
    L3Proto l3_proto = L3Proto::Unknown;
    bool is_ipv6 = false;
    uint32_t src_ip = 0;             // for IPv4
    uint32_t dst_ip = 0;
    std::array<uint8_t,16> src_ip6 = {};
    std::array<uint8_t,16> dst_ip6 = {};

    bool fragmented = false;         // IPv4 fragment
    bool dpi_eligible = true;        // false when skipped by policy (e.g. fragments)

    L4Proto l4_proto = L4Proto::Unknown;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint32_t tcp_seq = 0;
    uint32_t tcp_ack = 0;
    uint8_t tcp_flags = 0;

    size_t payload_offset = 0;
    size_t payload_length = 0;
    std::vector<uint8_t> l4_payload;
};

struct ParseResult {
    std::optional<ParsedPacket> packet;
    ParseError error = ParseError::None;
};

struct PacketParserOptions {
    bool vlan_enabled = true;
    bool skip_fragments = true;
};

class PacketParser {
public:
    explicit PacketParser(const PacketParserOptions &options = PacketParserOptions{});
    ~PacketParser();

    // parse raw bytes; returns filled ParsedPacket on success or std::nullopt on failure
    std::optional<ParsedPacket> parse(uint32_t ts_sec,
                                      uint32_t ts_usec,
                                      const std::vector<uint8_t> &data);

    ParseResult parse(const RawPacket &raw_packet);

    ParseError lastError() const { return last_error_; }
    const PacketParserOptions& options() const { return options_; }

private:
    PacketParserOptions options_;
    ParseError last_error_;
};

#endif // PACKET_PARSER_H
