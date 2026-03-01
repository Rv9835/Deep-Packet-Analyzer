#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <cstdint>
#include <vector>
#include <optional>

// Minimal parsed packet representation used by DPI engine.

enum class L3Proto { IPv4, Unknown };
enum class L4Proto { TCP, UDP, Unknown };

struct ParsedPacket {
    uint32_t ts_sec;
    uint32_t ts_usec;
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

    L4Proto l4_proto = L4Proto::Unknown;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    std::vector<uint8_t> l4_payload;
};

class PacketParser {
public:
    PacketParser();
    ~PacketParser();

    // parse raw bytes; returns filled ParsedPacket on success or std::nullopt on failure
    std::optional<ParsedPacket> parse(uint32_t ts_sec,
                                      uint32_t ts_usec,
                                      const std::vector<uint8_t> &data);
};

#endif // PACKET_PARSER_H
