#include "packet_parser.h"
#include <catch2/catch_test_macros.hpp>
#include <vector>

namespace {
std::vector<uint8_t> makeEthernetIPv4Base(uint8_t protocol, uint16_t total_length) {
    std::vector<uint8_t> pkt(14 + 20, 0);
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    pkt[14] = 0x45;
    pkt[15] = 0x00;
    pkt[16] = static_cast<uint8_t>((total_length >> 8) & 0xff);
    pkt[17] = static_cast<uint8_t>(total_length & 0xff);
    pkt[18] = 0x00;
    pkt[19] = 0x01;
    pkt[20] = 0x00;
    pkt[21] = 0x00;
    pkt[22] = 64;
    pkt[23] = protocol;

    pkt[26] = 1;
    pkt[27] = 2;
    pkt[28] = 3;
    pkt[29] = 4;
    pkt[30] = 5;
    pkt[31] = 6;
    pkt[32] = 7;
    pkt[33] = 8;
    return pkt;
}
}

TEST_CASE("PacketParser: Parse minimal Ethernet+IPv4+TCP packet", "[parser]") {
    std::vector<uint8_t> pkt = makeEthernetIPv4Base(6, 40);
    pkt.resize(14 + 40, 0);

    pkt[34] = 0x04;
    pkt[35] = 0xd2;
    pkt[36] = 0x00;
    pkt[37] = 0x50;
    pkt[46] = 0x50;

    PacketParser parser;
    RawPacket raw{1234567, pkt};
    auto result = parser.parse(raw);

    REQUIRE(result.packet.has_value());
    REQUIRE(result.error == ParseError::None);
    REQUIRE(result.packet->ts_us == 1234567);
    REQUIRE(result.packet->l4_proto == L4Proto::TCP);
    REQUIRE(result.packet->src_port == 1234);
    REQUIRE(result.packet->dst_port == 80);
    REQUIRE(!result.packet->is_ipv6);
    REQUIRE(!result.packet->fragmented);
    REQUIRE(result.packet->dpi_eligible);
    REQUIRE(result.packet->src_ip == ((1 << 24) | (2 << 16) | (3 << 8) | 4));
    REQUIRE(result.packet->dst_ip == ((5 << 24) | (6 << 16) | (7 << 8) | 8));
}

TEST_CASE("PacketParser: Ethernet minimum length validation", "[parser]") {
    PacketParser parser;
    RawPacket raw{0, std::vector<uint8_t>(13, 0)};
    auto result = parser.parse(raw);
    REQUIRE_FALSE(result.packet.has_value());
    REQUIRE(result.error == ParseError::PacketTooShortForEthernet);
}

TEST_CASE("PacketParser: VLAN parsing updates EtherType when enabled", "[parser]") {
    std::vector<uint8_t> pkt(14 + 4 + 20 + 8, 0);
    pkt[12] = 0x81;
    pkt[13] = 0x00;
    pkt[16] = 0x08;
    pkt[17] = 0x00;

    pkt[18] = 0x45;
    pkt[20] = 0x00;
    pkt[21] = 0x1c;
    pkt[26] = 64;
    pkt[27] = 17;
    pkt[30] = 10;
    pkt[31] = 0;
    pkt[32] = 0;
    pkt[33] = 1;
    pkt[34] = 10;
    pkt[35] = 0;
    pkt[36] = 0;
    pkt[37] = 2;

    pkt[38] = 0x1f;
    pkt[39] = 0x90;
    pkt[40] = 0x00;
    pkt[41] = 0x35;
    pkt[42] = 0x00;
    pkt[43] = 0x08;

    PacketParser parser;
    auto result = parser.parse(RawPacket{0, pkt});
    REQUIRE(result.packet.has_value());
    REQUIRE(result.packet->l4_proto == L4Proto::UDP);
    REQUIRE(result.error == ParseError::None);
}

TEST_CASE("PacketParser: IPv4 IHL and total length are validated", "[parser]") {
    auto pkt = makeEthernetIPv4Base(6, 40);
    pkt[14] = 0x44;
    pkt.resize(14 + 40, 0);

    PacketParser parser;
    auto result = parser.parse(RawPacket{0, pkt});
    REQUIRE_FALSE(result.packet.has_value());
    REQUIRE(result.error == ParseError::IPv4InvalidIHL);

    pkt = makeEthernetIPv4Base(6, 10);
    pkt.resize(14 + 20, 0);
    result = parser.parse(RawPacket{0, pkt});
    REQUIRE_FALSE(result.packet.has_value());
    REQUIRE(result.error == ParseError::IPv4InvalidTotalLength);
}

TEST_CASE("PacketParser: Fragmentation policy marks non-DPI eligible when configured", "[parser]") {
    auto pkt = makeEthernetIPv4Base(17, 28);
    pkt.resize(14 + 28, 0);
    pkt[20] = 0x20;
    pkt[34] = 0x00;
    pkt[35] = 0x35;
    pkt[36] = 0x1f;
    pkt[37] = 0x90;
    pkt[38] = 0x00;
    pkt[39] = 0x08;

    PacketParser parserSkip(PacketParserOptions{true, true});
    auto skipped = parserSkip.parse(RawPacket{0, pkt});
    REQUIRE(skipped.packet.has_value());
    REQUIRE(skipped.packet->fragmented);
    REQUIRE_FALSE(skipped.packet->dpi_eligible);

    PacketParser parserKeep(PacketParserOptions{true, false});
    auto kept = parserKeep.parse(RawPacket{0, pkt});
    REQUIRE(kept.packet.has_value());
    REQUIRE(kept.packet->fragmented);
    REQUIRE(kept.packet->dpi_eligible);
}

TEST_CASE("PacketParser: TCP header length and payload slice are safe", "[parser]") {
    auto pkt = makeEthernetIPv4Base(6, 44);
    pkt.resize(14 + 44, 0);
    pkt[34] = 0x00;
    pkt[35] = 0x50;
    pkt[36] = 0x13;
    pkt[37] = 0x88;
    pkt[46] = 0x60;
    pkt[47] = 0x12;
    pkt[54] = 0xaa;
    pkt[55] = 0xbb;
    pkt[56] = 0xcc;
    pkt[57] = 0xdd;

    PacketParser parser;
    auto result = parser.parse(RawPacket{0, pkt});
    REQUIRE(result.packet.has_value());
    REQUIRE(result.packet->l4_proto == L4Proto::TCP);
    REQUIRE(result.packet->tcp_flags == 0x12);
    REQUIRE(result.packet->payload_length == 4);
    REQUIRE(result.packet->l4_payload.size() == 4);

    pkt[46] = 0x40;
    result = parser.parse(RawPacket{0, pkt});
    REQUIRE_FALSE(result.packet.has_value());
    REQUIRE(result.error == ParseError::TCPInvalidHeaderLength);
}

TEST_CASE("PacketParser: UDP length and payload slice are safe", "[parser]") {
    auto pkt = makeEthernetIPv4Base(17, 32);
    pkt.resize(14 + 32, 0);
    pkt[34] = 0x00;
    pkt[35] = 0x35;
    pkt[36] = 0x13;
    pkt[37] = 0x89;
    pkt[38] = 0x00;
    pkt[39] = 0x0c;
    pkt[42] = 0xde;
    pkt[43] = 0xad;
    pkt[44] = 0xbe;
    pkt[45] = 0xef;

    PacketParser parser;
    auto result = parser.parse(RawPacket{0, pkt});
    REQUIRE(result.packet.has_value());
    REQUIRE(result.packet->l4_proto == L4Proto::UDP);
    REQUIRE(result.packet->payload_length == 4);
    REQUIRE(result.packet->l4_payload.size() == 4);

    pkt[38] = 0x00;
    pkt[39] = 0x07;
    result = parser.parse(RawPacket{0, pkt});
    REQUIRE_FALSE(result.packet.has_value());
    REQUIRE(result.error == ParseError::UDPInvalidLength);
}
