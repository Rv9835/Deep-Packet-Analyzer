#include "packet_parser.h"
#include <catch2/catch_test_macros.hpp>
#include <vector>

TEST_CASE("PacketParser: Parse minimal Ethernet+IPv4+TCP packet", "[parser]") {
    // Construct a minimal ethernet+IPv4+TCP packet
    std::vector<uint8_t> pkt(14 + 20 + 20);
    
    // Ethernet: dest, src, type=0x0800 (IPv4)
    pkt[12] = 0x08;
    pkt[13] = 0x00;
    
    // IPv4 header: version=4, IHL=5, total length=40
    pkt[14] = 0x45;
    pkt[15] = 0x00;
    pkt[16] = 0x00;
    pkt[17] = 0x28;
    
    // Source IP: 1.2.3.4
    pkt[26] = 1;
    pkt[27] = 2;
    pkt[28] = 3;
    pkt[29] = 4;
    
    // Destination IP: 5.6.7.8
    pkt[30] = 5;
    pkt[31] = 6;
    pkt[32] = 7;
    pkt[33] = 8;
    
    // IP Protocol: TCP (6)
    pkt[23] = 6;
    
    // TCP header: source port 1234, destination port 80
    pkt[34] = 0x04;
    pkt[35] = 0xd2; // 1234
    pkt[36] = 0x00;
    pkt[37] = 0x50; // 80

    PacketParser parser;
    auto p = parser.parse(0, 0, pkt);
    
    REQUIRE(p.has_value());
    REQUIRE(p->l4_proto == L4Proto::TCP);
    REQUIRE(p->src_port == 1234);
    REQUIRE(p->dst_port == 80);
    REQUIRE(!p->is_ipv6);
    REQUIRE(!p->fragmented);
    REQUIRE(p->src_ip == ((1 << 24) | (2 << 16) | (3 << 8) | 4));
    REQUIRE(p->dst_ip == ((5 << 24) | (6 << 16) | (7 << 8) | 8));
}

TEST_CASE("PacketParser: Detect fragmented IPv4 packets", "[parser]") {
    // Construct a fragmented packet (same IPv4 but with MF flag)
    std::vector<uint8_t> pkt(14 + 20 + 20);
    
    // Ethernet: type=0x0800 (IPv4)
    pkt[12] = 0x08;
    pkt[13] = 0x00;
    
    // IPv4 header: version=4, IHL=5, total length=40
    pkt[14] = 0x45;
    pkt[15] = 0x00;
    pkt[16] = 0x00;
    pkt[17] = 0x28;
    
    // Flags and fragment offset: MF flag set
    pkt[20] = 0x20;
    
    PacketParser parser;
    auto pf = parser.parse(0, 0, pkt);
    
    REQUIRE(pf.has_value());
    REQUIRE(pf->fragmented);
}
