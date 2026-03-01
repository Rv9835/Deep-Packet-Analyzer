#include "packet_parser.h"
#include <cassert>
#include <vector>

int main() {
    // construct a minimal ethernet+IPv4+TCP packet
    std::vector<uint8_t> pkt(14 + 20 + 20);
    // eth: dest, src, type=0x0800
    pkt[12] = 0x08;
    pkt[13] = 0x00;
    // ipv4 header: version=4, IHL=5, total length=40
    pkt[14] = 0x45;
    pkt[15] = 0x00;
    pkt[16] = 0x00;
    pkt[17] = 0x28;
    // src 1.2.3.4
    pkt[26] = 1;
    pkt[27] = 2;
    pkt[28] = 3;
    pkt[29] = 4;
    // dst 5.6.7.8
    pkt[30] = 5;
    pkt[31] = 6;
    pkt[32] = 7;
    pkt[33] = 8;
    // proto TCP
    pkt[23] = 6;
    // TCP header: src port 1234, dst port 80
    pkt[34] = 0x04;
    pkt[35] = 0xd2; // 1234
    pkt[36] = 0x00;
    pkt[37] = 0x50; // 80

    PacketParser parser;
    auto p = parser.parse(0,0,pkt);
    assert(p.has_value());
    assert(p->l4_proto == L4Proto::TCP);
    assert(p->src_port == 1234);
    assert(p->dst_port == 80);
    assert(!p->is_ipv6);
    assert(!p->fragmented);
    assert(p->src_ip == ((1<<24)|(2<<16)|(3<<8)|4));
    assert(p->dst_ip == ((5<<24)|(6<<16)|(7<<8)|8));
    
    // construct a fragmented packet header (same IPv4 but with MF flag)
    std::vector<uint8_t> frag = pkt;
    frag[20] = 0x20; // set flags MF only
    auto pf = parser.parse(0,0,frag);
    assert(pf.has_value());
    assert(pf->fragmented);
    return 0;
}
