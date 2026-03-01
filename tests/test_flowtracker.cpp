#include "flow_tracker.h"
#include "packet_parser.h"
#include <cassert>
#include <vector>

// helper to construct a fake ParsedPacket
ParsedPacket make_pkt(bool ipv6, const std::array<uint8_t,16> &src6,
                      const std::array<uint8_t,16> &dst6,
                      uint32_t src4, uint32_t dst4,
                      uint16_t sport, uint16_t dport) {
    ParsedPacket p;
    p.ts_sec = 1;
    p.ts_usec = 0;
    p.l4_proto = L4Proto::TCP;
    p.src_port = sport;
    p.dst_port = dport;
    if (ipv6) {
        p.is_ipv6 = true;
        p.src_ip6 = src6;
        p.dst_ip6 = dst6;
    } else {
        p.is_ipv6 = false;
        p.src_ip = src4;
        p.dst_ip = dst4;
    }
    return p;
}

int main() {
    FlowTracker ft;
    ParsedPacket a = make_pkt(false, {}, {}, 0x01020304, 0x05060708, 1000, 80);
    ParsedPacket b = make_pkt(true,
                              {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1},
                              {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2},
                              0,0,80,1000);
    ft.addPacket(a);
    ft.addPacket(b);
    auto &flows = ft.flows();
    assert(flows.size() == 2);
    // ensure ordering: IPv4 before IPv6
    auto it = flows.begin();
    assert(!it->first.is_ipv6);
    ++it;
    assert(it->first.is_ipv6);
    return 0;
}
