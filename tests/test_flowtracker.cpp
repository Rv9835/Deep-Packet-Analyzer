#include "flow_tracker.h"
#include "packet_parser.h"
#include <catch2/catch_test_macros.hpp>
#include <vector>

namespace {
ParsedPacket makeIpv4Pkt(uint32_t src,
                         uint32_t dst,
                         uint16_t sport,
                         uint16_t dport,
                         uint64_t ts_us,
                         size_t bytes = 60) {
    ParsedPacket p;
    p.is_ipv6 = false;
    p.l4_proto = L4Proto::TCP;
    p.src_ip = src;
    p.dst_ip = dst;
    p.src_port = sport;
    p.dst_port = dport;
    p.ts_sec = static_cast<uint32_t>(ts_us / 1000000ULL);
    p.ts_usec = static_cast<uint32_t>(ts_us % 1000000ULL);
    p.raw.assign(bytes, 0);
    return p;
}

FlowState runScenario(const std::vector<ParsedPacket> &packets) {
    FlowTracker tracker;
    for (const auto &pkt : packets) {
        tracker.addPacket(pkt);
    }
    REQUIRE(tracker.flows().size() == 1);
    return tracker.flows().begin()->second;
}
}

TEST_CASE("FlowKey canonicalization is direction-consistent for IPv4", "[flowtracker]") {
    ParsedPacket forward = makeIpv4Pkt(0x01020304, 0x05060708, 12345, 443, 1000000, 120);
    ParsedPacket reverse = makeIpv4Pkt(0x05060708, 0x01020304, 443, 12345, 1000100, 90);

    FlowTracker tracker;
    tracker.addPacket(forward);
    tracker.addPacket(reverse);

    REQUIRE(tracker.flows().size() == 1);
    const auto &st = tracker.flows().begin()->second;
    REQUIRE(st.packets == 2);
    REQUIRE(st.packets_ab == 1);
    REQUIRE(st.packets_ba == 1);
    REQUIRE(st.bytes == 210);
    REQUIRE(st.bytes_ab == 120);
    REQUIRE(st.bytes_ba == 90);
}

TEST_CASE("Flow state aggregation is deterministic for same packet set", "[flowtracker]") {
    ParsedPacket p1 = makeIpv4Pkt(0x01020304, 0x05060708, 12345, 443, 2000000, 100);
    ParsedPacket p2 = makeIpv4Pkt(0x05060708, 0x01020304, 443, 12345, 2000050, 80);
    ParsedPacket p3 = makeIpv4Pkt(0x01020304, 0x05060708, 12345, 443, 1999000, 40);

    FlowState ordered = runScenario({p1, p2, p3});
    FlowState reversed = runScenario({p3, p2, p1});

    REQUIRE(ordered.packets == reversed.packets);
    REQUIRE(ordered.bytes == reversed.bytes);
    REQUIRE(ordered.first_seen_ts == reversed.first_seen_ts);
    REQUIRE(ordered.last_seen_ts == reversed.last_seen_ts);
    REQUIRE(ordered.packets_ab == reversed.packets_ab);
    REQUIRE(ordered.packets_ba == reversed.packets_ba);
}

TEST_CASE("Flow iteration order is deterministic and sorted by key", "[flowtracker]") {
    FlowTracker tracker;
    tracker.addPacket(makeIpv4Pkt(0x0A000002, 0x0A000003, 15000, 443, 1000000));
    tracker.addPacket(makeIpv4Pkt(0x0A000001, 0x0A000004, 14000, 80, 1000100));
    tracker.addPacket(makeIpv4Pkt(0x0A000005, 0x0A000006, 16000, 53, 1000200));

    REQUIRE(tracker.flows().size() == 3);

    uint32_t prevIp1 = 0;
    uint16_t prevPort1 = 0;
    bool first = true;
    for (const auto &kv : tracker.flows()) {
        const FlowKey &key = kv.first;
        if (!first) {
            bool nondecreasing = (key.ip1 > prevIp1) ||
                                 (key.ip1 == prevIp1 && key.port1 >= prevPort1);
            REQUIRE(nondecreasing);
        }
        first = false;
        prevIp1 = key.ip1;
        prevPort1 = key.port1;
    }
}

TEST_CASE("FlowTracker max flow policy is deterministic reject-on-overflow", "[flowtracker]") {
    FlowTracker tracker(1);
    tracker.addPacket(makeIpv4Pkt(0x01010101, 0x02020202, 1111, 2222, 1000000));
    tracker.addPacket(makeIpv4Pkt(0x03030303, 0x04040404, 3333, 4444, 1000100));

    REQUIRE(tracker.flows().size() == 1);
    REQUIRE(tracker.overflowed());
}
