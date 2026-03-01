#ifndef FLOW_TRACKER_H
#define FLOW_TRACKER_H

#include "packet_parser.h"
#include "rule_manager.h"  // for Action
#include <cstdint>
#include <map>
#include <vector>
#include <optional>
#include <string>

struct FlowKey {
    bool is_ipv6 = false;
    uint32_t ip1;
    uint32_t ip2;
    std::array<uint8_t,16> ip6_1;
    std::array<uint8_t,16> ip6_2;
    uint16_t port1;
    uint16_t port2;
    L4Proto proto;

    // canonicalize direction and build key from packet
    static FlowKey make(const ParsedPacket &pkt);
};

// helper for IPv6 lexicographic compare
inline bool ipv6_less(const std::array<uint8_t,16> &a,
                      const std::array<uint8_t,16> &b) {
    return std::memcmp(a.data(), b.data(), 16) < 0;
}

struct FlowStats {
    uint64_t packets = 0;
    uint64_t bytes = 0;
    uint64_t first_seen_ts = 0; // microseconds
    uint64_t last_seen_ts = 0;
    // extracted metadata
    std::optional<std::string> sni;
    std::optional<std::string> http_host;
    // classification / filtering
    std::optional<Action> decision;
    std::optional<size_t> matched_rule_index;
    std::optional<std::string> app_type;
};

class FlowTracker {
public:
    FlowTracker();
    ~FlowTracker();

    // decision: allow/deny for this packet, rule_index indicates which rule matched
    void addPacket(const ParsedPacket &pkt,
                   std::optional<Action> decision = std::nullopt,
                   std::optional<size_t> rule_index = std::nullopt);

    const std::map<FlowKey, FlowStats> &flows() const { return flows_; }

private:
    std::map<FlowKey, FlowStats> flows_;
};

// define ordering to allow FlowKey to be used as map key
bool operator<(FlowKey const &a, FlowKey const &b);

// merge two flow maps (from different threads/shards) into dest, maintaining deterministic order
static void mergeFlows(std::map<FlowKey, FlowStats> &dest,
                       const std::map<FlowKey, FlowStats> &other) {
    for (auto const &kv : other) {
        auto it = dest.find(kv.first);
        if (it == dest.end()) {
            dest.insert(kv);
        } else {
            // combine stats deterministically: sum packets/bytes, update timestamps
            FlowStats &dst = it->second;
            const FlowStats &src = kv.second;
            dst.packets += src.packets;
            dst.bytes += src.bytes;
            if (dst.first_seen_ts == 0 || (src.first_seen_ts && src.first_seen_ts < dst.first_seen_ts))
                dst.first_seen_ts = src.first_seen_ts;
            if (src.last_seen_ts > dst.last_seen_ts) dst.last_seen_ts = src.last_seen_ts;
            // metadata could be merged or kept from first shard
        }
    }
}

#endif // FLOW_TRACKER_H
