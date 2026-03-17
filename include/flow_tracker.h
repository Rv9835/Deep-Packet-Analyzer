#ifndef FLOW_TRACKER_H
#define FLOW_TRACKER_H

#include "packet_parser.h"
#include "extractor.h"
#include "rule_manager.h"  // for Action
#include <cstdint>
#include <cstring>
#include <map>
#include <vector>
#include <optional>
#include <string>
#include <unordered_map>

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

    // packet direction relative to canonical key
    enum class Direction {
        AtoB = 0,
        BtoA = 1
    };

    static Direction directionOf(const FlowKey &key, const ParsedPacket &pkt);
};

struct FlowKeyHash {
    size_t operator()(const FlowKey &k) const;
};

bool operator==(FlowKey const &a, FlowKey const &b);

// helper for IPv6 lexicographic compare
inline bool ipv6_less(const std::array<uint8_t,16> &a,
                      const std::array<uint8_t,16> &b) {
    return std::memcmp(a.data(), b.data(), 16) < 0;
}

struct FlowState {
    uint64_t packets = 0;
    uint64_t bytes = 0;
    uint64_t first_seen_ts = 0; // microseconds
    uint64_t last_seen_ts = 0;
    uint64_t packets_ab = 0;
    uint64_t packets_ba = 0;
    uint64_t bytes_ab = 0;
    uint64_t bytes_ba = 0;
    // extracted metadata
    std::optional<std::string> sni;
    std::optional<std::string> http_host;
    // classification / filtering
    std::optional<Action> decision;
    std::optional<size_t> matched_rule_index;
    std::optional<std::string> matched_rule_id;
    std::optional<std::string> match_reason;
    std::optional<std::string> app_type;
    FlowMetadata metadata;
};

using FlowStats = FlowState;

class FlowTracker {
public:
    FlowTracker();
    ~FlowTracker();

    explicit FlowTracker(uint64_t max_flows);

    // decision: allow/deny for this packet, rule_index indicates which rule matched
    void addPacket(const ParsedPacket &pkt,
                   std::optional<Action> decision = std::nullopt,
                   std::optional<size_t> rule_index = std::nullopt,
                   std::optional<std::string> rule_id = std::nullopt,
                   std::optional<std::string> match_reason = std::nullopt);

    const std::map<FlowKey, FlowState> &flows() const { return flows_; }
    std::map<FlowKey, FlowState> &mutableFlows() { return flows_; }

    bool overflowed() const { return overflowed_; }
    uint64_t maxFlows() const { return max_flows_; }

private:
    std::map<FlowKey, FlowState> flows_;
    uint64_t max_flows_ = 0;
    bool overflowed_ = false;
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
            dst.packets_ab += src.packets_ab;
            dst.packets_ba += src.packets_ba;
            dst.bytes_ab += src.bytes_ab;
            dst.bytes_ba += src.bytes_ba;
            if (dst.first_seen_ts == 0 || (src.first_seen_ts && src.first_seen_ts < dst.first_seen_ts))
                dst.first_seen_ts = src.first_seen_ts;
            if (src.last_seen_ts > dst.last_seen_ts) dst.last_seen_ts = src.last_seen_ts;
            // metadata could be merged or kept from first shard
        }
    }
}

#endif // FLOW_TRACKER_H
