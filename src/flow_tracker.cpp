#include "flow_tracker.h"
#include "sni_extractor.h"
#include "http_extractor.h"
#include <cstring>
#include <functional>
#include <memory>

namespace {
template <typename T>
inline void hash_combine(size_t &seed, const T &value) {
    seed ^= std::hash<T>{}(value) + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
}

std::vector<std::unique_ptr<Extractor>> build_extractors() {
    std::vector<std::unique_ptr<Extractor>> extractors;
    extractors.emplace_back(std::make_unique<SNIExtractor>());
    extractors.emplace_back(std::make_unique<HTTPExtractor>());
    return extractors;
}
}

FlowKey FlowKey::make(const ParsedPacket &pkt) {
    FlowKey k;
    k.proto = pkt.l4_proto;
    if (pkt.is_ipv6) {
        k.is_ipv6 = true;
        // lexicographically compare address+port
        bool swap = false;
        if (ipv6_less(pkt.dst_ip6, pkt.src_ip6)) swap = true;
        else if (memcmp(pkt.dst_ip6.data(), pkt.src_ip6.data(), 16) == 0) {
            if (pkt.dst_port < pkt.src_port) swap = true;
        }
        if (swap) {
            k.ip6_1 = pkt.dst_ip6;
            k.ip6_2 = pkt.src_ip6;
            k.port1 = pkt.dst_port;
            k.port2 = pkt.src_port;
        } else {
            k.ip6_1 = pkt.src_ip6;
            k.ip6_2 = pkt.dst_ip6;
            k.port1 = pkt.src_port;
            k.port2 = pkt.dst_port;
        }
    } else {
        bool swap = false;
        if (pkt.dst_ip < pkt.src_ip) swap = true;
        else if (pkt.dst_ip == pkt.src_ip && pkt.dst_port < pkt.src_port) swap = true;

        if (swap) {
            k.ip1 = pkt.dst_ip;
            k.ip2 = pkt.src_ip;
            k.port1 = pkt.dst_port;
            k.port2 = pkt.src_port;
        } else {
            k.ip1 = pkt.src_ip;
            k.ip2 = pkt.dst_ip;
            k.port1 = pkt.src_port;
            k.port2 = pkt.dst_port;
        }
    }
    return k;
}

FlowKey::Direction FlowKey::directionOf(const FlowKey &key, const ParsedPacket &pkt) {
    if (key.is_ipv6) {
        bool a_to_b = (std::memcmp(key.ip6_1.data(), pkt.src_ip6.data(), 16) == 0) &&
                      (std::memcmp(key.ip6_2.data(), pkt.dst_ip6.data(), 16) == 0) &&
                      key.port1 == pkt.src_port &&
                      key.port2 == pkt.dst_port;
        return a_to_b ? Direction::AtoB : Direction::BtoA;
    }

    bool a_to_b = key.ip1 == pkt.src_ip && key.ip2 == pkt.dst_ip &&
                  key.port1 == pkt.src_port && key.port2 == pkt.dst_port;
    return a_to_b ? Direction::AtoB : Direction::BtoA;
}

size_t FlowKeyHash::operator()(const FlowKey &k) const {
    size_t seed = 0;
    hash_combine(seed, k.is_ipv6);
    if (k.is_ipv6) {
        for (auto b : k.ip6_1) hash_combine(seed, b);
        for (auto b : k.ip6_2) hash_combine(seed, b);
    } else {
        hash_combine(seed, k.ip1);
        hash_combine(seed, k.ip2);
    }
    hash_combine(seed, k.port1);
    hash_combine(seed, k.port2);
    hash_combine(seed, static_cast<int>(k.proto));
    return seed;
}

bool operator==(FlowKey const &a, FlowKey const &b) {
    if (a.is_ipv6 != b.is_ipv6) return false;
    if (a.port1 != b.port1 || a.port2 != b.port2 || a.proto != b.proto) return false;

    if (a.is_ipv6) {
        return std::memcmp(a.ip6_1.data(), b.ip6_1.data(), 16) == 0 &&
               std::memcmp(a.ip6_2.data(), b.ip6_2.data(), 16) == 0;
    }
    return a.ip1 == b.ip1 && a.ip2 == b.ip2;
}

bool operator<(FlowKey const &a, FlowKey const &b) {
    if (a.is_ipv6 != b.is_ipv6) return a.is_ipv6 < b.is_ipv6;
    if (a.is_ipv6) {
        if (ipv6_less(a.ip6_1, b.ip6_1)) return true;
        if (ipv6_less(b.ip6_1, a.ip6_1)) return false;
        if (ipv6_less(a.ip6_2, b.ip6_2)) return true;
        if (ipv6_less(b.ip6_2, a.ip6_2)) return false;
        if (a.port1 != b.port1) return a.port1 < b.port1;
        if (a.port2 != b.port2) return a.port2 < b.port2;
    } else {
        if (a.ip1 != b.ip1) return a.ip1 < b.ip1;
        if (a.port1 != b.port1) return a.port1 < b.port1;
        if (a.ip2 != b.ip2) return a.ip2 < b.ip2;
        if (a.port2 != b.port2) return a.port2 < b.port2;
    }
    if (a.proto != b.proto) return a.proto < b.proto;
    return false;
}

FlowTracker::FlowTracker() {}
FlowTracker::~FlowTracker() {}

FlowTracker::FlowTracker(uint64_t max_flows)
    : max_flows_(max_flows) {}

void FlowTracker::addPacket(const ParsedPacket &pkt,
                               std::optional<Action> decision,
                               std::optional<size_t> rule_index,
                               std::optional<std::string> rule_id,
                               std::optional<std::string> match_reason) {
    if (pkt.ts_sec == 0 && pkt.ts_usec == 0) return;
    FlowKey key = FlowKey::make(pkt);
    auto existing = flows_.find(key);
    if (existing == flows_.end() && max_flows_ > 0 && flows_.size() >= max_flows_) {
        overflowed_ = true;
        return;
    }

    uint64_t ts_us = uint64_t(pkt.ts_sec) * 1000000ull + pkt.ts_usec;
    auto &st = flows_[key];
    st.packets += 1;
    st.bytes += pkt.raw.size();
    FlowKey::Direction dir = FlowKey::directionOf(key, pkt);
    if (dir == FlowKey::Direction::AtoB) {
        st.packets_ab += 1;
        st.bytes_ab += pkt.raw.size();
    } else {
        st.packets_ba += 1;
        st.bytes_ba += pkt.raw.size();
    }
    if (st.first_seen_ts == 0 || ts_us < st.first_seen_ts) st.first_seen_ts = ts_us;
    if (ts_us > st.last_seen_ts) st.last_seen_ts = ts_us;

    if (decision && !st.decision) {
        st.decision = decision;
        st.matched_rule_index = rule_index;
        st.matched_rule_id = rule_id;
        st.match_reason = match_reason;
    }

    // simple app type classification; set once per flow
    if (!st.app_type) {
        if (pkt.dst_port == 80 || pkt.src_port == 80) st.app_type = "http";
        else if (pkt.dst_port == 443 || pkt.src_port == 443) st.app_type = "tls";
        else if (pkt.dst_port == 53 || pkt.src_port == 53) st.app_type = "dns";
        else {
            // payload heuristics
            if (!pkt.l4_payload.empty()) {
                std::string p(reinterpret_cast<const char*>(pkt.l4_payload.data()), pkt.l4_payload.size());
                if (p.rfind("GET ",0) == 0 || p.rfind("POST ",0) == 0) st.app_type = "http";
                else if (p.size() > 5 && p[0] == '\x16' && p[1] == '\x03') st.app_type = "tls";
            }
        }
    }

    // extractor pipeline output stored in flow metadata
    if (pkt.l4_proto == L4Proto::TCP || pkt.l4_proto == L4Proto::UDP) {
        static const std::vector<std::unique_ptr<Extractor>> extractors = build_extractors();
        for (const auto &extractor : extractors) {
            extractor->on_packet(pkt, st.metadata);
        }
    }

    if (!st.sni) {
        auto it = st.metadata.values.find("tls.sni");
        if (it != st.metadata.values.end() && !it->second.empty()) {
            st.sni = it->second;
        }
    }
    if (!st.http_host) {
        auto it = st.metadata.values.find("http.host");
        if (it != st.metadata.values.end() && !it->second.empty()) {
            st.http_host = it->second;
        }
    }
}
