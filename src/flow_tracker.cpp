#include "flow_tracker.h"
#include "sni_extractor.h"
#include "http_extractor.h"
#include <cstring>

// helper to compare tuple lexicographically
static bool less_tuple(uint32_t a1, uint16_t p1, uint32_t a2, uint16_t p2,
                       uint32_t b1, uint16_t q1, uint32_t b2, uint16_t q2) {
    if (a1 != b1) return a1 < b1;
    if (p1 != q1) return p1 < q1;
    if (a2 != b2) return a2 < b2;
    if (p2 != q2) return p2 < q2;
    return false;
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
        k.ip1 = pkt.src_ip;
        k.ip2 = pkt.dst_ip;
        k.port1 = pkt.src_port;
        k.port2 = pkt.dst_port;
    }
    return k;
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

void FlowTracker::addPacket(const ParsedPacket &pkt,
                               std::optional<Action> decision,
                               std::optional<size_t> rule_index) {
    if (pkt.ts_sec == 0 && pkt.ts_usec == 0) return;
    FlowKey key = FlowKey::make(pkt);
    uint64_t ts_us = uint64_t(pkt.ts_sec) * 1000000ull + pkt.ts_usec;
    auto &st = flows_[key];
    st.packets += 1;
    st.bytes += pkt.raw.size();
    if (st.first_seen_ts == 0 || ts_us < st.first_seen_ts) st.first_seen_ts = ts_us;
    if (ts_us > st.last_seen_ts) st.last_seen_ts = ts_us;

    if (decision && !st.decision) {
        st.decision = decision;
        st.matched_rule_index = rule_index;
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

    // attempt to extract metadata if not already present
    if (!st.sni || !st.http_host) {
        // only inspect payloads for TCP/UDP
        if (pkt.l4_proto == L4Proto::TCP || pkt.l4_proto == L4Proto::UDP) {
            // SNI
            if (!st.sni) {
                SNIExtractor ext;
                auto s = ext.extract(pkt.l4_payload.data(), pkt.l4_payload.size());
                if (s) st.sni = *s;
            }
            // HTTP Host header
            if (!st.http_host) {
                HTTPExtractor httpext;
                auto h = httpext.extractHost(pkt.l4_payload.data(), pkt.l4_payload.size());
                if (h) st.http_host = *h;
            }
        }
    }
}
