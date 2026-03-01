#include "rule_manager.h"
#include <fstream>
#include <sstream>
#include <nlohmann/json.hpp>
#include <algorithm>

using json = nlohmann::json;

RuleManager::RuleManager() {}
RuleManager::~RuleManager() {}

static uint32_t ipStringToUint(const std::string &s) {
    uint8_t b1,b2,b3,b4;
    if (sscanf(s.c_str(), "%hhu.%hhu.%hhu.%hhu", &b1,&b2,&b3,&b4) == 4) {
        return (uint32_t(b1)<<24) | (uint32_t(b2)<<16) |
               (uint32_t(b3)<<8) | uint32_t(b4);
    }
    return 0;
}

bool RuleManager::loadRules(const std::string &path) {
    std::ifstream in(path);
    if (!in) return false;
    json j;
    try {
        in >> j;
    } catch (...) {
        return false;
    }

    rules_.clear();
    if (j.contains("default_action")) {
        std::string da = j["default_action"].get<std::string>();
        default_action_ = (da == "deny" ? Action::Deny : Action::Allow);
    }
    if (j.contains("rules") && j["rules"].is_array()) {
        for (auto &rj : j["rules"]) {
            Rule r;
            std::string type = rj.value("type", "");
            std::string action = rj.value("action", "allow");
            r.action = (action == "deny" ? Action::Deny : Action::Allow);

            if (type == "ip") {
                r.type = RuleType::IP;
                std::string dir = rj.value("direction", "both");
                r.match_src = (dir == "src" || dir == "both");
                r.match_dst = (dir == "dst" || dir == "both");
                std::string cidr = rj.value("cidr", "");
                auto slash = cidr.find('/');
                if (slash != std::string::npos) {
                    std::string ip = cidr.substr(0, slash);
                    int prefix = stoi(cidr.substr(slash+1));
                    r.ip_base = ipStringToUint(ip);
                    if (prefix == 0) r.ip_mask = 0;
                    else r.ip_mask = prefix == 32 ? 0xffffffffu : (~0u << (32-prefix));
                }
            } else if (type == "domain") {
                r.type = RuleType::Domain;
                r.domain = rj.value("pattern", "");
                // normalization: lowercase, trim whitespace, strip trailing dot
                auto trim = [](std::string &s) {
                    while (!s.empty() && isspace((unsigned char)s.front())) s.erase(s.begin());
                    while (!s.empty() && isspace((unsigned char)s.back())) s.pop_back();
                };
                trim(r.domain);
                std::transform(r.domain.begin(), r.domain.end(), r.domain.begin(), ::tolower);
                if (!r.domain.empty() && r.domain.back() == '.') r.domain.pop_back();
                if (!r.domain.empty() && r.domain[0] == '*') {
                    r.domain_wildcard = true;
                    if (r.domain.size() > 2 && r.domain[1] == '.')
                        r.domain = r.domain.substr(2);
                }
                if (rj.contains("port")) {
                    r.port = rj["port"].get<uint16_t>();
                }
            } else if (type == "app") {
                r.type = RuleType::App;
                r.app = rj.value("app", "");
            }
            rules_.push_back(r);
        }
    }
    return true;
}

static bool ipMatches(uint32_t flow_ip, uint16_t flow_port, const Rule &r) {
    if (r.ip_mask != 0) {
        if ((flow_ip & r.ip_mask) != (r.ip_base & r.ip_mask)) return false;
    }
    if (r.port.has_value()) {
        if (flow_port != *r.port) return false;
    }
    return true;
}

// very cheap application classifier; only based on well‑known ports and simple
// payload heuristics.  It is intentionally not stateful so it can run per packet.
static std::string detectApp(const ParsedPacket &pkt) {
    if (pkt.dst_port == 80 || pkt.src_port == 80) return "http";
    if (pkt.dst_port == 443 || pkt.src_port == 443) return "tls";
    if (pkt.dst_port == 53 || pkt.src_port == 53) return "dns";
    // look for HTTP method or TLS handshake in payload if ports are atypical
    if (!pkt.l4_payload.empty()) {
        std::string p(reinterpret_cast<const char*>(pkt.l4_payload.data()), pkt.l4_payload.size());
        if (p.rfind("GET ",0) == 0 || p.rfind("POST ",0) == 0) return "http";
        if (p.size() > 5 && p[0] == '\x16' && p[1] == '\x03') return "tls";
    }
    return "";
}

std::optional<RuleManager::EvalResult> RuleManager::evaluate(const ParsedPacket &pkt) const {
    uint32_t src = pkt.src_ip;
    uint32_t dst = pkt.dst_ip;
    for (size_t idx = 0; idx < rules_.size(); ++idx) {
        const Rule &r = rules_[idx];
        bool matched = false;
        switch (r.type) {
        case RuleType::IP:
            if ((r.match_src && ipMatches(src, pkt.src_port, r)) ||
                (r.match_dst && ipMatches(dst, pkt.dst_port, r))) {
                matched = true;
            }
            break;
        case RuleType::Domain:
            if (!r.domain.empty()) {
                std::string payload(pkt.l4_payload.begin(), pkt.l4_payload.end());
                std::transform(payload.begin(), payload.end(), payload.begin(), ::tolower);
                std::string dom = r.domain;
                std::transform(dom.begin(), dom.end(), dom.begin(), ::tolower);
                if (payload.find(dom) != std::string::npos) matched = true;
            }
            break;
        case RuleType::App: {
            if (!r.app.empty()) {
                std::string detected = detectApp(pkt);
                if (!detected.empty() && detected == r.app) matched = true;
            }
            break;
        }
        }
        if (matched) {
            return EvalResult{r.action, idx};
        }
    }
    return EvalResult{default_action_, std::nullopt};
}
