#include "rule_manager.h"
#include "sni_extractor.h"
#include "http_extractor.h"
#include <fstream>
#include <sstream>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <cctype>
#include <cstdio>

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

static std::string normalizeDomain(std::string domain) {
    auto trim = [](std::string &s) {
        while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
        while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
    };
    trim(domain);
    std::transform(domain.begin(), domain.end(), domain.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    while (!domain.empty() && domain.back() == '.') domain.pop_back();
    return domain;
}

static AppType parseAppType(const std::string &app_raw) {
    std::string app = app_raw;
    std::transform(app.begin(), app.end(), app.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    if (app == "web" || app == "http") return AppType::WEB;
    if (app == "tls" || app == "https") return AppType::TLS;
    if (app == "dns") return AppType::DNS;
    return AppType::UNKNOWN;
}

static std::string appTypeToString(AppType app) {
    switch (app) {
        case AppType::WEB: return "web";
        case AppType::TLS: return "tls";
        case AppType::DNS: return "dns";
        default: return "unknown";
    }
}

static AppType inferAppType(const ParsedPacket &pkt) {
    if (pkt.dst_port == 80 || pkt.src_port == 80) return AppType::WEB;
    if (pkt.dst_port == 443 || pkt.src_port == 443) return AppType::TLS;
    if (pkt.dst_port == 53 || pkt.src_port == 53) return AppType::DNS;
    if (!pkt.l4_payload.empty()) {
        std::string payload(reinterpret_cast<const char*>(pkt.l4_payload.data()), pkt.l4_payload.size());
        if (payload.rfind("GET ", 0) == 0 || payload.rfind("POST ", 0) == 0 || payload.rfind("HEAD ", 0) == 0) {
            return AppType::WEB;
        }
        if (payload.size() > 5 && payload[0] == '\x16' && payload[1] == '\x03') {
            return AppType::TLS;
        }
    }
    return AppType::UNKNOWN;
}

struct MatchCandidate {
    size_t index = 0;
    Action action = Action::Allow;
    std::optional<std::string> rule_id;
    std::string reason;
    int precedence = -1;
    int specificity = -1;
};

static bool betterCandidate(const MatchCandidate &lhs, const MatchCandidate &rhs) {
    if (lhs.precedence != rhs.precedence) return lhs.precedence > rhs.precedence;
    if (lhs.specificity != rhs.specificity) return lhs.specificity > rhs.specificity;
    return lhs.index < rhs.index;
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
            r.id = rj.value("id", "");
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
                if (rj.contains("port")) {
                    r.port = rj["port"].get<uint16_t>();
                }
            } else if (type == "domain") {
                r.type = RuleType::Domain;
                r.domain = normalizeDomain(rj.value("pattern", ""));
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
                r.app = parseAppType(rj.value("app", ""));
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

std::optional<RuleManager::EvalResult> RuleManager::evaluate(const ParsedPacket &pkt) const {
    const uint32_t src = pkt.src_ip;
    const uint32_t dst = pkt.dst_ip;

    std::optional<std::string> normalized_sni;
    std::optional<std::string> normalized_host;
    if (!pkt.l4_payload.empty()) {
        SNIExtractor sni_extractor;
        normalized_sni = sni_extractor.extract(pkt.l4_payload.data(), pkt.l4_payload.size());
        HTTPExtractor http_extractor;
        normalized_host = http_extractor.extractHost(pkt.l4_payload.data(), pkt.l4_payload.size());
    }

    const AppType app_type = inferAppType(pkt);

    std::optional<MatchCandidate> best;
    for (size_t idx = 0; idx < rules_.size(); ++idx) {
        const Rule &r = rules_[idx];
        std::optional<MatchCandidate> candidate;
        switch (r.type) {
        case RuleType::IP:
            if ((r.match_src && ipMatches(src, pkt.src_port, r)) ||
                (r.match_dst && ipMatches(dst, pkt.dst_port, r))) {
                int prefix = 0;
                uint32_t mask = r.ip_mask;
                while (mask) { prefix += static_cast<int>(mask & 1u); mask >>= 1u; }
                candidate = MatchCandidate{idx, r.action, r.id.empty() ? std::nullopt : std::optional<std::string>(r.id),
                                           "ip_cidr", 2, prefix};
            }
            break;
        case RuleType::Domain:
            if (!r.domain.empty()) {
                const auto domainMatches = [&](const std::string &value) -> bool {
                    if (value.empty()) return false;
                    if (!r.domain_wildcard) return value == r.domain;
                    if (value == r.domain) return true;
                    if (value.size() <= r.domain.size()) return false;
                    return value.compare(value.size() - r.domain.size(), r.domain.size(), r.domain) == 0 &&
                           value[value.size() - r.domain.size() - 1] == '.';
                };

                bool matched = false;
                std::string reason;
                if (normalized_sni && domainMatches(*normalized_sni)) {
                    matched = true;
                    reason = r.domain_wildcard ? "domain_wildcard_sni" : "domain_exact_sni";
                } else if (normalized_host && domainMatches(*normalized_host)) {
                    matched = true;
                    reason = r.domain_wildcard ? "domain_wildcard_host" : "domain_exact_host";
                }
                if (matched) {
                    int specificity = static_cast<int>(r.domain.size()) + (r.domain_wildcard ? 0 : 1000);
                    candidate = MatchCandidate{idx, r.action, r.id.empty() ? std::nullopt : std::optional<std::string>(r.id),
                                               reason, 3, specificity};
                }
            }
            break;
        case RuleType::App: {
            if (r.app != AppType::UNKNOWN && app_type == r.app) {
                candidate = MatchCandidate{idx, r.action, r.id.empty() ? std::nullopt : std::optional<std::string>(r.id),
                                           "app_type_" + appTypeToString(app_type), 1, 0};
            }
            break;
        }
        }
        if (candidate && (!best || betterCandidate(*candidate, *best))) {
            best = candidate;
        }
    }

    if (best) {
        return EvalResult{best->action, best->index, best->rule_id, best->reason};
    }
    return EvalResult{default_action_, std::nullopt};
}
