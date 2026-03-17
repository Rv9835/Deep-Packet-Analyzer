#ifndef RULE_MANAGER_H
#define RULE_MANAGER_H

#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include "packet_parser.h"

// Simple rule types for MVP

enum class Action { Allow, Deny };
enum class RuleType { IP, Domain, App };
enum class AppType { WEB, TLS, DNS, UNKNOWN };

struct Rule {
    std::string id;
    RuleType type;
    Action action;
    // IP rule
    bool match_src = false;
    bool match_dst = false;
    uint32_t ip_base = 0;
    uint32_t ip_mask = 0; // network mask in host order
    std::optional<uint16_t> port;      // optional port match
    // Domain rule
    std::string domain;
    bool domain_wildcard = false;
    // App rule
    AppType app = AppType::UNKNOWN;
};

class RuleManager {
public:
    RuleManager();
    ~RuleManager();

    // load JSON ruleset from file; returns false on error
    bool loadRules(const std::string &path);

    // result of evaluation, including matched rule index (in rules_ vector)
    struct EvalResult {
        Action action;
        std::optional<size_t> rule_index;
        std::optional<std::string> rule_id;
        std::optional<std::string> reason;
    };

    std::optional<EvalResult> evaluate(const ParsedPacket &pkt) const;

private:
    std::vector<Rule> rules_;
    Action default_action_ = Action::Allow;
};

#endif // RULE_MANAGER_H
