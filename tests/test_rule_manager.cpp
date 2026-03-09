#include "rule_manager.h"
#include "packet_parser.h"
#include <catch2/catch_test_macros.hpp>
#include <fstream>

TEST_CASE("RuleManager: Load rules from JSON file", "[rule_manager]") {
    std::string fname = "tests/tmp_rules.json";
    std::ofstream out(fname);
    out << R"({
  "default_action": "deny",
  "rules": [
    {"type":"ip","action":"allow","direction":"src","cidr":"1.2.3.0/24"}
  ]
})";
    out.close();

    RuleManager rm;
    REQUIRE(rm.loadRules(fname));
}

TEST_CASE("RuleManager: Evaluate IP rules with CIDR matching", "[rule_manager]") {
    std::string fname = "tests/tmp_rules.json";
    std::ofstream out(fname);
    out << R"({
  "default_action": "deny",
  "rules": [
    {"type":"ip","action":"allow","direction":"src","cidr":"1.2.3.0/24"}
  ]
})";
    out.close();

    RuleManager rm;
    REQUIRE(rm.loadRules(fname));

    ParsedPacket pkt;
    pkt.src_ip = (1 << 24) | (2 << 16) | (3 << 8) | 5; // in range
    pkt.dst_ip = 0;
    pkt.src_port = 100;
    
    auto res = rm.evaluate(pkt);
    REQUIRE(res.has_value());
    REQUIRE(res->action == Action::Allow);
    REQUIRE(res->rule_index && *res->rule_index == 0);

    // Test IP outside CIDR
    pkt.src_ip = (9 << 24);
    res = rm.evaluate(pkt);
    REQUIRE(res.has_value());
    REQUIRE(res->action == Action::Deny);
}

TEST_CASE("RuleManager: IP rules with port restrictions", "[rule_manager]") {
    std::string fname = "tests/tmp_rules2.json";
    std::ofstream out(fname);
    out << R"({
  "default_action": "deny",
  "rules": [
    {"type":"ip","action":"allow","direction":"src","cidr":"1.2.3.0/24","port":100}
  ]
})";
    out.close();

    RuleManager rm;
    REQUIRE(rm.loadRules(fname));
    
    ParsedPacket pkt;
    pkt.src_ip = (1 << 24) | (2 << 16) | (3 << 8) | 10;
    pkt.src_port = 200;
    
    auto res = rm.evaluate(pkt);
    REQUIRE(res.has_value());
    REQUIRE(res->action == Action::Deny);
    
    pkt.src_port = 100;
    res = rm.evaluate(pkt);
    REQUIRE(res.has_value());
    REQUIRE(res->action == Action::Allow);
}

TEST_CASE("RuleManager: Domain normalization in HTTP Host header", "[rule_manager]") {
    std::string fname = "tests/tmp_rules3.json";
    std::ofstream out(fname);
    out << R"({
  "default_action": "deny",
  "rules": [
    {"type":"domain","action":"allow","pattern":"  EXAMPLE.COM.  "}
  ]
})";
    out.close();

    RuleManager rm;
    REQUIRE(rm.loadRules(fname));
    
    ParsedPacket pkt;
    pkt.l4_payload.assign((unsigned char*)"Host: example.com\r\n", 
                         (unsigned char*)"Host: example.com\r\n" + 18);
    
    auto res = rm.evaluate(pkt);
    REQUIRE(res.has_value());
    REQUIRE(res->action == Action::Allow);
}

TEST_CASE("RuleManager: Application-based rules (HTTP detection)", "[rule_manager]") {
    std::string fname = "tests/tmp_rules4.json";
    std::ofstream out(fname);
    out << R"({
  "default_action": "deny",
  "rules": [
    {"type":"app","action":"allow","app":"http"}
  ]
})";
    out.close();

    RuleManager rm;
    REQUIRE(rm.loadRules(fname));
    
    ParsedPacket pkt;
    pkt.src_port = 1234;
    pkt.dst_port = 80; // should trigger HTTP detection
    
    auto res = rm.evaluate(pkt);
    REQUIRE(res.has_value());
    REQUIRE(res->action == Action::Allow);
    
    pkt.dst_port = 53; // DNS port should not match HTTP rule
    res = rm.evaluate(pkt);
    REQUIRE(res.has_value());
    REQUIRE(res->action == Action::Deny);
}
