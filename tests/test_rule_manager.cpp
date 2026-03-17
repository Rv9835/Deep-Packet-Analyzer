#include "rule_manager.h"
#include "packet_parser.h"
#include <catch2/catch_test_macros.hpp>
#include <fstream>
#include <vector>

namespace {
static ParsedPacket makeBasePacket() {
  ParsedPacket pkt;
  pkt.src_ip = (10u << 24) | (0u << 16) | (0u << 8) | 5u;
  pkt.dst_ip = (1u << 24) | (2u << 16) | (3u << 8) | 4u;
  pkt.src_port = 55555;
  pkt.dst_port = 443;
  pkt.l4_proto = L4Proto::TCP;
  return pkt;
}

static std::vector<unsigned char> makeHttpPayload(const std::string &host) {
  std::string req = "GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: test\r\n\r\n";
  return std::vector<unsigned char>(req.begin(), req.end());
}

static std::vector<unsigned char> makeTlsClientHelloSni(const std::string &host) {
  std::vector<unsigned char> tls = {
    0x16, 0x03, 0x03, 0x00, 0x47,
    0x01, 0x00, 0x00, 0x43,
    0x03, 0x03,
  };
  for (int i = 0; i < 32; ++i) tls.push_back(0x11);
  tls.push_back(0x00);
  tls.push_back(0x00); tls.push_back(0x02); tls.push_back(0x13); tls.push_back(0x01);
  tls.push_back(0x01); tls.push_back(0x00);
  tls.push_back(0x00); tls.push_back(0x18);
  tls.push_back(0x00); tls.push_back(0x00);
  tls.push_back(0x00); tls.push_back(0x14);
  tls.push_back(0x00); tls.push_back(0x12);
  tls.push_back(0x00);
  tls.push_back(0x00); tls.push_back(0x0f);
  tls.insert(tls.end(), host.begin(), host.end());
  return tls;
}
}

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

    ParsedPacket pkt = makeBasePacket();
    pkt.src_ip = (1u << 24) | (2u << 16) | (3u << 8) | 5u; // in range
    pkt.src_port = 100;
    
    auto res = rm.evaluate(pkt);
    REQUIRE(res.has_value());
    REQUIRE(res->action == Action::Allow);
    REQUIRE(res->rule_index && *res->rule_index == 0);

    // Test IP outside CIDR
    pkt.src_ip = (9u << 24);
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
    
    ParsedPacket pkt = makeBasePacket();
    pkt.src_ip = (1u << 24) | (2u << 16) | (3u << 8) | 10u;
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
    
    ParsedPacket pkt = makeBasePacket();
    auto payload = makeHttpPayload("example.com");
    pkt.l4_payload = payload;
    
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
    
    ParsedPacket pkt = makeBasePacket();
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

TEST_CASE("RuleManager: Domain rule precedence over overlapping IP rule", "[rule_manager]") {
    std::string fname = "tests/tmp_rules_prec.json";
    std::ofstream out(fname);
    out << R"({
  "default_action": "allow",
  "rules": [
    {"id":"ip-deny","type":"ip","action":"deny","direction":"src","cidr":"10.0.0.0/8"},
    {"id":"domain-allow","type":"domain","action":"allow","pattern":"example.com"}
  ]
})";
    out.close();

    RuleManager rm;
    REQUIRE(rm.loadRules(fname));

    ParsedPacket pkt = makeBasePacket();
    pkt.src_ip = (10u << 24) | 1u;
    pkt.l4_payload = makeHttpPayload("example.com");

    auto res = rm.evaluate(pkt);
    REQUIRE(res.has_value());
    REQUIRE(res->action == Action::Allow);
    REQUIRE(res->rule_id.has_value());
    REQUIRE(*res->rule_id == "domain-allow");
    REQUIRE(res->reason.has_value());
    REQUIRE(res->reason->find("domain_") == 0);
}

TEST_CASE("RuleManager: Exact domain wins over wildcard in tie-break", "[rule_manager]") {
    std::string fname = "tests/tmp_rules_domain_tie.json";
    std::ofstream out(fname);
    out << R"({
  "default_action": "deny",
  "rules": [
    {"id":"wildcard-deny","type":"domain","action":"deny","pattern":"*.example.com"},
    {"id":"exact-allow","type":"domain","action":"allow","pattern":"api.example.com"}
  ]
})";
    out.close();

    RuleManager rm;
    REQUIRE(rm.loadRules(fname));

    ParsedPacket pkt = makeBasePacket();
    pkt.l4_payload = makeTlsClientHelloSni("api.example.com");

    auto res = rm.evaluate(pkt);
    REQUIRE(res.has_value());
    REQUIRE(res->action == Action::Allow);
    REQUIRE(res->rule_id.has_value());
    REQUIRE(*res->rule_id == "exact-allow");
    REQUIRE(res->reason.has_value());
    REQUIRE(res->reason->find("domain_exact") == 0);
}
