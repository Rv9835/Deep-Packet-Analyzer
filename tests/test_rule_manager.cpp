#include "rule_manager.h"
#include "packet_parser.h"
#include <cassert>
#include <fstream>

int main() {
    // create a temporary ruleset file
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
    assert(rm.loadRules(fname));

    ParsedPacket pkt;
    pkt.src_ip = (1<<24)|(2<<16)|(3<<8)|5; // in range
    pkt.dst_ip = 0;
    pkt.src_port = 100;
    auto res = rm.evaluate(pkt);
    assert(res.has_value());
    assert(res->action == Action::Allow);
    assert(res->rule_index && *res->rule_index == 0);

    pkt.src_ip = (9<<24);
    res = rm.evaluate(pkt);
    assert(res.has_value());
    assert(res->action == Action::Deny);

    // now test port restriction
    std::string fname2 = "tests/tmp_rules2.json";
    std::ofstream out2(fname2);
    out2 << R"({
  "default_action": "deny",
  "rules": [
    {"type":"ip","action":"allow","direction":"src","cidr":"1.2.3.0/24","port":100}
  ]
})";
    out2.close();
    RuleManager rm2;
    assert(rm2.loadRules(fname2));
    pkt.src_ip = (1<<24)|(2<<16)|(3<<8)|10;
    pkt.src_port = 200;
    res = rm2.evaluate(pkt);
    assert(res.has_value() && res->action == Action::Deny);
    pkt.src_port = 100;
    res = rm2.evaluate(pkt);
    assert(res.has_value() && res->action == Action::Allow);

    // domain normalization
    std::string fname3 = "tests/tmp_rules3.json";
    std::ofstream out3(fname3);
    out3 << R"({
  "default_action": "deny",
  "rules": [
    {"type":"domain","action":"allow","pattern":"  EXAMPLE.COM.  "}
  ]
})";
    out3.close();
    RuleManager rm3;
    assert(rm3.loadRules(fname3));
    ParsedPacket dpkt;
    dpkt.l4_payload.assign((unsigned char*)"Host: example.com\r\n", (unsigned char*)"Host: example.com\r\n"+18);
    res = rm3.evaluate(dpkt);
    assert(res.has_value() && res->action == Action::Allow);

    // app rule matching
    std::string fname4 = "tests/tmp_rules4.json";
    std::ofstream out4(fname4);
    out4 << R"({
  "default_action": "deny",
  "rules": [
    {"type":"app","action":"allow","app":"http"}
  ]
})";
    out4.close();
    RuleManager rm4;
    assert(rm4.loadRules(fname4));
    pkt.src_port = 1234;
    pkt.dst_port = 80; // should trigger http detection
    res = rm4.evaluate(pkt);
    assert(res.has_value() && res->action == Action::Allow);
    pkt.dst_port = 53;
    res = rm4.evaluate(pkt);
    assert(res.has_value() && res->action == Action::Deny);

    return 0;
}
