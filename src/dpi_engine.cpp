#include "dpi_engine.h"
#include "pcap_reader.h"
#include "packet_parser.h"
#include "flow_tracker.h"
#include "rule_manager.h"
#include "utils.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <algorithm>
#include <chrono>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

DPIEngine::DPIEngine() {}
DPIEngine::~DPIEngine() {}

bool DPIEngine::run(const std::string &pcap_path,
                    const std::string &ruleset_path,
                    const std::string &out_dir) {
    EngineConfig cfg;
    cfg.pcap_path = pcap_path;
    cfg.ruleset_path = ruleset_path;
    cfg.out_dir = out_dir;
    return run(cfg);
}

bool DPIEngine::run(const EngineConfig &cfg) {
    PcapReader reader;
    if (!reader.open(cfg.pcap_path)) {
        std::cerr << "Failed to open pcap: " << cfg.pcap_path << "\n";
        return false;
    }

    RuleManager rules;
    if (!rules.loadRules(cfg.ruleset_path)) {
        std::cerr << "Failed to load rules: " << cfg.ruleset_path << "\n";
        return false;
    }

    std::filesystem::create_directories(cfg.out_dir);
    std::ofstream logf(cfg.out_dir + "/engine.log");

    // read all packets and parse lazily
    struct Item { PcapPacket pkt; std::optional<ParsedPacket> parsed; };
    std::vector<Item> all;
    PcapPacket pkt;
    while (reader.readPacket(pkt)) {
        if (cfg.max_packets && all.size() >= cfg.max_packets) break;
        Item it;
        it.pkt = pkt;
        it.parsed = PacketParser().parse(pkt.ts_sec, pkt.ts_usec, pkt.data);
        all.push_back(std::move(it));
    }

    // counters for stats (shared via mutex)
    uint64_t skipped_fragments = 0;
    uint64_t skipped_parse_errors = 0;

    unsigned nthreads = std::thread::hardware_concurrency();
    if (nthreads == 0) nthreads = 1;
    std::vector<FlowTracker> trackers(nthreads);
    std::vector<std::vector<size_t>> allowed_indices(nthreads);
    std::vector<std::thread> threads;
    std::mutex merge_mutex;

    for (unsigned t = 0; t < nthreads; ++t) {
        threads.emplace_back([&, t]() {
            for (size_t i = t; i < all.size(); i += nthreads) {
                auto &item = all[i];
                if (!item.parsed) {
                    std::lock_guard<std::mutex> lock(merge_mutex);
                    ++skipped_parse_errors;
                    continue;
                }
                if (item.parsed->fragmented) {
                    std::lock_guard<std::mutex> lock(merge_mutex);
                    ++skipped_fragments;
                    continue;
                }
                auto eval = rules.evaluate(*item.parsed);
                bool allow = true;
                std::optional<size_t> rule_idx;
                std::optional<std::string> rule_id;
                std::optional<std::string> match_reason;
                if (eval) {
                    allow = (eval->action == Action::Allow);
                    rule_idx = eval->rule_index;
                    rule_id = eval->rule_id;
                    match_reason = eval->reason;
                }
                trackers[t].addPacket(*item.parsed,
                                      eval?std::optional<Action>(eval->action):std::nullopt,
                                      rule_idx,
                                      rule_id,
                                      match_reason);
                if (allow) {
                    allowed_indices[t].push_back(i);
                }
            }
        });
    }
    for (auto &th : threads) th.join();

    // merge trackers
    FlowTracker merged;
    for (auto &tr : trackers) {
        mergeFlows(merged.mutableFlows(), tr.flows());
    }
    FlowTracker &tracker = merged;

    if (cfg.max_flows > 0 && tracker.flows().size() > cfg.max_flows) {
        std::cerr << "Max flow limit exceeded: " << tracker.flows().size()
                  << " > " << cfg.max_flows << "\n";
        return false;
    }

    // open filtered pcap for writing; copy global header
    std::ifstream in2(cfg.pcap_path, std::ios::binary);
    std::ofstream out_filtered(cfg.out_dir + "/filtered.pcap", std::ios::binary);
    if (!in2 || !out_filtered) return false;
    char gh2[24];
    in2.read(gh2, sizeof(gh2));
    out_filtered.write(gh2, sizeof(gh2));

    // collect all allowed indices and sort
    std::vector<size_t> allowed;
    for (auto &v : allowed_indices) {
        allowed.insert(allowed.end(), v.begin(), v.end());
    }
    std::sort(allowed.begin(), allowed.end());
    for (size_t idx : allowed) {
        PcapPacket &p = all[idx].pkt;
        uint32_t ts_sec = p.ts_sec;
        uint32_t ts_usec = p.ts_usec;
        uint32_t len = p.data.size();
        uint32_t orig = len;
        out_filtered.write(reinterpret_cast<char*>(&ts_sec), 4);
        out_filtered.write(reinterpret_cast<char*>(&ts_usec), 4);
        out_filtered.write(reinterpret_cast<char*>(&len), 4);
        out_filtered.write(reinterpret_cast<char*>(&orig), 4);
        out_filtered.write(reinterpret_cast<const char*>(p.data.data()), len);
    }

    // produce report.json
    json report;
    report["flows"] = json::array();
    report["skipped"] = {
        {"fragments", skipped_fragments},
        {"parse_errors", skipped_parse_errors}
    };

    std::map<std::string,int> domain_counts;
    std::map<std::string,int> app_counts;
    for (auto const &kv : tracker.flows()) {
        const FlowKey &k = kv.first;
        const FlowStats &s = kv.second;
        if (s.sni) domain_counts[*s.sni]++;
        if (s.http_host) domain_counts[*s.http_host]++;
        if (s.app_type) app_counts[*s.app_type]++;
        json f;
        if (k.is_ipv6) {
            // represent IPv6 as hex string
            std::ostringstream a1,a2;
            for (auto b: k.ip6_1) a1 << std::hex << (int)b;
            for (auto b: k.ip6_2) a2 << std::hex << (int)b;
            f["src_ip6"] = a1.str();
            f["dst_ip6"] = a2.str();
        } else {
            f["src_ip"] = k.ip1;
            f["dst_ip"] = k.ip2;
        }
        f["src_port"] = k.port1;
        f["dst_port"] = k.port2;
        f["proto"] = (k.proto == L4Proto::TCP ? "tcp" : "udp");
        f["packets"] = s.packets;
        f["bytes"] = s.bytes;
        f["first_seen_us"] = s.first_seen_ts;
        f["last_seen_us"] = s.last_seen_ts;
        if (s.sni) f["sni"] = *s.sni;
        if (s.http_host) f["http_host"] = *s.http_host;
        if (s.decision) f["decision"] = (*s.decision == Action::Allow ? "allow" : "deny");
        if (s.matched_rule_index) f["matched_rule_index"] = *s.matched_rule_index;
        if (s.matched_rule_id) f["matched_rule_id"] = *s.matched_rule_id;
        if (s.match_reason) f["match_reason"] = *s.match_reason;
        report["flows"].push_back(f);
    }
    // add sorted domain/app lists
    report["domains"] = json::array();
    for (auto &p : domain_counts) report["domains"].push_back({{"domain", p.first}, {"count", p.second}});
    std::sort(report["domains"].begin(), report["domains"].end(), [](const json &a, const json &b){
        return a["domain"].get<std::string>() < b["domain"].get<std::string>();
    });
    report["app_types"] = json::array();
    for (auto &p : app_counts) report["app_types"].push_back({{"app", p.first}, {"count", p.second}});
    std::sort(report["app_types"].begin(), report["app_types"].end(), [](const json &a, const json &b){
        return a["app"].get<std::string>() < b["app"].get<std::string>();
    });

    std::ofstream report_out(cfg.out_dir + "/report.json");
    report_out << report.dump(2) << "\n";

    // manifest with hashes
    json manifest;
    manifest["engine_version"] = "0.1.0";
    manifest["ruleset_path"] = cfg.ruleset_path;
    manifest["pcap_path"] = cfg.pcap_path;
    manifest["report_sha256"] = sha256_file(cfg.out_dir + "/report.json");
    manifest["filtered_pcap_sha256"] = sha256_file(cfg.out_dir + "/filtered.pcap");
    std::ofstream man_out(cfg.out_dir + "/manifest.json");
    man_out << manifest.dump(2) << "\n";

    return true;
}

bool DPIEngine::loadConfig(const std::string &json_path, EngineConfig &cfg) {
    std::ifstream in(json_path);
    if (!in) return false;
    json j;
    try { in >> j; } catch (...) { return false; }
    if (!j.contains("pcap") || !j.contains("ruleset") || !j.contains("out_dir"))
        return false;
    cfg.pcap_path = j["pcap"].get<std::string>();
    cfg.ruleset_path = j["ruleset"].get<std::string>();
    cfg.out_dir = j["out_dir"].get<std::string>();
    if (j.contains("max_packets")) cfg.max_packets = j["max_packets"].get<uint64_t>();
    if (j.contains("max_flows")) cfg.max_flows = j["max_flows"].get<uint64_t>();
    if (j.contains("timeout_secs")) cfg.timeout_secs = j["timeout_secs"].get<uint64_t>();
    return true;
}
