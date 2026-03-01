#include "dpi_engine.h"
#include <cassert>
#include <fstream>

// write a trivial pcap file with a single or two dummy packets; if frag=true include one fragmented IPv4 packet
static void write_dummy_pcap(const std::string &path, bool frag=false,
                                 uint16_t sport=0, uint16_t dport=0) {
    std::ofstream out(path, std::ios::binary);
    // global header
    uint32_t magic = 0xa1b2c3d4;
    uint16_t major = 2, minor = 4;
    int32_t tz = 0;
    uint32_t sig = 0;
    uint32_t snaplen = 65535;
    uint32_t linktype = 1; // ethernet
    out.write(reinterpret_cast<char*>(&magic), 4);
    out.write(reinterpret_cast<char*>(&major), 2);
    out.write(reinterpret_cast<char*>(&minor), 2);
    out.write(reinterpret_cast<char*>(&tz), 4);
    out.write(reinterpret_cast<char*>(&sig), 4);
    out.write(reinterpret_cast<char*>(&snaplen), 4);
    out.write(reinterpret_cast<char*>(&linktype), 4);
    
    auto write_packet = [&](bool setfrag, uint16_t sport, uint16_t dport) {
        uint32_t ts_sec = 0;
        uint32_t ts_usec = 0;
        // simple minimal ethernet+IPv4 + TCP header
        uint8_t pkt[54] = {};
        // eth type
        pkt[12] = 0x08; pkt[13] = 0x00;
        // ipv4 version/ihl
        pkt[14] = 0x45;
        // total length 40 (20 ip + 20 tcp)
        pkt[16] = 0x00; pkt[17] = 0x28;
        if (setfrag) {
            pkt[20] = 0x20; // MF flag
        }
        // TCP source/dest ports at offset 34
        if (sport) {
            pkt[34] = sport >> 8;
            pkt[35] = sport & 0xff;
        }
        if (dport) {
            pkt[36] = dport >> 8;
            pkt[37] = dport & 0xff;
        }
        uint32_t incl_len = sizeof(pkt);
        uint32_t orig_len = incl_len;
        out.write(reinterpret_cast<char*>(&ts_sec),4);
        out.write(reinterpret_cast<char*>(&ts_usec),4);
        out.write(reinterpret_cast<char*>(&incl_len),4);
        out.write(reinterpret_cast<char*>(&orig_len),4);
        out.write(reinterpret_cast<char*>(pkt), incl_len);
    };
    write_packet(false, sport, dport);
    if (frag) write_packet(true, sport, dport);
}

int main() {
    std::string pcap = "tests/tmp.pcap";
    write_dummy_pcap(pcap, true, 1234, 80); // include one frag and http flow
    std::string rules = "tests/tmp_rules.json";
    // same rules file created by other test
    std::string outdir = "tests/out";

    DPIEngine engine;
    bool ok = engine.run(pcap, rules, outdir);
    assert(ok);
    // check outputs created
    std::ifstream r(outdir + "/report.json");
    std::ifstream f(outdir + "/filtered.pcap");
    std::ifstream m(outdir + "/manifest.json");
    assert(r && f && m);
    {
        nlohmann::json rep;
        r >> rep;
        assert(rep.contains("skipped"));
        auto sk = rep["skipped"];
        assert(sk["fragments"].get<uint64_t>() == 1);
        // app type http should be counted
        assert(rep.contains("app_types"));
        bool saw_http = false;
        for (auto &a : rep["app_types"]) {
            if (a["app"] == "http") saw_http = true;
        }
        assert(saw_http);
    }

    // now test config JSON limits: set max_packets = 0 (should exit immediately)
    std::string cfgpath = "tests/tmp_config.json";
    {
        std::ofstream cfg(cfgpath);
        cfg << "{\n";
        cfg << "  \"pcap\": \"" << pcap << "\",\n";
        cfg << "  \"ruleset\": \"" << rules << "\",\n";
        cfg << "  \"out_dir\": \"tests/out2\",\n";
        cfg << "  \"max_packets\": 0\n";
        cfg << "}";
    }
    EngineConfig cfg;
    assert(DPIEngine::loadConfig(cfgpath, cfg));
    assert(cfg.max_packets == 0);
    ok = engine.run(cfg);
    assert(ok);
    return 0;
}
