#include "dpi_engine.h"
#include <filesystem>
#include <iostream>
#include <fstream>
#include <cassert>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main() {
    namespace fs = std::filesystem;
    fs::path dir = "tests/fixtures";
    if (!fs::exists(dir)) return 0;
    for (auto &entry : fs::directory_iterator(dir)) {
        if (entry.path().extension() == ".pcap") {
            std::string base = entry.path().stem().string();
            std::string pcap = entry.path().string();
            std::string rules = (dir / (base + ".rules.json")).string();
            std::string expected_report = (dir / (base + ".expected_report.json")).string();
            std::string expected_hash = (dir / (base + ".expected_filtered_hash.txt")).string();
            if (!fs::exists(rules) || !fs::exists(expected_report) || !fs::exists(expected_hash)) continue;
            std::string outdir = "tests/out_" + base;
            DPIEngine engine;
            bool ok = engine.run(pcap, rules, outdir);
            assert(ok);
            // compare report
            std::ifstream r1(outdir + "/report.json");
            std::ifstream r2(expected_report);
            json j1, j2;
            r1 >> j1;
            r2 >> j2;
            assert(j1 == j2);
            // compare filtered hash
            std::ifstream hfile(expected_hash);
            std::string expected;
            std::getline(hfile, expected);
            // read produced manifest
            std::ifstream m(outdir + "/manifest.json");
            json manifest;
            m >> manifest;
            assert(manifest["filtered_pcap_sha256"].get<std::string>() == expected);
        }
    }
    return 0;
}
