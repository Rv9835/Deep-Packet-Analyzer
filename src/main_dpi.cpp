#include "dpi_engine.h"
#include <iostream>

void usage(const char *prog) {
    std::cerr << "Usage: " << prog << " --pcap <file> --rules <rules.json> --out-dir <dir>\n";
}

int main(int argc, char **argv) {
    std::string pcap, rules, outdir, config_file;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--pcap" && i+1 < argc) {
            pcap = argv[++i];
        } else if (arg == "--rules" && i+1 < argc) {
            rules = argv[++i];
        } else if (arg == "--out-dir" && i+1 < argc) {
            outdir = argv[++i];
        } else if (arg == "--config" && i+1 < argc) {
            config_file = argv[++i];
        } else {
            usage(argv[0]);
            return 1;
        }
    }
    DPIEngine engine;
    bool ok = false;
    if (!config_file.empty()) {
        EngineConfig cfg;
        if (!DPIEngine::loadConfig(config_file, cfg)) {
            std::cerr << "Failed to load config " << config_file << "\n";
            return 1;
        }
        ok = engine.run(cfg);
    } else {
        if (pcap.empty() || rules.empty() || outdir.empty()) {
            usage(argv[0]);
            return 1;
        }
        ok = engine.run(pcap, rules, outdir);
    }
    return ok ? 0 : 1;
}
