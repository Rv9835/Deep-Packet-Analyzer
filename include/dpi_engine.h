#ifndef DPI_ENGINE_H
#define DPI_ENGINE_H

#include <string>

// DPI engine coordinates reading a pcap, applying rules, and writing outputs.

struct EngineConfig {
    std::string pcap_path;
    std::string ruleset_path;
    std::string out_dir;
    uint64_t max_packets = 0; // 0 == unlimited
    uint64_t max_flows = 0;
    uint64_t timeout_secs = 0;
};

class DPIEngine {
public:
    DPIEngine();
    ~DPIEngine();

    // Run analysis using explicit parameters.
    bool run(const std::string &pcap_path,
             const std::string &ruleset_path,
             const std::string &out_dir);

    // Run analysis using configuration object.
    bool run(const EngineConfig &cfg);

    // load JSON configuration file into EngineConfig; returns false on error.
    static bool loadConfig(const std::string &json_path, EngineConfig &cfg);
};

#endif // DPI_ENGINE_H
