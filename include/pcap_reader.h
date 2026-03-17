#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <string>
#include <vector>
#include <cstdint>

// Low‑level PCAP reader for both classic ``pcap`` and simple ``pcapng`` files.
// When a pcapng file is opened we eagerly parse sections, IDBs and EPBs
// converting them into the same PcapPacket records returned by readPacket().
// The implementation is minimal; it ignores options and only handles the
// most common blocks.

struct PcapPacket {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint64_t ts_us;
    std::vector<uint8_t> data;
};

struct PcapWarningCounts {
    uint64_t corrupt_record_headers = 0;
    uint64_t invalid_record_lengths = 0;
    uint64_t truncated_record_data = 0;
};

class PcapReader {
public:
    PcapReader();
    ~PcapReader();

    // Open a file; returns true on success. If file is pcapng, returns false.
    bool open(const std::string &filename);

    // Read the next packet; returns false on EOF or error.
    bool readPacket(PcapPacket &pkt);

    // Error handling policy and status accessors.
    void setSkipCorruptRecords(bool enabled) { skip_corrupt_records_ = enabled; }
    bool skipCorruptRecords() const { return skip_corrupt_records_; }
    bool hasFatalError() const { return fatal_error_; }
    const std::string& lastError() const { return last_error_; }
    const PcapWarningCounts& warningCounts() const { return warnings_; }
    uint64_t warningCount() const;

    // Accessors for properties read from the global header.
    uint32_t snaplen() const { return snaplen_; }
    uint32_t network() const { return network_; } // link type

private:
    FILE *fp_;
    bool swap_bytes_;
    uint32_t snaplen_;
    uint32_t network_;
    bool timestamp_is_nanos_;
    bool fatal_error_;
    bool skip_corrupt_records_;
    std::string last_error_;
    PcapWarningCounts warnings_;

    // pcapng support
    bool is_ng_;
    struct InterfaceDesc { uint32_t linktype; uint32_t snaplen; };
    std::vector<InterfaceDesc> ifaces_;        // interfaces discovered in section
    std::vector<PcapPacket> ng_packets_;       // all packets parsed from EPBs
    size_t ng_index_;                          // current read position

    // helper for pcapng parsing
    bool parsePcapNg(FILE *f);
    void resetState();
    void setFatalError(const std::string &msg);
};

#endif // PCAP_READER_H
