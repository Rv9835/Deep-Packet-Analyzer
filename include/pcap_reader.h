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
    std::vector<uint8_t> data;
};

class PcapReader {
public:
    PcapReader();
    ~PcapReader();

    // Open a file; returns true on success. If file is pcapng, returns false.
    bool open(const std::string &filename);

    // Read the next packet; returns false on EOF or error.
    bool readPacket(PcapPacket &pkt);

    // Accessors for properties read from the global header.
    uint32_t snaplen() const { return snaplen_; }
    uint32_t network() const { return network_; } // link type

private:
    FILE *fp_;
    bool swap_bytes_;
    uint32_t snaplen_;
    uint32_t network_;

    // pcapng support
    bool is_ng_;
    struct InterfaceDesc { uint32_t linktype; uint32_t snaplen; };
    std::vector<InterfaceDesc> ifaces_;        // interfaces discovered in section
    std::vector<PcapPacket> ng_packets_;       // all packets parsed from EPBs
    size_t ng_index_;                          // current read position

    // helper for pcapng parsing
    bool parsePcapNg(FILE *f);
};

#endif // PCAP_READER_H
