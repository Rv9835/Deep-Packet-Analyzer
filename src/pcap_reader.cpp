#include "pcap_reader.h"
#include <cstdio>
#include <cstring>
#include <arpa/inet.h> // for ntohl

namespace {
constexpr uint32_t PCAP_MAGIC_USEC_BE = 0xa1b2c3d4;
constexpr uint32_t PCAP_MAGIC_USEC_LE = 0xd4c3b2a1;
constexpr uint32_t PCAP_MAGIC_NSEC_BE = 0xa1b23c4d;
constexpr uint32_t PCAP_MAGIC_NSEC_LE = 0x4d3cb2a1;
constexpr uint32_t LINKTYPE_ETHERNET = 1;
constexpr uint32_t MAX_REASONABLE_PACKET_SIZE = 16 * 1024 * 1024;
}

#pragma pack(push,1)
struct PcapGlobalHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PcapRecordHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};
#pragma pack(pop)

PcapReader::PcapReader()
    : fp_(nullptr), swap_bytes_(false), snaplen_(0), network_(0),
      timestamp_is_nanos_(false), fatal_error_(false),
      skip_corrupt_records_(true), is_ng_(false), ng_index_(0) {}

void PcapReader::resetState() {
    swap_bytes_ = false;
    snaplen_ = 0;
    network_ = 0;
    timestamp_is_nanos_ = false;
    fatal_error_ = false;
    last_error_.clear();
    warnings_ = {};

    is_ng_ = false;
    ifaces_.clear();
    ng_packets_.clear();
    ng_index_ = 0;
}

void PcapReader::setFatalError(const std::string &msg) {
    fatal_error_ = true;
    last_error_ = msg;
}

uint64_t PcapReader::warningCount() const {
    return warnings_.corrupt_record_headers +
           warnings_.invalid_record_lengths +
           warnings_.truncated_record_data;
}

// simple pcapng parsing: only Section Header (ignored), Interface Description,
// and Enhanced Packet blocks are handled.  The implementation reads through the
// file and creates a vector<PcapPacket> for later iteration.  We assume
// little‑endian pcapng (the common case) and don't support byte‑swapped files.

static bool read32(FILE *f, uint32_t &out) {
    if (fread(&out, 4, 1, f) != 1) return false;
    return true;
}

bool PcapReader::parsePcapNg(FILE *f) {
    // file pointer positioned at start (magic already consumed)
    while (true) {
        uint32_t block_type;
        if (!read32(f, block_type)) break;
        uint32_t block_len;
        if (!read32(f, block_len)) break;
        long block_start = ftell(f);
        switch (block_type) {
            case 0x0A0D0D0A: { // SHB
                // skip entire block
                fseek(f, block_len - 8, SEEK_CUR);
                break;
            }
            case 0x00000001: { // IDB
                uint16_t linktype;
                uint16_t reserved;
                uint32_t snaplen;
                fread(&linktype, 2, 1, f);
                fread(&reserved, 2, 1, f);
                fread(&snaplen, 4, 1, f);
                if (feof(f)) break;
                InterfaceDesc id{linktype, snaplen};
                ifaces_.push_back(id);
                // skip remainder of block (options etc)
                fseek(f, block_len - 16, SEEK_CUR);
                break;
            }
            case 0x00000006: { // Enhanced Packet Block
                uint32_t if_id, ts_high, ts_low, cap_len, orig_len;
                fread(&if_id, 4, 1, f);
                fread(&ts_high, 4, 1, f);
                fread(&ts_low, 4, 1, f);
                fread(&cap_len, 4, 1, f);
                fread(&orig_len, 4, 1, f);
                PcapPacket pkt;
                uint64_t ts = ((uint64_t)ts_high << 32) | ts_low;
                pkt.ts_sec = ts / 1000000;
                pkt.ts_usec = ts % 1000000;
                pkt.ts_us = ts;
                pkt.data.resize(cap_len);
                fread(pkt.data.data(), 1, cap_len, f);
                ng_packets_.push_back(std::move(pkt));
                // advance past padding to 32‑bit boundary
                uint32_t pad = (4 - (cap_len % 4)) % 4;
                if (pad) fseek(f, pad, SEEK_CUR);
                // skip remainder of block (options after packet)
                long used = ftell(f) - block_start;
                if ((uint32_t)used < block_len)
                    fseek(f, block_len - used, SEEK_CUR);
                break;
            }
            default:
                // skip unknown block
                fseek(f, block_len - 8, SEEK_CUR);
                break;
        }
        // read trailing block_len (repeat) and ignore
        uint32_t trailing_len;
        if (!read32(f, trailing_len)) break;
    }
    return true;
}

PcapReader::~PcapReader() {
    if (fp_) fclose(fp_);
}

bool PcapReader::open(const std::string &filename) {
    if (fp_) {
        fclose(fp_);
        fp_ = nullptr;
    }
    resetState();

    // attempt to detect file format by examining first 4 bytes
    FILE *f = fopen(filename.c_str(), "rb");
    if (!f) {
        setFatalError("failed to open file");
        return false;
    }
    uint32_t magic;
    if (fread(&magic, sizeof(magic), 1, f) != 1) {
        fclose(f);
        setFatalError("failed to read file magic");
        return false;
    }
    rewind(f);

    if (magic == 0x0A0D0D0A) {
        // pcapng file; parse eagerly and keep in memory
        is_ng_ = true;
        if (!parsePcapNg(f)) {
            fclose(f);
            setFatalError("failed to parse pcapng file");
            return false;
        }
        fclose(f);
        // set first interface values if available
        if (!ifaces_.empty()) {
            network_ = ifaces_[0].linktype;
            snaplen_ = ifaces_[0].snaplen;
        }
        ng_index_ = 0;
        return true;
    }

    // otherwise assume classic PCAP
    fp_ = f;
    PcapGlobalHeader gh;
    if (fread(&gh, sizeof(gh), 1, fp_) != 1) {
        fclose(fp_);
        fp_ = nullptr;
        setFatalError("failed to read pcap global header");
        return false;
    }

    // detect byte order
    if (gh.magic_number == PCAP_MAGIC_USEC_BE) {
        swap_bytes_ = false;
        timestamp_is_nanos_ = false;
    } else if (gh.magic_number == PCAP_MAGIC_USEC_LE) {
        swap_bytes_ = true;
        timestamp_is_nanos_ = false;
    } else if (gh.magic_number == PCAP_MAGIC_NSEC_BE) {
        swap_bytes_ = false;
        timestamp_is_nanos_ = true;
    } else if (gh.magic_number == PCAP_MAGIC_NSEC_LE) {
        swap_bytes_ = true;
        timestamp_is_nanos_ = true;
    } else {
        fclose(fp_);
        fp_ = nullptr;
        setFatalError("unsupported pcap magic number");
        return false;
    }

    const uint16_t version_major = swap_bytes_ ? __builtin_bswap16(gh.version_major) : gh.version_major;
    const uint16_t version_minor = swap_bytes_ ? __builtin_bswap16(gh.version_minor) : gh.version_minor;
    if (version_major != 2 || version_minor != 4) {
        fclose(fp_);
        fp_ = nullptr;
        setFatalError("unsupported pcap version (expected 2.4)");
        return false;
    }

    snaplen_ = swap_bytes_ ? __builtin_bswap32(gh.snaplen) : gh.snaplen;
    network_ = swap_bytes_ ? __builtin_bswap32(gh.network) : gh.network;

    if (network_ != LINKTYPE_ETHERNET) {
        fclose(fp_);
        fp_ = nullptr;
        setFatalError("unsupported linktype (only Ethernet is supported)");
        return false;
    }

    return true;
}

bool PcapReader::readPacket(PcapPacket &pkt) {
    if (is_ng_) {
        if (ng_index_ >= ng_packets_.size()) return false;
        pkt = ng_packets_[ng_index_++];
        return true;
    }

    if (!fp_) return false;
    while (true) {
        PcapRecordHeader rh{};
        size_t header_read = fread(&rh, 1, sizeof(rh), fp_);
        if (header_read == 0) {
            return false;
        }
        if (header_read != sizeof(rh)) {
            if (skip_corrupt_records_) {
                ++warnings_.corrupt_record_headers;
                return false;
            }
            setFatalError("truncated packet record header");
            return false;
        }

        if (swap_bytes_) {
            rh.ts_sec = __builtin_bswap32(rh.ts_sec);
            rh.ts_usec = __builtin_bswap32(rh.ts_usec);
            rh.incl_len = __builtin_bswap32(rh.incl_len);
            rh.orig_len = __builtin_bswap32(rh.orig_len);
        }

        bool invalid_length = (rh.incl_len > rh.orig_len) ||
                              (snaplen_ != 0 && rh.incl_len > snaplen_) ||
                              (rh.incl_len > MAX_REASONABLE_PACKET_SIZE);
        if (invalid_length) {
            if (!skip_corrupt_records_) {
                setFatalError("invalid packet record lengths");
                return false;
            }
            ++warnings_.invalid_record_lengths;
            if (fseek(fp_, static_cast<long>(rh.incl_len), SEEK_CUR) != 0) {
                ++warnings_.truncated_record_data;
                return false;
            }
            continue;
        }

        pkt.data.resize(rh.incl_len);
        if (rh.incl_len > 0 && fread(pkt.data.data(), 1, rh.incl_len, fp_) != rh.incl_len) {
            if (!skip_corrupt_records_) {
                setFatalError("truncated packet data");
                return false;
            }
            ++warnings_.truncated_record_data;
            return false;
        }

        pkt.ts_sec = rh.ts_sec;
        if (timestamp_is_nanos_) {
            pkt.ts_usec = rh.ts_usec / 1000;
        } else {
            pkt.ts_usec = rh.ts_usec;
        }
        pkt.ts_us = static_cast<uint64_t>(pkt.ts_sec) * 1000000ULL + pkt.ts_usec;
        return true;
    }
}
