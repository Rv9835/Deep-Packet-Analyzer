#include "pcap_reader.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <vector>

namespace {
void writeLe16(std::ofstream &out, uint16_t v) {
    const char b[2] = {
        static_cast<char>(v & 0xff),
        static_cast<char>((v >> 8) & 0xff)
    };
    out.write(b, sizeof(b));
}

void writeLe32(std::ofstream &out, uint32_t v) {
    const char b[4] = {
        static_cast<char>(v & 0xff),
        static_cast<char>((v >> 8) & 0xff),
        static_cast<char>((v >> 16) & 0xff),
        static_cast<char>((v >> 24) & 0xff)
    };
    out.write(b, sizeof(b));
}

void writePcapGlobalHeader(std::ofstream &out, uint32_t magic, uint32_t linktype) {
    writeLe32(out, magic);
    writeLe16(out, 2);
    writeLe16(out, 4);
    writeLe32(out, 0);
    writeLe32(out, 0);
    writeLe32(out, 65535);
    writeLe32(out, linktype);
}

void writeRecord(std::ofstream &out,
                 uint32_t tsSec,
                 uint32_t tsSubsec,
                 uint32_t inclLen,
                 uint32_t origLen,
                 uint8_t fill = 0x00) {
    writeLe32(out, tsSec);
    writeLe32(out, tsSubsec);
    writeLe32(out, inclLen);
    writeLe32(out, origLen);
    std::vector<uint8_t> payload(inclLen, fill);
    if (!payload.empty()) {
        out.write(reinterpret_cast<const char *>(payload.data()), static_cast<std::streamsize>(payload.size()));
    }
}
}

TEST_CASE("PcapReader reads golden fixture and exposes canonical microsecond timestamps", "[pcap]") {
    PcapReader reader;
    REQUIRE(reader.open("tests/fixtures/golden_minimal_eth.pcap"));
    REQUIRE(reader.network() == 1);
    REQUIRE(reader.snaplen() == 65535);

    PcapPacket pkt;
    uint64_t count = 0;
    uint64_t firstTsUs = 0;
    uint64_t lastTsUs = 0;

    while (reader.readPacket(pkt)) {
        if (count == 0) {
            firstTsUs = pkt.ts_us;
        }
        lastTsUs = pkt.ts_us;
        REQUIRE(pkt.ts_us == static_cast<uint64_t>(pkt.ts_sec) * 1000000ULL + pkt.ts_usec);
        ++count;
    }

    REQUIRE_FALSE(reader.hasFatalError());
    REQUIRE(reader.warningCount() == 0);
    REQUIRE(count == 2);
    REQUIRE(firstTsUs == 1000010ULL);
    REQUIRE(lastTsUs == 2000020ULL);
}

TEST_CASE("PcapReader rejects malformed global header magic", "[pcap]") {
    auto filePath = std::filesystem::temp_directory_path() / "bad_magic_test.pcap";
    {
        std::ofstream out(filePath, std::ios::binary);
        writePcapGlobalHeader(out, 0x01020304, 1);
    }

    PcapReader reader;
    REQUIRE_FALSE(reader.open(filePath.string()));
    REQUIRE(reader.hasFatalError());
}

TEST_CASE("PcapReader rejects unsupported linktype", "[pcap]") {
    auto filePath = std::filesystem::temp_directory_path() / "bad_linktype_test.pcap";
    {
        std::ofstream out(filePath, std::ios::binary);
        writePcapGlobalHeader(out, 0xa1b2c3d4, 101);
    }

    PcapReader reader;
    REQUIRE_FALSE(reader.open(filePath.string()));
    REQUIRE(reader.hasFatalError());
}

TEST_CASE("PcapReader skip-corrupt policy produces deterministic warning counts", "[pcap]") {
    auto filePath = std::filesystem::temp_directory_path() / "corrupt_record_test.pcap";
    {
        std::ofstream out(filePath, std::ios::binary);
        writePcapGlobalHeader(out, 0xa1b2c3d4, 1);
        writeRecord(out, 1, 5, 4, 4, 0x11);
        writeRecord(out, 2, 6, 70000, 70000, 0x22);
    }

    PcapReader reader;
    REQUIRE(reader.open(filePath.string()));

    PcapPacket pkt;
    REQUIRE(reader.readPacket(pkt));
    REQUIRE_FALSE(reader.readPacket(pkt));
    REQUIRE_FALSE(reader.hasFatalError());
    REQUIRE(reader.warningCounts().invalid_record_lengths == 1);
    REQUIRE(reader.warningCount() == 1);

    PcapReader strictReader;
    strictReader.setSkipCorruptRecords(false);
    REQUIRE(strictReader.open(filePath.string()));
    REQUIRE(strictReader.readPacket(pkt));
    REQUIRE_FALSE(strictReader.readPacket(pkt));
    REQUIRE(strictReader.hasFatalError());
}
