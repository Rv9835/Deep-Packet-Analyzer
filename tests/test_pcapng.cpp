#include "pcap_reader.h"
#include <cassert>
#include <fstream>

// create a trivial pcapng file containing a single Enhanced Packet Block
static void write_dummy_pcapng(const std::string &path) {
    std::ofstream out(path, std::ios::binary);
    // write Section Header Block
    uint32_t type = 0x0A0D0D0A;
    uint32_t length = 28;
    uint32_t magic = 0x1A2B3C4D;
    uint16_t major = 1, minor = 0;
    int32_t zone = 0;
    uint32_t sig = 0;
    uint64_t snap = 65535;
    out.write(reinterpret_cast<char*>(&type),4);
    out.write(reinterpret_cast<char*>(&length),4);
    out.write(reinterpret_cast<char*>(&magic),4);
    out.write(reinterpret_cast<char*>(&major),2);
    out.write(reinterpret_cast<char*>(&minor),2);
    out.write(reinterpret_cast<char*>(&zone),4);
    out.write(reinterpret_cast<char*>(&sig),4);
    out.write(reinterpret_cast<char*>(&snap),8);
    out.write(reinterpret_cast<char*>(&length),4);
    // Interface Description Block
    type = 1;
    length = 20;
    uint16_t linktype = 1;
    uint16_t reserved = 0;
    uint32_t snaplen = 65535;
    out.write(reinterpret_cast<char*>(&type),4);
    out.write(reinterpret_cast<char*>(&length),4);
    out.write(reinterpret_cast<char*>(&linktype),2);
    out.write(reinterpret_cast<char*>(&reserved),2);
    out.write(reinterpret_cast<char*>(&snaplen),4);
    out.write(reinterpret_cast<char*>(&length),4);
    // Enhanced Packet Block
    type = 6;
    // we'll compute length later
    std::streampos lenpos = out.tellp();
    out.write(reinterpret_cast<char*>(&type),4);
    out.write(reinterpret_cast<char*>(&length),4); // placeholder
    uint32_t ifid = 0;
    uint32_t ts_hi = 0;
    uint32_t ts_lo = 0;
    uint32_t caplen = 4;
    uint32_t origlen = 4;
    uint8_t data[4] = {1,2,3,4};
    out.write(reinterpret_cast<char*>(&ifid),4);
    out.write(reinterpret_cast<char*>(&ts_hi),4);
    out.write(reinterpret_cast<char*>(&ts_lo),4);
    out.write(reinterpret_cast<char*>(&caplen),4);
    out.write(reinterpret_cast<char*>(&origlen),4);
    out.write(reinterpret_cast<char*>(data),4);
    // pad to 32-bit
    uint32_t pad = 0;
    out.write(reinterpret_cast<char*>(&pad),4);
    // compute block length (count from type to trailing length inclusive)
    std::streampos afterdata = out.tellp();
    uint32_t totlen = uint32_t(afterdata - lenpos + 4); // plus trailing length itself
    out.seekp(lenpos + 4);
    out.write(reinterpret_cast<char*>(&totlen),4);
    out.seekp(afterdata);
    out.write(reinterpret_cast<char*>(&totlen),4);
}

int main() {
    std::string path = "tests/tmp.pcapng";
    write_dummy_pcapng(path);
    PcapReader reader;
    assert(reader.open(path));
    PcapPacket pkt;
    bool ok = reader.readPacket(pkt);
    assert(ok);
    assert(pkt.data.size() == 4);
    assert(!reader.readPacket(pkt));
    return 0;
}
