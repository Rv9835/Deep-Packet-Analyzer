#include "packet_parser.h"
#include <cstring>

PacketParser::PacketParser() {}
PacketParser::~PacketParser() {}

static uint16_t be16(const uint8_t *p) {
    return (uint16_t(p[0]) << 8) | uint16_t(p[1]);
}

static uint32_t be32(const uint8_t *p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

std::optional<ParsedPacket> PacketParser::parse(uint32_t ts_sec,
                                                uint32_t ts_usec,
                                                const std::vector<uint8_t> &data) {
    ParsedPacket pkt;
    pkt.ts_sec = ts_sec;
    pkt.ts_usec = ts_usec;
    pkt.raw = data;

    const size_t len = data.size();
    if (len < 14) // minimum ethernet
        return std::nullopt;

    const uint8_t *ptr = data.data();
    uint16_t ethertype = be16(ptr + 12);
    size_t offset = 14;

    // handle stacked VLAN tags
    while (ethertype == 0x8100 && offset + 4 <= len) {
        if (len < offset + 4) return std::nullopt;
        ethertype = be16(ptr + offset + 2);
        offset += 4;
    }

    if (ethertype == 0x0800) {
        // IPv4
        if (len < offset + 20) return std::nullopt;
        pkt.l3_proto = L3Proto::IPv4;
        const uint8_t *ip = ptr + offset;
        uint8_t ihl = (ip[0] & 0x0f) * 4;
        if (ihl < 20) return std::nullopt;
        uint16_t totlen = be16(ip + 2);
        if (totlen < ihl || offset + totlen > len) return std::nullopt;
        // optionally verify checksum
        unsigned sum = 0;
        for (int i = 0; i < ihl; i += 2) {
            sum += (ip[i] << 8) | ip[i+1];
        }
        while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
        if ((sum & 0xffff) != 0xffff) {
            // bad checksum; skip packet
            return std::nullopt;
        }
        pkt.src_ip = be32(ip + 12);
        pkt.dst_ip = be32(ip + 16);
        uint16_t frag = be16(ip + 6);
        if ((frag & 0x1fff) != 0 || (frag & 0x2000)) {
            pkt.fragmented = true;
        }
        uint8_t proto = ip[9];
        offset += ihl;
        if (proto == 6 && len >= offset + 20) {
            pkt.l4_proto = L4Proto::TCP;
            const uint8_t *tcp = ptr + offset;
            pkt.src_port = be16(tcp);
            pkt.dst_port = be16(tcp + 2);
            uint8_t data_offset = (tcp[12] >> 4) * 4;
            offset += data_offset;
            if (offset <= len)
                pkt.l4_payload.assign(ptr + offset, ptr + len);
        } else if (proto == 17 && len >= offset + 8) {
            pkt.l4_proto = L4Proto::UDP;
            const uint8_t *udp = ptr + offset;
            pkt.src_port = be16(udp);
            pkt.dst_port = be16(udp + 2);
            uint16_t udplen = be16(udp + 4);
            offset += 8;
            if (udplen >= 8 && offset <= len) {
                // udplen includes header
                size_t payload_len = udplen - 8;
                if (offset + payload_len <= len)
                    pkt.l4_payload.assign(ptr + offset, ptr + offset + payload_len);
                else
                    pkt.l4_payload.assign(ptr + offset, ptr + len);
            }
        }
    } else if (ethertype == 0x86DD) {
        // IPv6 minimal parsing
        if (len < offset + 40) return std::nullopt;
        pkt.l3_proto = L3Proto::Unknown; // treat as IPv6
        pkt.is_ipv6 = true;
        const uint8_t *ip6 = ptr + offset;
        memcpy(pkt.src_ip6.data(), ip6 + 8, 16);
        memcpy(pkt.dst_ip6.data(), ip6 + 24, 16);
        uint8_t nxt = ip6[6];
        offset += 40;
        if (nxt == 6 && len >= offset + 20) {
            pkt.l4_proto = L4Proto::TCP;
            const uint8_t *tcp = ptr + offset;
            pkt.src_port = be16(tcp);
            pkt.dst_port = be16(tcp + 2);
            uint8_t data_offset = (tcp[12] >> 4) * 4;
            offset += data_offset;
            if (offset <= len)
                pkt.l4_payload.assign(ptr + offset, ptr + len);
        } else if (nxt == 17 && len >= offset + 8) {
            pkt.l4_proto = L4Proto::UDP;
            const uint8_t *udp = ptr + offset;
            pkt.src_port = be16(udp);
            pkt.dst_port = be16(udp + 2);
            offset += 8;
            if (offset <= len)
                pkt.l4_payload.assign(ptr + offset, ptr + len);
        }
    }

    return pkt;
}
