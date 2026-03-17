#include "packet_parser.h"
#include <cstring>

PacketParser::PacketParser(const PacketParserOptions &options)
    : options_(options), last_error_(ParseError::None) {}
PacketParser::~PacketParser() {}

static uint16_t be16(const uint8_t *p) {
    return (uint16_t(p[0]) << 8) | uint16_t(p[1]);
}

static uint32_t be32(const uint8_t *p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

ParseResult PacketParser::parse(const RawPacket &raw_packet) {
    ParseResult result;
    last_error_ = ParseError::None;

    ParsedPacket pkt;
    pkt.ts_us = raw_packet.timestamp_us;
    pkt.ts_sec = static_cast<uint32_t>(raw_packet.timestamp_us / 1000000ULL);
    pkt.ts_usec = static_cast<uint32_t>(raw_packet.timestamp_us % 1000000ULL);
    pkt.raw = raw_packet.bytes;

    const size_t len = pkt.raw.size();
    if (len < 14) {
        last_error_ = ParseError::PacketTooShortForEthernet;
        result.error = last_error_;
        return result;
    }

    const uint8_t *ptr = pkt.raw.data();
    uint16_t ethertype = be16(ptr + 12);
    size_t offset = 14;

    if (options_.vlan_enabled) {
        while (ethertype == 0x8100 || ethertype == 0x88A8) {
            if (offset + 4 > len) {
                last_error_ = ParseError::VlanHeaderTruncated;
                result.error = last_error_;
                return result;
            }
            ethertype = be16(ptr + offset + 2);
            offset += 4;
        }
    }

    if (ethertype == 0x0800) {
        if (len < offset + 20) {
            last_error_ = ParseError::IPv4HeaderTooShort;
            result.error = last_error_;
            return result;
        }

        pkt.l3_proto = L3Proto::IPv4;
        const uint8_t *ip = ptr + offset;
        const uint8_t version = (ip[0] >> 4);
        if (version != 4) {
            last_error_ = ParseError::IPv4HeaderTooShort;
            result.error = last_error_;
            return result;
        }

        uint8_t ihl = (ip[0] & 0x0f) * 4;
        if (ihl < 20) {
            last_error_ = ParseError::IPv4InvalidIHL;
            result.error = last_error_;
            return result;
        }
        if (offset + ihl > len) {
            last_error_ = ParseError::IPv4Truncated;
            result.error = last_error_;
            return result;
        }

        uint16_t totlen = be16(ip + 2);
        if (totlen < ihl) {
            last_error_ = ParseError::IPv4InvalidTotalLength;
            result.error = last_error_;
            return result;
        }
        if (offset + totlen > len) {
            last_error_ = ParseError::IPv4Truncated;
            result.error = last_error_;
            return result;
        }

        pkt.src_ip = be32(ip + 12);
        pkt.dst_ip = be32(ip + 16);
        uint16_t frag = be16(ip + 6);
        if ((frag & 0x1fff) != 0 || (frag & 0x2000)) {
            pkt.fragmented = true;
            if (options_.skip_fragments) {
                pkt.dpi_eligible = false;
            }
        }

        uint8_t proto = ip[9];
        const size_t l4_start = offset + ihl;
        const size_t ip_end = offset + totlen;

        if (proto == 6) {
            if (l4_start + 20 > ip_end) {
                last_error_ = ParseError::TCPHeaderTooShort;
                result.error = last_error_;
                return result;
            }
            pkt.l4_proto = L4Proto::TCP;
            const uint8_t *tcp = ptr + l4_start;
            pkt.src_port = be16(tcp);
            pkt.dst_port = be16(tcp + 2);
            pkt.tcp_seq = be32(tcp + 4);
            pkt.tcp_ack = be32(tcp + 8);
            pkt.tcp_flags = tcp[13];

            uint8_t tcp_header_len = static_cast<uint8_t>((tcp[12] >> 4) * 4);
            if (tcp_header_len < 20) {
                last_error_ = ParseError::TCPInvalidHeaderLength;
                result.error = last_error_;
                return result;
            }
            if (l4_start + tcp_header_len > ip_end) {
                last_error_ = ParseError::TCPHeaderTooShort;
                result.error = last_error_;
                return result;
            }

            const size_t payload_start = l4_start + tcp_header_len;
            pkt.payload_offset = payload_start;
            pkt.payload_length = ip_end - payload_start;
            pkt.l4_payload.assign(ptr + payload_start, ptr + ip_end);
        } else if (proto == 17) {
            if (l4_start + 8 > ip_end) {
                last_error_ = ParseError::UDPHeaderTooShort;
                result.error = last_error_;
                return result;
            }

            pkt.l4_proto = L4Proto::UDP;
            const uint8_t *udp = ptr + l4_start;
            pkt.src_port = be16(udp);
            pkt.dst_port = be16(udp + 2);
            uint16_t udplen = be16(udp + 4);
            if (udplen < 8) {
                last_error_ = ParseError::UDPInvalidLength;
                result.error = last_error_;
                return result;
            }

            const size_t udp_end = l4_start + udplen;
            if (udp_end > ip_end) {
                last_error_ = ParseError::UDPInvalidLength;
                result.error = last_error_;
                return result;
            }

            const size_t payload_start = l4_start + 8;
            pkt.payload_offset = payload_start;
            pkt.payload_length = udp_end - payload_start;
            pkt.l4_payload.assign(ptr + payload_start, ptr + udp_end);
        }
    } else if (ethertype == 0x86DD) {
        // IPv6 minimal parsing
        if (len < offset + 40) {
            last_error_ = ParseError::PacketTooShortForEthernet;
            result.error = last_error_;
            return result;
        }
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
            if (offset <= len) {
                pkt.payload_offset = offset;
                pkt.payload_length = len - offset;
                pkt.l4_payload.assign(ptr + offset, ptr + len);
            }
        } else if (nxt == 17 && len >= offset + 8) {
            pkt.l4_proto = L4Proto::UDP;
            const uint8_t *udp = ptr + offset;
            pkt.src_port = be16(udp);
            pkt.dst_port = be16(udp + 2);
            offset += 8;
            if (offset <= len) {
                pkt.payload_offset = offset;
                pkt.payload_length = len - offset;
                pkt.l4_payload.assign(ptr + offset, ptr + len);
            }
        }
    } else {
        last_error_ = ParseError::UnsupportedEtherType;
        result.error = last_error_;
        return result;
    }

    result.packet = std::move(pkt);
    result.error = ParseError::None;
    return result;
}

std::optional<ParsedPacket> PacketParser::parse(uint32_t ts_sec,
                                                uint32_t ts_usec,
                                                const std::vector<uint8_t> &data) {
    RawPacket raw;
    raw.timestamp_us = static_cast<uint64_t>(ts_sec) * 1000000ULL + ts_usec;
    raw.bytes = data;
    ParseResult result = parse(raw);
    return result.packet;
}
