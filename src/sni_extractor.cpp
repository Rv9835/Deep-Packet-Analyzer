#include "sni_extractor.h"
#include <cstring>

SNIExtractor::SNIExtractor() {}
SNIExtractor::~SNIExtractor() {}

static uint16_t read16(const unsigned char *p) {
    return (uint16_t(p[0]) << 8) | uint16_t(p[1]);
}

std::optional<std::string> SNIExtractor::extract(const unsigned char *data, size_t len) {
    // minimalistic parse: expect TLS record header (5 bytes)
    if (len < 5) return std::nullopt;
    unsigned char content_type = data[0];
    if (content_type != 22) return std::nullopt; // handshake
    uint16_t version = read16(data+1);
    uint16_t record_len = read16(data+3);
    if (len < 5 + record_len) return std::nullopt;
    const unsigned char *p = data + 5;
    size_t remaining = record_len;
    // handshake header
    if (remaining < 4) return std::nullopt;
    unsigned char hs_type = p[0];
    uint32_t hs_len = (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
    if (hs_type != 1) return std::nullopt; // ClientHello
    if (remaining < 4 + hs_len) return std::nullopt;
    p += 4;
    remaining -= 4;
    // skip: version(2), random(32)
    if (remaining < 2+32) return std::nullopt;
    p += 2+32;
    remaining -= 2+32;
    // session id
    if (remaining < 1) return std::nullopt;
    unsigned char sid_len = p[0]; p++; remaining--;
    if (remaining < sid_len) return std::nullopt;
    p += sid_len; remaining -= sid_len;
    // cipher suites
    if (remaining < 2) return std::nullopt;
    uint16_t cs_len = read16(p); p +=2; remaining -= 2;
    if (remaining < cs_len) return std::nullopt;
    p += cs_len; remaining -= cs_len;
    // compression methods
    if (remaining < 1) return std::nullopt;
    unsigned char comp_len = p[0]; p++; remaining--;
    if (remaining < comp_len) return std::nullopt;
    p += comp_len; remaining -= comp_len;
    // extensions
    if (remaining < 2) return std::nullopt;
    uint16_t ext_len = read16(p); p += 2; remaining -= 2;
    while (remaining >= 4) {
        uint16_t ext_type = read16(p);
        uint16_t ext_sz = read16(p+2);
        p += 4;
        remaining -= 4;
        if (remaining < ext_sz) break;
        if (ext_type == 0x0000) { // server_name
            const unsigned char *q = p;
            if (ext_sz < 2) break;
            uint16_t list_len = read16(q); q += 2;
            size_t list_rem = ext_sz - 2;
            while (list_rem >= 3) {
                unsigned char name_type = q[0];
                uint16_t name_len = read16(q+1);
                q += 3;
                list_rem -= 3;
                if (list_rem < name_len) break;
                if (name_type == 0) {
                    // host_name
                    return std::string(reinterpret_cast<const char*>(q), name_len);
                }
                q += name_len;
                list_rem -= name_len;
            }
            break;
        }
        p += ext_sz;
        remaining -= ext_sz;
    }
    return std::nullopt;
}
