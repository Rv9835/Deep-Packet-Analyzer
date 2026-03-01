#include "sni_extractor.h"
#include <cassert>
#include <vector>

int main() {
    // build minimal TLS ClientHello containing server_name "test.com"
    std::vector<unsigned char> tls = {
        0x16, 0x03, 0x01, 0x00, 0x2a, // record hdr
        0x01, 0x00, 0x00, 0x26,       // handshake hdr (ClientHello)
        0x03,0x03,
    };
    // random bytes
    for (int i=0;i<32;i++) tls.push_back(0);
    tls.push_back(0); // session id len
    tls.push_back(0); tls.push_back(0); // cipher suite len
    tls.push_back(0); // comp methods len
    tls.push_back(0); tls.push_back(0x0a); // ext len 10
    // server_name ext
    tls.push_back(0x00); tls.push_back(0x00); // type
    tls.push_back(0x00); tls.push_back(0x06); // len 6
    tls.push_back(0x00); tls.push_back(0x04); // list len
    tls.push_back(0x00); // name type
    tls.push_back(0x00); tls.push_back(0x00); // name length 0 (empty)

    SNIExtractor ext;
    auto s = ext.extract(tls.data(), tls.size());
    // our packet has empty hostname, so result should be empty optional but not crash
    assert(!s.has_value());
    return 0;
}
