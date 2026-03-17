#include "sni_extractor.h"
#include <catch2/catch_test_macros.hpp>
#include <vector>

TEST_CASE("SNIExtractor extracts and normalizes hostname from ClientHello", "[sni]") {
    std::vector<unsigned char> tls = {
        0x16, 0x03, 0x03, 0x00, 0x47,
        0x01, 0x00, 0x00, 0x43,
        0x03, 0x03,
    };
    for (int i = 0; i < 32; ++i) tls.push_back(0x11);
    tls.push_back(0x00);
    tls.push_back(0x00); tls.push_back(0x02); tls.push_back(0x13); tls.push_back(0x01);
    tls.push_back(0x01); tls.push_back(0x00);
    tls.push_back(0x00); tls.push_back(0x18);
    tls.push_back(0x00); tls.push_back(0x00);
    tls.push_back(0x00); tls.push_back(0x14);
    tls.push_back(0x00); tls.push_back(0x12);
    tls.push_back(0x00);
    tls.push_back(0x00); tls.push_back(0x0f);
    const char *host = "ExAmPle.COM.";
    tls.insert(tls.end(), host, host + 15);

    SNIExtractor ext;
    auto result = ext.extract(tls.data(), tls.size());
    REQUIRE(result.has_value());
    REQUIRE(*result == "example.com");
}

TEST_CASE("SNIExtractor gracefully handles partial handshake", "[sni]") {
    std::vector<unsigned char> partial = {
        0x16, 0x03, 0x03, 0x00, 0x20,
        0x01, 0x00, 0x00, 0x1c,
        0x03, 0x03,
        0x00, 0x01, 0x02
    };

    SNIExtractor ext;
    auto result = ext.extract(partial.data(), partial.size());
    REQUIRE_FALSE(result.has_value());
}
