#include "http_extractor.h"
#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include <string>

TEST_CASE("HTTPExtractor extracts and normalizes Host header", "[http]") {
    const char *req = "GET / HTTP/1.1\r\nHost: ExAmPle.COM:8080.\r\nUser-Agent: test\r\n\r\n";
    HTTPExtractor ext;
    auto h = ext.extractHost((const unsigned char*)req, strlen(req));
    REQUIRE(h.has_value());
    REQUIRE(h.value() == "example.com");
}

TEST_CASE("HTTPExtractor ignores non-request payloads", "[http]") {
    const char *payload = "HTTP/1.1 200 OK\r\nHost: response.example\r\n\r\n";
    HTTPExtractor ext;
    auto h = ext.extractHost((const unsigned char*)payload, strlen(payload));
    REQUIRE_FALSE(h.has_value());
}
