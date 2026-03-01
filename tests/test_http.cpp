#include "http_extractor.h"
#include <cassert>
#include <string>

int main() {
    const char *req = "GET / HTTP/1.1\r\nHost: Example.COM\r\nUser-Agent: test\r\n\r\n";
    HTTPExtractor ext;
    auto h = ext.extractHost((const unsigned char*)req, strlen(req));
    assert(h.has_value());
    assert(h.value() == "Example.COM");
    return 0;
}
