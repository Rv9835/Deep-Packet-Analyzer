#include "http_extractor.h"
#include <string>
#include <cctype>

HTTPExtractor::HTTPExtractor() {}
HTTPExtractor::~HTTPExtractor() {}

std::optional<std::string> HTTPExtractor::extractHost(const unsigned char *data, size_t len) {
    if (len == 0) return std::nullopt;
    std::string s(reinterpret_cast<const char*>(data), len);
    // find start of headers (after first CRLF)
    auto pos = s.find("Host:");
    if (pos == std::string::npos) return std::nullopt;
    pos += 5;
    // skip whitespace
    while (pos < s.size() && isspace((unsigned char)s[pos])) pos++;
    size_t end = s.find('\r', pos);
    if (end == std::string::npos) end = s.find('\n', pos);
    if (end == std::string::npos) return std::nullopt;
    std::string host = s.substr(pos, end - pos);
    return host;
}
