#include "http_extractor.h"
#include <string>
#include <cctype>
#include <algorithm>

HTTPExtractor::HTTPExtractor() {}
HTTPExtractor::~HTTPExtractor() {}

std::string HTTPExtractor::normalizeDomain(const std::string &host) {
    if (host.empty()) return host;
    std::string out;
    out.reserve(host.size());
    for (char ch : host) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }

    size_t begin = 0;
    while (begin < out.size() && std::isspace(static_cast<unsigned char>(out[begin]))) ++begin;
    size_t end = out.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(out[end - 1]))) --end;
    out = out.substr(begin, end - begin);

    if (!out.empty() && out.front() == '[') {
        auto close = out.find(']');
        if (close != std::string::npos) {
            return out.substr(0, close + 1);
        }
    }

    auto colon = out.find(':');
    if (colon != std::string::npos) {
        out = out.substr(0, colon);
    }

    while (!out.empty() && out.back() == '.') {
        out.pop_back();
    }
    return out;
}

std::optional<std::string> HTTPExtractor::extractHost(const unsigned char *data, size_t len) {
    if (len == 0) return std::nullopt;
    std::string s(reinterpret_cast<const char*>(data), len);
    // request-line check (MVP, no stream reassembly)
    auto line_end = s.find("\r\n");
    if (line_end == std::string::npos) return std::nullopt;
    const std::string request_line = s.substr(0, line_end);
    if (request_line.rfind("GET ", 0) != 0 &&
        request_line.rfind("POST ", 0) != 0 &&
        request_line.rfind("PUT ", 0) != 0 &&
        request_line.rfind("DELETE ", 0) != 0 &&
        request_line.rfind("HEAD ", 0) != 0 &&
        request_line.rfind("OPTIONS ", 0) != 0 &&
        request_line.rfind("PATCH ", 0) != 0) {
        return std::nullopt;
    }

    auto pos = s.find("\r\nHost:");
    if (pos == std::string::npos) {
        pos = s.find("\r\nhost:");
    }
    if (pos == std::string::npos) return std::nullopt;
    pos += 7;
    // skip whitespace
    while (pos < s.size() && isspace((unsigned char)s[pos])) pos++;
    size_t end = s.find('\r', pos);
    if (end == std::string::npos) end = s.find('\n', pos);
    if (end == std::string::npos) return std::nullopt;
    std::string host = normalizeDomain(s.substr(pos, end - pos));
    if (host.empty()) return std::nullopt;
    return host;
}

void HTTPExtractor::on_packet(const ParsedPacket &packet, FlowMetadata &metadata) {
    if (packet.l4_payload.empty()) return;
    auto host = extractHost(packet.l4_payload.data(), packet.l4_payload.size());
    if (host) {
        metadata.values["http.host"] = *host;
    }
}
