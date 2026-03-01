#ifndef HTTP_EXTRACTOR_H
#define HTTP_EXTRACTOR_H

#include <string>
#include <optional>

// Simple HTTP parser used to extract Host header from a request or response.
// Only inspects the first header block; does not reassemble streams.

class HTTPExtractor {
public:
    HTTPExtractor();
    ~HTTPExtractor();

    // Provide raw payload (start of TCP segment) and return host if found.
    std::optional<std::string> extractHost(const unsigned char *data, size_t len);
};

#endif // HTTP_EXTRACTOR_H
