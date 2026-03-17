#ifndef SNI_EXTRACTOR_H
#define SNI_EXTRACTOR_H

#include "extractor.h"
#include <string>
#include <optional>

// Extract Server Name Indication from a TLS ClientHello packet payload.
// This is a best-effort, single-pass parser; returns the first hostname found.

class SNIExtractor : public Extractor {
public:
    SNIExtractor();
    ~SNIExtractor();

    // returns hostname if present
    std::optional<std::string> extract(const unsigned char *data, size_t len);

    void on_packet(const ParsedPacket &packet, FlowMetadata &metadata) override;

    static std::string normalizeDomain(const std::string &domain);
};

#endif // SNI_EXTRACTOR_H
