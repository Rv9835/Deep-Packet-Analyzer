#ifndef EXTRACTOR_H
#define EXTRACTOR_H

#include "packet_parser.h"
#include <string>
#include <unordered_map>

struct FlowMetadata {
    std::unordered_map<std::string, std::string> values;
};

class Extractor {
public:
    virtual ~Extractor() = default;
    virtual void on_packet(const ParsedPacket &packet, FlowMetadata &metadata) = 0;
};

#endif // EXTRACTOR_H
