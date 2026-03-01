#ifndef UTILS_H
#define UTILS_H

#include <string>

// compute sha256 of file contents; returns hex string or empty on failure
std::string sha256_file(const std::string &path);

#endif // UTILS_H
