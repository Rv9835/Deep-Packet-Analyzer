#include "utils.h"
#include <openssl/sha.h>
#include <fstream>
#include <iomanip>
#include <sstream>

std::string sha256_file(const std::string &path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return "";
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    char buf[8192];
    while (in.good()) {
        in.read(buf, sizeof(buf));
        std::streamsize n = in.gcount();
        if (n > 0) SHA256_Update(&ctx, buf, n);
    }
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return oss.str();
}
