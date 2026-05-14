#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

namespace crypto {
    std::string sha256(const std::string& data);
    void rc4_crypt(std::vector<uint8_t>& data, const std::string& key);
}
