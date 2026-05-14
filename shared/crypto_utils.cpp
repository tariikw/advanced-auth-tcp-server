#include "crypto_utils.hpp"
#include <stdio.h>

namespace crypto {
    std::string sha256(const std::string& data) {
        BCRYPT_ALG_HANDLE h_alg = nullptr;
        BCRYPT_HASH_HANDLE h_hash = nullptr;
        std::vector<uint8_t> hash(32);
        DWORD hash_len = 32, cb_data = 0;

        if (BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return "";
        if (BCryptCreateHash(h_alg, &h_hash, nullptr, 0, nullptr, 0, 0) != 0) return "";
        
        BCryptHashData(h_hash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
        BCryptFinishHash(h_hash, hash.data(), hash_len, 0);

        BCryptDestroyHash(h_hash);
        BCryptCloseAlgorithmProvider(h_alg, 0);

        char hex[65];
        for (int i = 0; i < 32; i++) sprintf_s(hex + (i * 2), 3, "%02x", hash[i]);
        return std::string(hex);
    }

    void rc4_crypt(std::vector<uint8_t>& data, const std::string& key) {
        std::vector<uint8_t> S(256);
        for (int i = 0; i < 256; i++) S[i] = i;

        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + S[i] + key[i % key.length()]) % 256;
            std::swap(S[i], S[j]);
        }

        int i = 0; j = 0;
        for (size_t k = 0; k < data.size(); k++) {
            i = (i + 1) % 256;
            j = (j + S[i]) % 256;
            std::swap(S[i], S[j]);
            data[k] ^= S[(S[i] + S[j]) % 256];
        }
    }
}
