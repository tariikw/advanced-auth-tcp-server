#include <iostream>
#include <string>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "..\shared\crypto_utils.hpp"

#pragma comment(lib, "ws2_32.lib")

#pragma pack(push, 1)
struct auth_packet {
    uint32_t magic;
    char hwid[64];
    uint32_t payload_len;
};
#pragma pack(pop)

int main() {
    WSADATA w;
    if (WSAStartup(MAKEWORD(2,2), &w) != 0) return 1;

    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(54001);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);

    if (connect(s, (sockaddr*)&a, sizeof(a)) == SOCKET_ERROR) {
        std::cout << "conn err\n";
        return 1;
    }

    std::cout << "conn ok\n";

    std::string hwid_str = "A1B2C3D4E5F6G7H8";
    std::string payload_str = "load module 0x1";
    
    std::vector<uint8_t> payload(payload_str.begin(), payload_str.end());
    crypto::rc4_crypt(payload, "blablablasecretkey");

    auth_packet pkt = {0};
    pkt.magic = 0xDEADBEEF;
    strncpy_s(pkt.hwid, sizeof(pkt.hwid), hwid_str.c_str(), _TRUNCATE);
    pkt.payload_len = (uint32_t)payload.size();

    send(s, (char*)&pkt, sizeof(pkt), 0);
    send(s, (char*)payload.data(), (int)payload.size(), 0);

    char b[256] = {0};
    int r = recv(s, b, sizeof(b) - 1, 0);
    if (r > 0) {
        std::cout << "srv " << b << "\n";
    }

    closesocket(s);
    WSACleanup();
    return 0;
}
