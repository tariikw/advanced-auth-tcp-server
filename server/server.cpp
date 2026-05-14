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
    std::cout << "init server\n";

    WSADATA w;
    if (WSAStartup(MAKEWORD(2,2), &w) != 0) return 1;
    
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(54001);
    a.sin_addr.S_un.S_addr = INADDR_ANY;
    
    bind(s, (sockaddr*)&a, sizeof(a));
    listen(s, SOMAXCONN);
    
    std::cout << "lstn 54001\n";
    
    while(true) {
        SOCKET cs = accept(s, nullptr, nullptr);
        if (cs == INVALID_SOCKET) continue;
        
        std::cout << "inc conn\n";
        
        auth_packet pkt = {0};
        int received = recv(cs, (char*)&pkt, sizeof(pkt), 0);
        
        if (received == sizeof(pkt)) {
            if (pkt.magic == 0xDEADBEEF) {
                std::string hwid_hash = crypto::sha256(pkt.hwid);
                std::cout << "hwid " << hwid_hash << "\n";
                
                if (pkt.payload_len > 0 && pkt.payload_len < 4096) {
                    std::vector<uint8_t> payload(pkt.payload_len);
                    recv(cs, (char*)payload.data(), pkt.payload_len, 0);
                    
                    crypto::rc4_crypt(payload, "blablablasecretkey");
                    
                    std::cout << "dec payload " << std::string(payload.begin(), payload.end()) << "\n";
                    
                    const char* resp = "auth success\n";
                    send(cs, resp, strlen(resp), 0);
                }
            } else {
                std::cout << "inv magic\n";
            }
        }
        closesocket(cs);
    }
    
    closesocket(s);
    WSACleanup();
    return 0;
}
