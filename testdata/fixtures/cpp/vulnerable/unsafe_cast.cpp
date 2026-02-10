// VULN: Unsafe reinterpret_cast on user-controlled data.
// Demonstrates type confusion / unsafe cast on untrusted input.

#include <cstring>
#include <iostream>
#include <cstdint>

struct Header {
    uint32_t magic;
    uint32_t version;
    uint32_t payload_size;
    uint32_t flags;
};

struct AdminHeader {
    uint32_t magic;
    uint32_t version;
    uint32_t payload_size;
    uint32_t flags;
    uint32_t privilege_level;
    char admin_token[64];
};

void process_packet(const char *data, size_t len) {
    if (len < sizeof(Header)) {
        std::cerr << "Packet too small" << std::endl;
        return;
    }

    // Vulnerable: reinterpret_cast on untrusted network data.
    // Attacker controls the raw bytes, can set arbitrary field values.
    const Header *hdr = reinterpret_cast<const Header *>(data);

    std::cout << "Magic: 0x" << std::hex << hdr->magic << std::endl;
    std::cout << "Version: " << std::dec << hdr->version << std::endl;
    std::cout << "Payload: " << hdr->payload_size << " bytes" << std::endl;

    // Dangerous: casting to a larger struct without size validation
    if (hdr->flags & 0x01) {
        const AdminHeader *admin = reinterpret_cast<const AdminHeader *>(data);
        std::cout << "Privilege: " << admin->privilege_level << std::endl;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <hex-data>" << std::endl;
        return 1;
    }

    process_packet(argv[1], strlen(argv[1]));
    return 0;
}
