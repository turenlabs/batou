// VULN: Use-after-free via delete followed by method call on dangling pointer.
// Should trigger GTSS-MEM-004 (Memory Management Issue: use-after-free).

#include <iostream>
#include <string>

class Session {
public:
    std::string username;
    int session_id;

    Session(const std::string &user, int id)
        : username(user), session_id(id) {}

    void print_info() const {
        std::cout << "Session " << session_id
                  << " for user: " << username << std::endl;
    }

    void invalidate() {
        std::cout << "Session " << session_id << " invalidated" << std::endl;
    }
};

void process_logout(Session *session) {
    session->invalidate();

    // Delete the session
    delete session;

    // Vulnerable: calling method on deleted object (use-after-free)
    session->print_info();
}

int main() {
    Session *s = new Session("alice", 12345);
    s->print_info();
    process_logout(s);
    return 0;
}
