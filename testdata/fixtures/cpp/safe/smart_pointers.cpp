// SAFE: Memory management using unique_ptr and shared_ptr.
// Should NOT trigger memory management issues.

#include <iostream>
#include <memory>
#include <string>
#include <vector>

class Session {
public:
    std::string username;
    int session_id;

    Session(const std::string &user, int id)
        : username(user), session_id(id) {
        std::cout << "Session " << session_id << " created" << std::endl;
    }

    ~Session() {
        std::cout << "Session " << session_id << " destroyed" << std::endl;
    }

    void print_info() const {
        std::cout << "Session " << session_id
                  << " for user: " << username << std::endl;
    }
};

class SessionManager {
public:
    void create_session(const std::string &user, int id) {
        // Safe: unique_ptr handles deallocation automatically
        auto session = std::make_unique<Session>(user, id);
        session->print_info();
        sessions_.push_back(std::move(session));
    }

    void create_shared_session(const std::string &user, int id) {
        // Safe: shared_ptr with reference counting
        auto session = std::make_shared<Session>(user, id);
        session->print_info();
        shared_sessions_.push_back(session);
    }

    size_t count() const { return sessions_.size() + shared_sessions_.size(); }

private:
    std::vector<std::unique_ptr<Session>> sessions_;
    std::vector<std::shared_ptr<Session>> shared_sessions_;
};

int main() {
    SessionManager mgr;
    mgr.create_session("alice", 1);
    mgr.create_session("bob", 2);
    mgr.create_shared_session("charlie", 3);

    std::cout << "Active sessions: " << mgr.count() << std::endl;
    // All sessions are automatically freed when mgr goes out of scope
    return 0;
}
