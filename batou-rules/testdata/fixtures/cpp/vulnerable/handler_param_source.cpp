// VULN: C++ handler-parameter-as-source taint.
//
// These are entry-point handlers (handler-shaped names) whose user-shaped
// string/buffer parameters are attacker-controlled. Batou seeds such params
// as taint sources (Layer 3 tsflow) so the dataflow into the dangerous sink
// is detected even without an explicit framework source call.
//
// Expected detections:
//   handle()       -> system(user.c_str())        CWE-78  command injection
//   handle_sql()   -> req->db().query(user)        CWE-89  SQL injection (nested receiver)
//   on_request()   -> popen(cmd, "r")              CWE-78  command injection

#include <string>
#include <cstdio>
#include <cstdlib>

struct DB {
    void query(const std::string &sql);
};
struct Req {
    DB &db();
};

// Tainted std::string param flows into system() via c_str().
void handle(const std::string &user) {
    std::system(user.c_str());
}

// Tainted std::string param flows into a nested/chained-receiver SQL sink.
void handle_sql(Req *req, const std::string &user) {
    req->db().query(user);
}

// Tainted char* buffer param flows into popen().
void on_request(char *cmd) {
    FILE *fp = popen(cmd, "r");
    if (fp) {
        pclose(fp);
    }
}
