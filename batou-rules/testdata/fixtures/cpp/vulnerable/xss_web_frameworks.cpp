#include <drogon/HttpResponse.h>
#include <drogon/HttpRequest.h>
#include <civetweb.h>
#include <httplib.h>
#include <cstdlib>
#include <string>

// Drogon XSS: user input reflected in response body
void drogon_handler(const drogon::HttpRequestPtr &req,
                    std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
    auto name = req->getParameter("name");
    auto resp = drogon::HttpResponse::newHttpResponse();
    resp->setBody("<h1>Hello " + name + "</h1>");
    callback(resp);
}

// CivetWeb XSS: user input in mg_printf output
int civet_handler(struct mg_connection *conn, void *cbdata) {
    char *user_input = getenv("USER_INPUT");
    mg_printf(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<p>%s</p>", user_input);
    return 200;
}

// cpp-httplib XSS: user input in set_content
void httplib_handler(const httplib::Request &req, httplib::Response &res) {
    char *name = getenv("USER_NAME");
    res.set_content("<html><body>" + std::string(name) + "</body></html>", "text/html");
}
