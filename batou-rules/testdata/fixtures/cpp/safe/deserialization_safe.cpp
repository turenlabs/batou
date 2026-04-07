#include <flatbuffers/flatbuffers.h>
#include <google/protobuf/message.h>
#include <drogon/HttpResponse.h>
#include <drogon/HttpRequest.h>
#include <cstdlib>
#include <string>

// FlatBuffers: safe with Verifier before GetRoot
void safe_flatbuf(const uint8_t* buf, size_t len) {
    flatbuffers::Verifier verifier(buf, len);
    // Only access after verification passes
    if (verifier.VerifyBuffer<Monster>()) {
        auto monster = flatbuffers::GetRoot<Monster>(buf);
    }
}

// Protobuf: safe with IsInitialized check
void safe_protobuf(const std::string& data) {
    MyMessage msg;
    msg.ParseFromString(data);
    if (msg.IsInitialized()) {
        // Safe to use after validation
    }
}

// Drogon: safe with htmlTranslate escaping
void safe_drogon_handler(const drogon::HttpRequestPtr &req,
                         std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
    auto name = req->getParameter("name");
    auto safe_name = drogon::HttpViewData::htmlTranslate(name);
    auto resp = drogon::HttpResponse::newHttpResponse();
    resp->setBody("<h1>Hello " + safe_name + "</h1>");
    callback(resp);
}
