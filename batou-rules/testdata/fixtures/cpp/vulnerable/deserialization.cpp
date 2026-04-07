#include <cereal/archives/binary.h>
#include <cereal/archives/json.h>
#include <msgpack.hpp>
#include <capnp/message.h>
#include <capnp/serialize.h>
#include <flatbuffers/flatbuffers.h>
#include <nlohmann/json.hpp>
#include <sstream>
#include <cstdlib>
#include <cstring>

struct Config {
    int value;
    template<class Archive>
    void serialize(Archive& ar) { ar(value); }
};

// Cereal deserialization from untrusted input
void load_cereal_binary() {
    char *data = getenv("CONFIG_DATA");
    std::istringstream iss(data);
    cereal::BinaryInputArchive archive(iss);
    Config cfg;
    archive(cfg);
}

void load_cereal_json() {
    char *data = getenv("JSON_DATA");
    std::istringstream iss(data);
    cereal::JSONInputArchive archive(iss);
    Config cfg;
    archive(cfg);
}

// MessagePack deserialization from untrusted input
void process_msgpack() {
    char *raw = getenv("MSG_DATA");
    size_t len = strlen(raw);
    msgpack::object_handle oh = msgpack::unpack(raw, len);
}

// Cap'n Proto deserialization from untrusted input
void read_capnp(const char* buf, size_t len) {
    kj::ArrayPtr<const kj::byte> arr(reinterpret_cast<const kj::byte*>(buf), len);
    capnp::FlatArrayMessageReader reader(arr);
}

// FlatBuffers without Verifier
void parse_flatbuf(const uint8_t* buf) {
    auto monster = flatbuffers::GetRoot<Monster>(buf);
}

// nlohmann::json binary format deserialization
void parse_cbor(const std::vector<uint8_t>& data) {
    auto j = nlohmann::json::from_cbor(data);
}

void parse_msgpack_nlohmann(const std::vector<uint8_t>& data) {
    auto j = nlohmann::json::from_msgpack(data);
}
