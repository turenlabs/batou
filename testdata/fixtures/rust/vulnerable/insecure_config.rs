// Vulnerable Rust code - insecure configurations
use rand::Rng;

// RS-006: Insecure TLS - disabled certificate verification
fn create_insecure_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .unwrap()
}

// RS-008: Insecure random for token generation
fn generate_api_key() -> String {
    let mut rng = thread_rng();
    let token: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    hex::encode(token)
}

// RS-010: CORS permissive configuration
fn configure_cors() -> actix_cors::Cors {
    actix_cors::Cors::permissive()
}

// RS-010: CORS any origin with credentials
fn configure_cors_creds() -> tower_http::cors::CorsLayer {
    tower_http::cors::CorsLayer::new()
        .allow_any_origin()
        .allow_credentials(true)
}

// RS-005: Insecure deserialization of binary data
fn process_binary(data: &[u8]) -> Message {
    bincode::deserialize(data).unwrap()
}

struct Message { content: String }
