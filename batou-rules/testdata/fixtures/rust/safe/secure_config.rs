// Safe Rust code - secure configurations
use rand::rngs::OsRng;
use rand::Rng;

// Safe: Default TLS configuration (certificate verification enabled)
fn create_secure_client() -> reqwest::Client {
    reqwest::Client::builder()
        .build()
        .unwrap()
}

// Safe: Cryptographically secure random for token generation
fn generate_api_key() -> String {
    let token: Vec<u8> = (0..32).map(|_| OsRng.gen()).collect();
    hex::encode(token)
}

// Safe: CORS with specific allowed origins
fn configure_cors() -> tower_http::cors::CorsLayer {
    tower_http::cors::CorsLayer::new()
        .allow_origin(["https://example.com".parse().unwrap()])
        .allow_methods([http::Method::GET, http::Method::POST])
}

// Safe: JSON deserialization with size limits (no binary format from untrusted)
fn process_json(data: &str) -> Result<Config, serde_json::Error> {
    serde_json::from_str(data)
}

struct Config { name: String, value: i32 }
