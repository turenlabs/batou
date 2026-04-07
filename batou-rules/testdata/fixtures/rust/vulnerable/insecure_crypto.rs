// RS-006: TLS certificate verification disabled
use reqwest;

pub fn insecure_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

pub fn insecure_hostname() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_hostnames(true)
        .build()
        .unwrap()
}

// RS-010: CORS misconfiguration
use tower_http::cors::CorsLayer;

pub fn permissive_cors() -> CorsLayer {
    CorsLayer::permissive()
}

// RS-008: Insecure random in security context
use rand::Rng;

pub fn generate_token() -> String {
    let mut rng = thread_rng();
    let token: u64 = rng.gen();
    format!("{:x}", token)
}

pub fn generate_session_id() -> u32 {
    rand::random::<u32>()
}
