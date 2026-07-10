use actix_web::{web, HttpResponse};

// Safe: Deserialization from local config file, not user input
async fn handler(_query: web::Query<()>) -> HttpResponse {
    let contents = std::fs::read_to_string("config.json").unwrap_or_default();
    let _config: serde_json::Value = serde_json::from_str(&contents).unwrap_or_default();
    HttpResponse::Ok().body("config loaded")
}
