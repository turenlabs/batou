use actix_web::{web, HttpResponse};

// Safe: TOML deserialization from local file
async fn handler(_query: web::Query<()>) -> HttpResponse {
    let contents = std::fs::read_to_string("App.toml").unwrap_or_default();
    let _config: toml::Value = toml::from_str(&contents).unwrap_or_default();
    HttpResponse::Ok().body("config loaded")
}
