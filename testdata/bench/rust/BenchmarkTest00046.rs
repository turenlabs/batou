use actix_web::{web, HttpResponse};

// Safe: Hardcoded file path, no user input
async fn handler(_path: web::Path<String>) -> HttpResponse {
    let content = std::fs::read_to_string("/etc/app/config.toml").unwrap_or_default();
    HttpResponse::Ok().body(content)
}
