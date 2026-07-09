use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: Path-only redirect prevents protocol-relative URLs
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("path").unwrap_or(&String::new()).clone();
    let path = format!("/{}", param.trim_start_matches('/'));
    if path.contains("://") || path.starts_with("//") {
        return HttpResponse::BadRequest().body("invalid path");
    }
    HttpResponse::Found().append_header(("Location", path.as_str())).finish()
}
