use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: Relative path only redirect, reject absolute URLs
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("next").unwrap_or(&String::new()).clone();
    if param.contains("://") || param.starts_with("//") {
        return HttpResponse::BadRequest().body("absolute URLs not allowed");
    }
    let path = format!("/{}", param.trim_start_matches('/'));
    HttpResponse::Found().append_header(("Location", path.as_str())).finish()
}
