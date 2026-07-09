use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: Allowlist-based redirect
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("page").unwrap_or(&String::new()).clone();
    let target = match param.as_str() {
        "home" => "/",
        "profile" => "/profile",
        "settings" => "/settings",
        _ => return HttpResponse::BadRequest().body("invalid redirect"),
    };
    HttpResponse::Found().append_header(("Location", target)).finish()
}
