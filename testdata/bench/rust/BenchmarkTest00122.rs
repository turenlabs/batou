use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: Redirect prevented with URL parse and host allowlist
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("url").unwrap_or(&String::new()).clone();
    let url = match url::Url::parse(&param) {
        Ok(u) => u,
        Err(_) => return HttpResponse::BadRequest().body("invalid url"),
    };
    if url.host_str() != Some("example.com") && url.host_str() != Some("www.example.com") {
        return HttpResponse::BadRequest().body("redirect not allowed");
    }
    HttpResponse::Found().append_header(("Location", url.as_str())).finish()
}
