use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: XSS prevented with ammonia HTML sanitizer
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("name").unwrap_or(&String::new()).clone();
    let clean = ammonia::clean(&param);
    let html = format!("<html><body>Hello, {}!</body></html>", clean);
    HttpResponse::Ok().content_type("text/html").body(html)
}
