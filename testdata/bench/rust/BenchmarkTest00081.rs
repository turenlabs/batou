use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: XSS via format! HTML body
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("name").unwrap_or(&String::new()).clone();
    let html = format!("<html><body>Hello, {}!</body></html>", param);
    HttpResponse::Ok().content_type("text/html").body(html)
}
