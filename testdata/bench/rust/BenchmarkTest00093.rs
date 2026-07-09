use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: XSS via href injection
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("link").unwrap_or(&String::new()).clone();
    let html = format!("<a href='{}'>Click here</a>", param);
    HttpResponse::Ok().content_type("text/html").body(html)
}
