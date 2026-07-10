use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: XSS via variable indirection
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("content").unwrap_or(&String::new()).clone();
    let x = param.clone();
    let html = format!("<p>{}</p>", x);
    HttpResponse::Ok().content_type("text/html").body(html)
}
