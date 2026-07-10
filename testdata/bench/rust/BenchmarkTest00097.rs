use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: XSS via to_string chain
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("msg").unwrap_or(&String::new()).clone();
    let s = param.to_string();
    let html = format!("<span>{}</span>", s);
    HttpResponse::Ok().content_type("text/html").body(html)
}
