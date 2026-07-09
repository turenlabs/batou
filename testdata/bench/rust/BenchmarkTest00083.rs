use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: XSS via div injection
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("msg").unwrap_or(&String::new()).clone();
    let html = format!("<div class='result'>{}</div>", param);
    HttpResponse::Ok().content_type("text/html").body(html)
}
