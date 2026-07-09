use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: XSS via script injection
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("data").unwrap_or(&String::new()).clone();
    let html = format!("<script>var data = '{}';</script>", param);
    HttpResponse::Ok().content_type("text/html").body(html)
}
