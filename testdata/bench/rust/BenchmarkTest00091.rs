use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: XSS via push_str HTML construction
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("title").unwrap_or(&String::new()).clone();
    let mut html = String::from("<h1>");
    html.push_str(&param);
    html.push_str("</h1>");
    HttpResponse::Ok().content_type("text/html").body(html)
}
