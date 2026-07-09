use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: XSS via input value injection
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("value").unwrap_or(&String::new()).clone();
    let html = format!("<input type='text' value='{}'>", param);
    HttpResponse::Ok().content_type("text/html").body(html)
}
