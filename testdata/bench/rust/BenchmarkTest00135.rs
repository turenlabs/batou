use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: Open redirect via push_str
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("target").unwrap_or(&String::new()).clone();
    let mut url = String::new();
    url.push_str(&param);
    HttpResponse::Found().append_header(("Location", url.as_str())).finish()
}
