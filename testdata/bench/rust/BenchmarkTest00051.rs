use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: Path traversal via variable indirection
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("name").unwrap_or(&String::new()).clone();
    let f = param.clone();
    let content = std::fs::read_to_string(&f).unwrap_or_default();
    HttpResponse::Ok().body(content)
}
