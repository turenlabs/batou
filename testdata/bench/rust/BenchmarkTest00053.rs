use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: Path traversal via push_str path construction
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("file").unwrap_or(&String::new()).clone();
    let mut path = String::from("/data/");
    path.push_str(&param);
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    HttpResponse::Ok().body(content)
}
