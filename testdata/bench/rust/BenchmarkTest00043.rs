use actix_web::{web, HttpResponse};
use std::collections::HashMap;
use std::path::PathBuf;

// Vulnerable: Path traversal via PathBuf::from user input
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("path").unwrap_or(&String::new()).clone();
    let path = PathBuf::from(&param);
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    HttpResponse::Ok().body(content)
}
