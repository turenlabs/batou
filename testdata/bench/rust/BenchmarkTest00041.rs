use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: Path traversal via format! in file read
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("file").unwrap_or(&String::new()).clone();
    let path = format!("/data/{}", param);
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    HttpResponse::Ok().body(content)
}
