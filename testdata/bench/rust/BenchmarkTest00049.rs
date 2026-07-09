use actix_web::{web, HttpResponse};
use std::collections::HashMap;
use std::path::PathBuf;

// Vulnerable: Path traversal via join without canonicalize
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("file").unwrap_or(&String::new()).clone();
    let path = PathBuf::from("/var/data").join(&param);
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    HttpResponse::Ok().body(content)
}
