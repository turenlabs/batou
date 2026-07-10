use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: Path traversal via remove_file
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("file").unwrap_or(&String::new()).clone();
    let path = format!("/tmp/{}", param);
    std::fs::remove_file(&path).unwrap();
    HttpResponse::Ok().body("deleted")
}
