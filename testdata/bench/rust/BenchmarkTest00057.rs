use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: Path traversal via copy from user path
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("src").unwrap_or(&String::new()).clone();
    std::fs::copy(&param, "/backup/latest.dat").unwrap();
    HttpResponse::Ok().body("copied")
}
