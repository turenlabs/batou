use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: Path traversal via async file read
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("doc").unwrap_or(&String::new()).clone();
    let content = tokio::fs::read_to_string(&param).await.unwrap_or_default();
    HttpResponse::Ok().body(content)
}
