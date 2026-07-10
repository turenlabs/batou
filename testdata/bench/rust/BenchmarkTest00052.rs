use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: Extension allowlist prevents traversal
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("file").unwrap_or(&String::new()).clone();
    if !param.ends_with(".txt") && !param.ends_with(".csv") {
        return HttpResponse::BadRequest().body("invalid extension");
    }
    if param.contains("..") {
        return HttpResponse::BadRequest().body("invalid path");
    }
    let path = format!("/data/{}", param);
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    HttpResponse::Ok().body(content)
}
