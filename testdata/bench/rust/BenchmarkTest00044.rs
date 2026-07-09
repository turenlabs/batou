use actix_web::{web, HttpResponse};
use std::collections::HashMap;
use std::path::Path;

// Safe: Path traversal prevented with file_name() stripping directory
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("file").unwrap_or(&String::new()).clone();
    let safe_name = match Path::new(&param).file_name() {
        Some(n) => n.to_string_lossy().to_string(),
        None => return HttpResponse::BadRequest().body("invalid filename"),
    };
    let path = format!("/data/{}", safe_name);
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    HttpResponse::Ok().body(content)
}
