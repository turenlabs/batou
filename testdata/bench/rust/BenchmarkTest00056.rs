use actix_web::{web, HttpResponse};
use std::collections::HashMap;
use std::path::Path;

// Safe: fs::canonicalize + starts_with base dir check
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("file").unwrap_or(&String::new()).clone();
    let base = Path::new("/var/data");
    let target = base.join(&param);
    let canonical = match std::fs::canonicalize(&target) {
        Ok(p) => p,
        Err(_) => return HttpResponse::NotFound().body("not found"),
    };
    if !canonical.starts_with(base) {
        return HttpResponse::Forbidden().body("denied");
    }
    let content = std::fs::read_to_string(&canonical).unwrap_or_default();
    HttpResponse::Ok().body(content)
}
