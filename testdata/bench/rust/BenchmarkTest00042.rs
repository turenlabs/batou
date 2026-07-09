use actix_web::{web, HttpResponse};
use std::collections::HashMap;
use std::path::Path;

// Safe: Path traversal prevented with canonicalize + starts_with
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("file").unwrap_or(&String::new()).clone();
    let base = Path::new("/data");
    let requested = base.join(&param);
    let canonical = match requested.canonicalize() {
        Ok(p) => p,
        Err(_) => return HttpResponse::NotFound().body("not found"),
    };
    if !canonical.starts_with(base) {
        return HttpResponse::Forbidden().body("access denied");
    }
    let content = std::fs::read_to_string(&canonical).unwrap_or_default();
    HttpResponse::Ok().body(content)
}
