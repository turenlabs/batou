use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: Integer index prevents path traversal
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("id").unwrap_or(&String::new()).clone();
    let idx: u32 = match param.parse() {
        Ok(v) => v,
        Err(_) => return HttpResponse::BadRequest().body("invalid id"),
    };
    let path = format!("/data/file_{}.dat", idx);
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    HttpResponse::Ok().body(content)
}
