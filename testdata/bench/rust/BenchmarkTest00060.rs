use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: Regex validated filename prevents traversal
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("file").unwrap_or(&String::new()).clone();
    let re = regex::Regex::new(r"^[a-zA-Z0-9_]+\.txt$").unwrap();
    if !re.is_match(&param) {
        return HttpResponse::BadRequest().body("invalid filename");
    }
    let path = format!("/data/{}", param);
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    HttpResponse::Ok().body(content)
}
