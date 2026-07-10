use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: Typed deserialization to Vec<String>
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("tags").unwrap_or(&String::new()).clone();
    let tags: Vec<String> = match serde_json::from_str(&param) {
        Ok(t) => t,
        Err(_) => return HttpResponse::BadRequest().body("invalid json"),
    };
    HttpResponse::Ok().json(tags)
}
