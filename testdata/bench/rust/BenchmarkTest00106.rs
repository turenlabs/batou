use actix_web::{web, HttpResponse};
use std::collections::HashMap;
use serde::Deserialize;

#[derive(Deserialize)]
struct SearchParams { query: String, page: u32 }

// Safe: Typed deserialization to concrete struct
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("data").unwrap_or(&String::new()).clone();
    let search: SearchParams = match serde_json::from_str(&param) {
        Ok(s) => s,
        Err(_) => return HttpResponse::BadRequest().body("invalid"),
    };
    HttpResponse::Ok().body(format!("search: {} page: {}", search.query, search.page))
}
