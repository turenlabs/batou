use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: Unsafe deserialization via serde_json::from_reader
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("data").unwrap_or(&String::new()).clone();
    let cursor = std::io::Cursor::new(param.as_bytes().to_vec());
    let value: serde_json::Value = serde_json::from_reader(cursor).unwrap();
    HttpResponse::Ok().json(value)
}
