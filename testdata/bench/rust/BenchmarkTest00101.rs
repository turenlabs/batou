use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: Unsafe deserialization of arbitrary JSON Value
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("data").unwrap_or(&String::new()).clone();
    let value: serde_json::Value = serde_json::from_str(&param).unwrap();
    HttpResponse::Ok().json(value)
}
