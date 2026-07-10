use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: Unsafe deserialization with variable indirection
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("payload").unwrap_or(&String::new()).clone();
    let data = param.clone();
    let value: serde_json::Value = serde_json::from_str(&data).unwrap();
    HttpResponse::Ok().json(value)
}
