use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: Unsafe deserialization via to_string chain
async fn handler(body: web::Bytes) -> HttpResponse {
    let s = String::from_utf8_lossy(&body).to_string();
    let value: serde_json::Value = serde_json::from_str(&s).unwrap();
    HttpResponse::Ok().json(value)
}
