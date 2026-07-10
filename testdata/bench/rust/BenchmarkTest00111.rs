use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: Unsafe TOML deserialization from user input
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("config").unwrap_or(&String::new()).clone();
    let value: toml::Value = toml::from_str(&param).unwrap();
    HttpResponse::Ok().json(format!("{:?}", value))
}
