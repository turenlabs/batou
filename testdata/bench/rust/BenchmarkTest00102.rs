use actix_web::{web, HttpResponse};
use std::collections::HashMap;
use serde::Deserialize;

#[derive(Deserialize)]
struct UserRequest { name: String, age: u32 }

// Safe: Typed deserialization to known struct
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("data").unwrap_or(&String::new()).clone();
    let user: UserRequest = match serde_json::from_str(&param) {
        Ok(u) => u,
        Err(_) => return HttpResponse::BadRequest().body("invalid json"),
    };
    HttpResponse::Ok().body(format!("name={} age={}", user.name, user.age))
}
