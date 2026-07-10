use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: JSON response prevents XSS
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("data").unwrap_or(&String::new()).clone();
    HttpResponse::Ok().json(serde_json::json!({"value": param}))
}
