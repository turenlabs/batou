use actix_web::{web, HttpResponse};

// Vulnerable: Unsafe deserialization from bytes
async fn handler(body: web::Bytes) -> HttpResponse {
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    HttpResponse::Ok().json(value)
}
