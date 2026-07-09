use actix_web::{web, HttpResponse};

// Vulnerable: Unsafe bincode deserialization from user bytes
async fn handler(body: web::Bytes) -> HttpResponse {
    let items: Vec<u8> = bincode::deserialize(&body).unwrap();
    HttpResponse::Ok().json(items)
}
