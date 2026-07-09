use actix_web::{web, HttpResponse};

// Vulnerable: Unsafe bincode deserialize_from user stream
async fn handler(body: web::Bytes) -> HttpResponse {
    let cursor = std::io::Cursor::new(body.to_vec());
    let data: Vec<String> = bincode::deserialize_from(cursor).unwrap();
    HttpResponse::Ok().json(data)
}
