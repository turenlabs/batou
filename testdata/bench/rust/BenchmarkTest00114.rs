use actix_web::{web, HttpResponse};

// Safe: Bincode deserialization from trusted local cache
async fn handler(_query: web::Query<()>) -> HttpResponse {
    let data = std::fs::read("cache/data.bin").unwrap_or_default();
    let _items: Vec<String> = bincode::deserialize(&data).unwrap_or_default();
    HttpResponse::Ok().body("cache loaded")
}
