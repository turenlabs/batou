use actix_web::{web, HttpResponse};
use serde::Deserialize;

#[derive(Deserialize)]
struct CreateItem { title: String, quantity: u32 }

// Safe: web::Json extractor with typed struct
async fn handler(body: web::Json<CreateItem>) -> HttpResponse {
    let item = body.into_inner();
    HttpResponse::Ok().body(format!("created: {}", item.title))
}
