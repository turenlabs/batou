use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: Unsafe serde_json::from_value from user JSON
async fn handler(body: web::Json<serde_json::Value>) -> HttpResponse {
    let v = body.into_inner();
    let map: HashMap<String, serde_json::Value> = serde_json::from_value(v).unwrap();
    HttpResponse::Ok().json(map)
}
