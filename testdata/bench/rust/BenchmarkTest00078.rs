use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: Enum-based endpoint selection prevents SSRF
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("resource").unwrap_or(&String::new()).clone();
    let url = match param.as_str() {
        "users" => "https://api.example.com/users",
        "items" => "https://api.example.com/items",
        "orders" => "https://api.example.com/orders",
        _ => return HttpResponse::BadRequest().body("unknown resource"),
    };
    let resp = reqwest::get(url).await.unwrap();
    HttpResponse::Ok().body(resp.text().await.unwrap_or_default())
}
