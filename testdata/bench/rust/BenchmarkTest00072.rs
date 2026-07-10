use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: Integer ID prevents SSRF
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("id").unwrap_or(&String::new()).clone();
    let id: u64 = match param.parse() {
        Ok(v) => v,
        Err(_) => return HttpResponse::BadRequest().body("invalid id"),
    };
    let url = format!("https://api.example.com/items/{}", id);
    let resp = reqwest::get(&url).await.unwrap();
    HttpResponse::Ok().body(resp.text().await.unwrap_or_default())
}
