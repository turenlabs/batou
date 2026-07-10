use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: Fixed base URL with validated path segment
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("resource").unwrap_or(&String::new()).clone();
    if !param.chars().all(|c| c.is_alphanumeric() || c == '-') {
        return HttpResponse::BadRequest().body("invalid resource");
    }
    let url = format!("https://api.example.com/v1/{}", param);
    let resp = reqwest::get(&url).await.unwrap();
    HttpResponse::Ok().body(resp.text().await.unwrap_or_default())
}
