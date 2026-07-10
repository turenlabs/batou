use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: SSRF via direct reqwest::get with user URL
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("url").unwrap_or(&String::new()).clone();
    let resp = reqwest::get(&param).await.unwrap();
    HttpResponse::Ok().body(resp.text().await.unwrap_or_default())
}
