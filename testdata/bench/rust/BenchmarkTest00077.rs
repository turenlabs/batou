use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: SSRF via to_string chain
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("url").unwrap_or(&String::new()).clone();
    let u = param.to_string();
    let resp = reqwest::get(&u).await.unwrap();
    HttpResponse::Ok().body(resp.text().await.unwrap_or_default())
}
