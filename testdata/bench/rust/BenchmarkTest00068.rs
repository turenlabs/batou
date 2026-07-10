use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: SSRF prevented with scheme check
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("url").unwrap_or(&String::new()).clone();
    let url = match url::Url::parse(&param) {
        Ok(u) => u,
        Err(_) => return HttpResponse::BadRequest().body("invalid url"),
    };
    if url.scheme() != "https" {
        return HttpResponse::BadRequest().body("https only");
    }
    if url.host_str() != Some("api.example.com") {
        return HttpResponse::Forbidden().body("not allowed");
    }
    let resp = reqwest::get(url.as_str()).await.unwrap();
    HttpResponse::Ok().body(resp.text().await.unwrap_or_default())
}
