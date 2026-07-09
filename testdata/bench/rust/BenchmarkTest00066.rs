use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: SSRF prevented with domain allowlist
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("url").unwrap_or(&String::new()).clone();
    let url = match url::Url::parse(&param) {
        Ok(u) => u,
        Err(_) => return HttpResponse::BadRequest().body("invalid url"),
    };
    let allowed = ["api.example.com", "cdn.example.com"];
    let host = url.host_str().unwrap_or("");
    if !allowed.contains(&host) {
        return HttpResponse::Forbidden().body("domain not allowed");
    }
    let resp = reqwest::get(url.as_str()).await.unwrap();
    HttpResponse::Ok().body(resp.text().await.unwrap_or_default())
}
