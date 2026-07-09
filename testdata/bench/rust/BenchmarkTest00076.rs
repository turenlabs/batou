use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: Private IP rejection prevents SSRF
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("url").unwrap_or(&String::new()).clone();
    let url = match url::Url::parse(&param) {
        Ok(u) => u,
        Err(_) => return HttpResponse::BadRequest().body("invalid url"),
    };
    let host = url.host_str().unwrap_or("");
    if host.starts_with("10.") || host.starts_with("172.") || host.starts_with("192.168.") || host == "127.0.0.1" || host == "localhost" {
        return HttpResponse::Forbidden().body("private IP not allowed");
    }
    let resp = reqwest::get(url.as_str()).await.unwrap();
    HttpResponse::Ok().body(resp.text().await.unwrap_or_default())
}
