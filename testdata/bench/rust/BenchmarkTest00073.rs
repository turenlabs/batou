use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: SSRF via host injection in format URL
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("server").unwrap_or(&String::new()).clone();
    let client = reqwest::Client::new();
    let resp = client.get(format!("http://{}/api", param)).send().await.unwrap();
    HttpResponse::Ok().body(resp.text().await.unwrap_or_default())
}
