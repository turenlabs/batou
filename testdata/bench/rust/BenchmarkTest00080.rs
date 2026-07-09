use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: User input only in query string, not in URL
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("q").unwrap_or(&String::new()).clone();
    let client = reqwest::Client::new();
    let resp = client.get("https://api.example.com/search")
        .query(&[("q", &param)])
        .send().await.unwrap();
    HttpResponse::Ok().body(resp.text().await.unwrap_or_default())
}
