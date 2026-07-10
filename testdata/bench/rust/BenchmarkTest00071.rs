use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: SSRF via string concat URL
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("host").unwrap_or(&String::new()).clone();
    let url = String::from("http://") + &param + "/api/data";
    let resp = reqwest::get(&url).await.unwrap();
    HttpResponse::Ok().body(resp.text().await.unwrap_or_default())
}
