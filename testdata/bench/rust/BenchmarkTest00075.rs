use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: SSRF via push_str URL construction
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("url").unwrap_or(&String::new()).clone();
    let mut url = String::from("http://");
    url.push_str(&param);
    let resp = reqwest::get(&url).await.unwrap();
    HttpResponse::Ok().body(resp.text().await.unwrap_or_default())
}
