use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: SSRF via partial URL construction
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("endpoint").unwrap_or(&String::new()).clone();
    let url = format!("http://internal-api/{}", param);
    let resp = reqwest::get(&url).await.unwrap();
    HttpResponse::Ok().body(resp.text().await.unwrap_or_default())
}
