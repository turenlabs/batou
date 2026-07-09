use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: SSRF via reqwest Client post
async fn handler(form: web::Form<HashMap<String, String>>) -> HttpResponse {
    let param = form.get("webhook").unwrap_or(&String::new()).clone();
    let client = reqwest::Client::new();
    let resp = client.post(&param).body("ping").send().await.unwrap();
    HttpResponse::Ok().body(resp.text().await.unwrap_or_default())
}
