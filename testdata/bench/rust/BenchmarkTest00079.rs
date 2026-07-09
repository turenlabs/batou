use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: SSRF via reqwest Client put
async fn handler(form: web::Form<HashMap<String, String>>) -> HttpResponse {
    let param = form.get("url").unwrap_or(&String::new()).clone();
    let client = reqwest::Client::new();
    let resp = client.put(&param).body("data").send().await.unwrap();
    HttpResponse::Ok().body(resp.text().await.unwrap_or_default())
}
