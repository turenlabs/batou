use actix_web::{web, HttpResponse};
use std::collections::HashMap;
use std::process::Command;

// Vulnerable: Command injection via bash -c
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("script").unwrap_or(&String::new()).clone();
    let output = Command::new("bash").arg("-c").arg(&param).output().expect("failed");
    HttpResponse::Ok().body(String::from_utf8_lossy(&output.stdout).to_string())
}
