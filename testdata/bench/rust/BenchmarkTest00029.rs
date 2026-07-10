use actix_web::{web, HttpResponse};
use std::collections::HashMap;
use std::process::Command;

// Vulnerable: Command injection via variable indirection
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("input").unwrap_or(&String::new()).clone();
    let x = param.clone();
    let output = Command::new("sh").arg("-c").arg(&x).output().expect("failed");
    HttpResponse::Ok().body(String::from_utf8_lossy(&output.stdout).to_string())
}
