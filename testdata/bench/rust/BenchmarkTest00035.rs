use actix_web::{web, HttpResponse};
use std::collections::HashMap;
use std::process::Command;

// Vulnerable: Command injection via to_string chain
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("cmd").unwrap_or(&String::new()).clone();
    let s = param.to_string();
    let output = Command::new("sh").arg("-c").arg(&s).output().expect("failed");
    HttpResponse::Ok().body(String::from_utf8_lossy(&output.stdout).to_string())
}
