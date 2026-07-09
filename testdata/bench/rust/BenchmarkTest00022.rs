use actix_web::{web, HttpResponse};
use std::collections::HashMap;
use std::process::Command;

// Safe: Command execution with fixed program and validated arg
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("host").unwrap_or(&String::new()).clone();
    if !param.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-') {
        return HttpResponse::BadRequest().body("invalid host");
    }
    let output = Command::new("ping").arg("-c").arg("3").arg(&param).output().expect("failed");
    HttpResponse::Ok().body(String::from_utf8_lossy(&output.stdout).to_string())
}
