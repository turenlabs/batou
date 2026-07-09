use actix_web::{web, HttpResponse};
use std::collections::HashMap;
use std::process::Command;

// Vulnerable: Command injection via cmd /C on Windows
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("cmd").unwrap_or(&String::new()).clone();
    let output = Command::new("cmd").arg("/C").arg(&param).output().expect("failed");
    HttpResponse::Ok().body(String::from_utf8_lossy(&output.stdout).to_string())
}
