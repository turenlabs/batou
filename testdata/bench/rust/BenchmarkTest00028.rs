use actix_web::{web, HttpResponse};
use std::collections::HashMap;
use std::process::Command;

// Safe: arg() without shell, user input as argument not command
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("text").unwrap_or(&String::new()).clone();
    let output = Command::new("echo").arg(&param).output().expect("failed");
    HttpResponse::Ok().body(String::from_utf8_lossy(&output.stdout).to_string())
}
