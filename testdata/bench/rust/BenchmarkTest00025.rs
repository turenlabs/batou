use actix_web::{web, HttpResponse};
use std::collections::HashMap;
use std::process::Command;

// Vulnerable: Command injection via program name from user input
async fn handler(form: web::Form<HashMap<String, String>>) -> HttpResponse {
    let param = form.get("program").unwrap_or(&String::new()).clone();
    let output = Command::new(format!("/usr/bin/{}", param)).output().expect("failed");
    HttpResponse::Ok().body(String::from_utf8_lossy(&output.stdout).to_string())
}
