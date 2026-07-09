use actix_web::{web, HttpResponse};
use std::collections::HashMap;
use std::process::Command;

// Vulnerable: Command injection via string concat
async fn handler(form: web::Form<HashMap<String, String>>) -> HttpResponse {
    let param = form.get("arg").unwrap_or(&String::new()).clone();
    let cmd = String::from("echo ") + &param;
    let output = Command::new("bash").arg("-c").arg(&cmd).output().expect("failed");
    HttpResponse::Ok().body(String::from_utf8_lossy(&output.stdout).to_string())
}
