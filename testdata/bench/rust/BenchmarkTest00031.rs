use actix_web::{web, HttpResponse};
use std::collections::HashMap;
use std::process::Command;

// Vulnerable: Command injection via push_str
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("dir").unwrap_or(&String::new()).clone();
    let mut cmd = String::from("ls -la ");
    cmd.push_str(&param);
    let output = Command::new("sh").arg("-c").arg(&cmd).output().expect("failed");
    HttpResponse::Ok().body(String::from_utf8_lossy(&output.stdout).to_string())
}
