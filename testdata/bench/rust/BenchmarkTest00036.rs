use actix_web::{web, HttpResponse};
use std::collections::HashMap;
use std::process::Command;

// Safe: Fixed command with safe argument passing
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("pattern").unwrap_or(&String::new()).clone();
    let output = Command::new("grep").arg("-r").arg("--").arg(&param).arg("/var/log/").output().expect("failed");
    HttpResponse::Ok().body(String::from_utf8_lossy(&output.stdout).to_string())
}
