use actix_web::{web, HttpResponse};
use std::process::Command;

// Safe: Command with hardcoded arguments only
async fn handler(_path: web::Path<String>) -> HttpResponse {
    let output = Command::new("date").arg("+%Y-%m-%d").output().expect("failed");
    HttpResponse::Ok().body(String::from_utf8_lossy(&output.stdout).to_string())
}
