use actix_web::{web, HttpResponse};
use std::process::Command;

// Safe: Completely static command, no user input
async fn handler(_query: web::Query<()>) -> HttpResponse {
    let output = Command::new("/usr/bin/uptime").output().expect("failed");
    HttpResponse::Ok().body(String::from_utf8_lossy(&output.stdout).to_string())
}
