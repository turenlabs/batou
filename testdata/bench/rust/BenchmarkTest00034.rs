use actix_web::{web, HttpResponse};
use std::collections::HashMap;
use std::process::Command;

// Safe: Regex validation before command arg
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("name").unwrap_or(&String::new()).clone();
    let re = regex::Regex::new(r"^[a-zA-Z0-9_]+$").unwrap();
    if !re.is_match(&param) {
        return HttpResponse::BadRequest().body("invalid name");
    }
    let output = Command::new("grep").arg("--").arg(&param).arg("users.txt").output().expect("failed");
    HttpResponse::Ok().body(String::from_utf8_lossy(&output.stdout).to_string())
}
