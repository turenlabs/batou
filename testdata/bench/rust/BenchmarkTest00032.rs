use actix_web::{web, HttpResponse};
use std::collections::HashMap;
use std::process::Command;

// Safe: Allowlist of permitted commands
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("action").unwrap_or(&String::new()).clone();
    let cmd = match param.as_str() {
        "list" => "ls",
        "time" => "date",
        "disk" => "df",
        _ => return HttpResponse::BadRequest().body("unknown action"),
    };
    let output = Command::new(cmd).output().expect("failed");
    HttpResponse::Ok().body(String::from_utf8_lossy(&output.stdout).to_string())
}
