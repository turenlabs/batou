use actix_web::{web, HttpResponse};
use std::collections::HashMap;
use std::process::Command;

// Safe: Integer-parsed argument prevents injection
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("count").unwrap_or(&String::new()).clone();
    let n: u32 = match param.parse() {
        Ok(v) => v,
        Err(_) => return HttpResponse::BadRequest().body("invalid number"),
    };
    let output = Command::new("head").arg("-n").arg(n.to_string()).arg("file.txt").output().expect("failed");
    HttpResponse::Ok().body(String::from_utf8_lossy(&output.stdout).to_string())
}
