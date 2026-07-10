use actix_web::{web, HttpResponse};
use std::collections::HashMap;
use std::process::Command;

// Safe: Enum conversion prevents arbitrary command execution
async fn handler(form: web::Form<HashMap<String, String>>) -> HttpResponse {
    let param = form.get("action").unwrap_or(&String::new()).clone();
    let (cmd, args) = match param.as_str() {
        "uptime" => ("uptime", vec![]),
        "whoami" => ("whoami", vec![]),
        "pwd" => ("pwd", vec![]),
        _ => return HttpResponse::BadRequest().body("not allowed"),
    };
    let output = Command::new(cmd).args(&args).output().expect("failed");
    HttpResponse::Ok().body(String::from_utf8_lossy(&output.stdout).to_string())
}
