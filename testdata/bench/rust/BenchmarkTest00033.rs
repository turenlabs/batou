use actix_web::{web, HttpResponse};

#[derive(serde::Deserialize)]
struct ExecReq { command: String }

// Vulnerable: Command injection from JSON body via match
async fn handler(body: web::Json<ExecReq>) -> HttpResponse {
    let param = body.command.clone();
    let cmd = match param.as_str() {
        _ => param.clone(),
    };
    let output = std::process::Command::new("sh").arg("-c").arg(&cmd).output().expect("failed");
    HttpResponse::Ok().body(String::from_utf8_lossy(&output.stdout).to_string())
}
