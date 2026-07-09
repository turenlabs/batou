use actix_web::{web, HttpResponse};
use std::collections::HashMap;
use std::path::PathBuf;

// Vulnerable: Path traversal via async write to user path
async fn handler(form: web::Form<HashMap<String, String>>) -> HttpResponse {
    let param = form.get("name").unwrap_or(&String::new()).clone();
    let data = form.get("data").unwrap_or(&String::new()).clone();
    let path = PathBuf::from("/uploads").join(&param);
    tokio::fs::write(&path, data.as_bytes()).await.unwrap();
    HttpResponse::Ok().body("saved")
}
