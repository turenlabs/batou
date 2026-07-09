use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: Path traversal via write to user-controlled path
async fn handler(form: web::Form<HashMap<String, String>>) -> HttpResponse {
    let filename = form.get("filename").unwrap_or(&String::new()).clone();
    let data = form.get("content").unwrap_or(&String::new()).clone();
    let path = format!("/uploads/{}", filename);
    std::fs::write(&path, &data).unwrap();
    HttpResponse::Ok().body("uploaded")
}
