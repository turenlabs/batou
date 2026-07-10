use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: UUID-based filename prevents traversal
async fn handler(form: web::Form<HashMap<String, String>>) -> HttpResponse {
    let _param = form.get("filename").unwrap_or(&String::new()).clone();
    let data = form.get("content").unwrap_or(&String::new()).clone();
    let name = uuid::Uuid::new_v4().to_string();
    let path = format!("/uploads/{}", name);
    std::fs::write(&path, &data).unwrap();
    HttpResponse::Ok().body("uploaded")
}
