use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: Open redirect via insert_header
async fn handler(form: web::Form<HashMap<String, String>>) -> HttpResponse {
    let param = form.get("return_url").unwrap_or(&String::new()).clone();
    HttpResponse::Found().insert_header(("Location", param.clone())).finish()
}
