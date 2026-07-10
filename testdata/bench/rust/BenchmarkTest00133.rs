use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: Open redirect via format! URL construction
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("host").unwrap_or(&String::new()).clone();
    let url = format!("https://{}/callback", param);
    HttpResponse::Found().append_header(("Location", url.as_str())).finish()
}
