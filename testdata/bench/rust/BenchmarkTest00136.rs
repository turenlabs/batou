use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: Regex validated path prevents redirect injection
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("path").unwrap_or(&String::new()).clone();
    let re = regex::Regex::new(r"^/[a-zA-Z0-9/]+$").unwrap();
    if !re.is_match(&param) {
        return HttpResponse::BadRequest().body("invalid path");
    }
    HttpResponse::Found().append_header(("Location", param.as_str())).finish()
}
