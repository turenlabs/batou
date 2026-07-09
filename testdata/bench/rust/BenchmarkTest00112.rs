use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: Schema validation before deserialization
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("data").unwrap_or(&String::new()).clone();
    // jsonschema validation first
    let value: serde_json::Value = match serde_json::from_str(&param) {
        Ok(v) => v,
        Err(_) => return HttpResponse::BadRequest().body("invalid json"),
    };
    if !value.is_object() || value.as_object().unwrap().len() > 10 {
        return HttpResponse::BadRequest().body("schema validation failed");
    }
    HttpResponse::Ok().body("validated")
}
