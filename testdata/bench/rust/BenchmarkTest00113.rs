use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: Unsafe YAML deserialization from user input
async fn handler(form: web::Form<HashMap<String, String>>) -> HttpResponse {
    let param = form.get("yaml").unwrap_or(&String::new()).clone();
    let value: serde_yaml::Value = serde_yaml::from_str(&param).unwrap();
    HttpResponse::Ok().json(format!("{:?}", value))
}
