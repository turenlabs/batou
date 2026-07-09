use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: SQL injection prevented with tokio_postgres parameterized query
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("email").unwrap_or(&String::new()).clone();
    // client.query("SELECT * FROM users WHERE email = $1", &[&param]).await
    HttpResponse::Ok().body("safe")
}
