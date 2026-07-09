use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: SQL injection prevented with sqlx::query! macro
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("name").unwrap_or(&String::new()).clone();
    // sqlx::query!("SELECT * FROM users WHERE name = $1", param).fetch_one(&pool).await
    HttpResponse::Ok().body("safe")
}
