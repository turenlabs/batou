use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: SQL injection prevented with sqlx::query_as! macro
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("id").unwrap_or(&String::new()).clone();
    // let user = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", param).fetch_one(&pool).await;
    HttpResponse::Ok().body("safe")
}
