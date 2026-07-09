use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: SQL injection prevented with parameterized query bind
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("input").unwrap_or(&String::new()).clone();
    // sqlx::query("SELECT * FROM users WHERE id = $1").bind(&param).fetch_one(&pool).await
    HttpResponse::Ok().body("safe")
}
