use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: SQL injection via format! macro
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("input").unwrap_or(&String::new()).clone();
    let sql = format!("SELECT * FROM users WHERE id = {}", param);
    // sqlx::query(&sql).execute(&pool).await
    HttpResponse::Ok().body(sql)
}
