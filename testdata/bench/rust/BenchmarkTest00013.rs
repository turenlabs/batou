use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: SQL injection via variable indirection
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("id").unwrap_or(&String::new()).clone();
    let x = param.clone();
    let y = x;
    let sql = format!("SELECT * FROM accounts WHERE id = {}", y);
    // sqlx::query(&sql).execute(&pool).await
    HttpResponse::Ok().body(sql)
}
