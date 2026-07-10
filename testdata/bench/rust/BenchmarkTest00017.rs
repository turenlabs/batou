use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: SQL injection via to_string propagation
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("term").unwrap_or(&String::new()).clone();
    let s = param.to_string();
    let sql = format!("SELECT * FROM products WHERE description LIKE '%{}%'", s);
    // sqlx::query(&sql).execute(&pool).await
    HttpResponse::Ok().body(sql)
}
