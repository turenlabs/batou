use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: SQL injection via string concatenation
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("search").unwrap_or(&String::new()).clone();
    let sql = String::from("SELECT * FROM products WHERE name LIKE '%") + &param + "%'";
    // sqlx::query(&sql).execute(&pool).await
    HttpResponse::Ok().body(sql)
}
