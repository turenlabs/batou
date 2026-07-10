use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: SQL injection via push_str taint propagation
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("name").unwrap_or(&String::new()).clone();
    let mut sql = String::from("SELECT * FROM users WHERE name = '");
    sql.push_str(&param);
    sql.push_str("'");
    // sqlx::query(&sql).execute(&pool).await
    HttpResponse::Ok().body(sql)
}
