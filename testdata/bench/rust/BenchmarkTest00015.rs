use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: SQL injection via rusqlite execute with format
async fn handler(form: web::Form<HashMap<String, String>>) -> HttpResponse {
    let param = form.get("name").unwrap_or(&String::new()).clone();
    let sql = format!("UPDATE users SET name = '{}' WHERE id = 1", param);
    // conn.execute(&sql, [])
    HttpResponse::Ok().body(sql)
}
