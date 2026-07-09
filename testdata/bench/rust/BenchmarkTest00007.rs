use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: SQL injection via diesel::sql_query with format
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("id").unwrap_or(&String::new()).clone();
    let sql = format!("DELETE FROM records WHERE id = {}", param);
    // diesel::sql_query(&sql).execute(&conn)
    HttpResponse::Ok().body(sql)
}
