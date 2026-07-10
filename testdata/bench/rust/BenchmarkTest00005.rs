use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Vulnerable: SQL injection via format! INSERT
async fn handler(form: web::Form<HashMap<String, String>>) -> HttpResponse {
    let param = form.get("username").unwrap_or(&String::new()).clone();
    let sql = format!("INSERT INTO logs (user, action) VALUES ('{}', 'login')", param);
    // sqlx::query(&sql).execute(&pool).await
    HttpResponse::Ok().body(sql)
}
