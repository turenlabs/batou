use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: SQL injection prevented with diesel filter
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("name").unwrap_or(&String::new()).clone();
    // users::table.filter(users::name.eq(&param)).first::<User>(&conn)
    HttpResponse::Ok().body("safe")
}
