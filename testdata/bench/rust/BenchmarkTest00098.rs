use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: Askama typed template auto-escapes
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let _param = query.get("name").unwrap_or(&String::new()).clone();
    // #[derive(askama::Template)]
    // #[template(path = "page.html")]
    // struct PageTemplate { name: String }
    // let tmpl = PageTemplate { name: param };
    HttpResponse::Ok().body("safe template render")
}
