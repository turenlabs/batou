use actix_web::{web, HttpResponse};
use std::collections::HashMap;

// Safe: Regex validated domain prevents SSRF
async fn handler(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let param = query.get("subdomain").unwrap_or(&String::new()).clone();
    let re = regex::Regex::new(r"^[a-z]+$").unwrap();
    if !re.is_match(&param) {
        return HttpResponse::BadRequest().body("invalid subdomain");
    }
    let url = format!("https://{}.example.com/api", param);
    let resp = reqwest::get(&url).await.unwrap();
    HttpResponse::Ok().body(resp.text().await.unwrap_or_default())
}
