use actix_web::{web, HttpResponse};

#[derive(serde::Deserialize)]
struct CommentReq { text: String }

// Vulnerable: XSS from JSON body in HTML response
async fn handler(body: web::Json<CommentReq>) -> HttpResponse {
    let param = body.text.clone();
    let html = format!("<div class='comment'>{}</div>", param);
    HttpResponse::Ok().content_type("text/html").body(html)
}
