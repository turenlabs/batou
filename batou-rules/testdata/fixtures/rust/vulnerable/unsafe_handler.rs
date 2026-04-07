use actix_web::{web, HttpResponse, HttpRequest};

// RS-007: unwrap() in web handler
#[get("/user/{id}")]
async fn get_user(req: HttpRequest, path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    let user = db.find_user(&id).await.unwrap();
    HttpResponse::Ok().json(user)
}

// RS-007: expect() in web handler
#[post("/upload")]
async fn upload_file(req: HttpRequest, body: web::Json<UploadRequest>) -> HttpResponse {
    let data = body.into_inner();
    let file = std::fs::read(&data.path).expect("file must exist");
    HttpResponse::Ok().body(file)
}

// RS-001: Unsafe block with transmute
pub fn cast_bytes(data: &[u8]) -> &[u32] {
    unsafe {
        std::mem::transmute(data)
    }
}

// RS-009: from_raw_parts
pub fn slice_from_ptr(ptr: *const u8, len: usize) -> &'static [u8] {
    unsafe {
        std::slice::from_raw_parts(ptr, len)
    }
}
