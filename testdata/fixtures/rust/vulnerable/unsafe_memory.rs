// Vulnerable Rust code - unsafe memory operations
use std::mem;
use std::slice;

// RS-001: Unsafe block with transmute
fn dangerous_cast(val: f64) -> u64 {
    unsafe {
        std::mem::transmute(val)
    }
}

// RS-009: from_raw_parts with unchecked length
fn make_slice(ptr: *const u8, len: usize) -> &'static [u8] {
    unsafe {
        slice::from_raw_parts(ptr, len)
    }
}

// RS-009: mem::forget leaking resource
fn leak_handle(handle: FileHandle) {
    std::mem::forget(handle);
    // handle's Drop never runs, file descriptor leaks
}

// RS-009: Box::from_raw double-free risk
fn reclaim_twice(ptr: *mut Widget) {
    let w1 = unsafe { Box::from_raw(ptr) };
    let w2 = unsafe { Box::from_raw(ptr) }; // double free!
    drop(w1);
    drop(w2);
}

// RS-009: Raw pointer operations
fn raw_copy(src: *const u8, dst: *mut u8, count: usize) {
    unsafe {
        std::ptr::copy(src, dst, count);
    }
}

struct FileHandle { fd: i32 }
impl Drop for FileHandle {
    fn drop(&mut self) { /* close fd */ }
}
struct Widget { id: u32 }
