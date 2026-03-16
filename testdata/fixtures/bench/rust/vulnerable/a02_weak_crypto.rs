// Source: CWE-119 - Unsafe memory operations via transmute in Rust
// Expected: BATOU-RS
// OWASP: A06:2021 - Vulnerable and Outdated Components

use std::mem;

fn dangerous_cast(input: &[u8]) -> u64 {
    unsafe {
        let ptr = input.as_ptr() as *const u64;
        let val: u64 = mem::transmute(*ptr);
        val
    }
}

fn main() {
    let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
    println!("{}", dangerous_cast(&data));
}
