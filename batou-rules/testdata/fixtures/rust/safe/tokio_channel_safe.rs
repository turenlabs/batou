// Safe: bare RefCell/Borrow `borrow()` is the std trait method, NOT a tokio
// watch channel surface — the catalog deliberately does not model it, so this
// must NOT be flagged. A hardcoded command argument is likewise not tainted.
use std::cell::RefCell;
use std::process::Command;

fn use_refcell(cell: &RefCell<String>) {
    let val = cell.borrow().clone(); // std RefCell::borrow — not a channel recv
    let _ = Command::new("echo").arg(&val).output();
}

fn fixed_command() {
    let cmd = String::from("ls -la"); // hardcoded, no channel input
    let _ = Command::new("sh").arg("-c").arg(&cmd).output();
}
