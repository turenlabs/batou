// Vulnerable: tainted data received from tokio async channels reaches an
// OS-command sink across the async-task boundary (CWE-78). Each receiver
// method models a distinct tokio::sync channel surface that the taint engine
// previously dropped (recv / try_recv / blocking_recv / recv_many /
// borrow_and_update). A producer task forwards attacker-controlled bytes over
// the channel; the worker here treats them as trusted and shells out.
use std::process::Command;
use tokio::sync::{mpsc, broadcast, watch};

// mpsc Receiver::recv() — canonical producer->worker channel handoff.
async fn worker_mpsc(mut rx: mpsc::Receiver<String>) {
    let cmd = rx.recv().await.unwrap();
    let _ = Command::new("sh").arg("-c").arg(&cmd).output();
}

// mpsc Receiver::try_recv() — non-blocking poll.
fn worker_try(mut rx: mpsc::Receiver<String>) {
    let cmd = rx.try_recv().unwrap();
    let _ = Command::new("sh").arg("-c").arg(&cmd).output();
}

// broadcast Receiver::blocking_recv() — sync receive in a blocking context.
fn worker_blocking(mut rx: broadcast::Receiver<String>) {
    let cmd = rx.blocking_recv().unwrap();
    let _ = Command::new("bash").arg("-c").arg(&cmd).output();
}

// watch Receiver::borrow_and_update() — read latest published value.
fn worker_watch(mut rx: watch::Receiver<String>) {
    let cmd = rx.borrow_and_update().clone();
    let _ = Command::new("sh").arg("-c").arg(&cmd).output();
}
