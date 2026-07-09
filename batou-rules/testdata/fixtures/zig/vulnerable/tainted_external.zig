// External-tainted memory-safety fixtures: each dangerous shape is fed a value
// that flows from an explicit EXTERNAL source (argv, file/socket read, stdin).
// These prove the external-origin gate FIRES on genuinely untrusted data —
// distinguishing it from the local/comptime uses in safe/, which do not fire.
const std = @import("std");

const Packet = extern struct { kind: u32, length: u32 };

// argv -> @ptrCast: reinterpret a process-argument byte buffer as a struct
// pointer. The bytes are fully attacker-controlled (command line).
pub fn fromArgv(allocator: std.mem.Allocator) !*Packet {
    const args = try std.process.argsAlloc(allocator);
    const raw = args[1];
    const pkt: *Packet = @ptrCast(raw.ptr);
    return pkt;
}

// socket/file read -> @memcpy into a fixed buffer with the EXTERNAL read length.
// `n` is the number of bytes read from an untrusted descriptor; copying `n`
// bytes into a 64-byte buffer overflows when the peer sends more than 64.
pub fn handleConn(fd: std.posix.fd_t) !void {
    var scratch: [4096]u8 = undefined;
    const n = try std.posix.read(fd, scratch[0..]);
    var frame: [64]u8 = undefined;
    @memcpy(frame[0..n], scratch[0..n]);
}
