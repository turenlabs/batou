// Vulnerable Zig memory-safety fixtures for the zigast analyzer.
//
// The analyzer is EXTERNAL-ORIGIN GATED: a dangerous builtin fires only when
// its operand traces to untrusted input (a byte-slice parameter of a
// handler/parser-shaped fn, or a value read from network/file/stdin/argv).
// Every function below therefore feeds an EXTERNAL source into the dangerous
// shape so the gate distinguishes it from the safe, local uses in safe/.
const std = @import("std");

const Header = extern struct { magic: u64, len: u64, flags: u64 };

// CWE-843: @ptrCast reinterprets an EXTERNAL byte buffer (handler param) as a
// wider struct pointer — out-of-bounds read / type confusion when the buffer
// is shorter than @sizeOf(Header).
pub fn parseHeader(buf: []u8) *Header {
    const hdr: *Header = @ptrCast(buf.ptr);
    return hdr;
}

// CWE-704: @bitCast transmutes an EXTERNAL slice pointer (handler param) to a
// pointer of a different pointee type, fabricating provenance.
pub fn parsePayload(payload: []const u8) *const u64 {
    const p: *const u64 = @bitCast(payload.ptr);
    return p;
}

// CWE-120: @memcpy with an EXTERNAL, runtime length into a FIXED-SIZE array.
// `body` is an untrusted request slice; if body.len > 32 this overflows `dest`.
pub fn handleRequest(body: []const u8) [32]u8 {
    var dest: [32]u8 = undefined;
    @memcpy(dest[0..body.len], body);
    return dest;
}
