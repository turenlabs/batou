const std = @import("std");

// Memory copy with tainted source data
pub fn copyUserData(dest: []u8, user_input: []const u8) void {
    @memcpy(dest, user_input);
}

// Memory set with tainted value
pub fn fillBuffer(buf: []u8, user_byte: u8) void {
    @memset(buf, user_byte);
}

// Forward copy with tainted source
pub fn forwardCopy(dest: []u8, user_data: []const u8) void {
    std.mem.copyForwards(u8, dest, user_data);
}

// Backward copy with tainted source
pub fn backwardCopy(dest: []u8, user_data: []const u8) void {
    std.mem.copyBackwards(u8, dest, user_data);
}
