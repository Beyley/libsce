//! Simple providers for libc functions

// NOTE: we *cannot* use @memset and @memcpy because they try to call into libc, which is an infinite loop!!!

pub export fn memcpy(dst: [*]u8, src: [*]u8, n: c_ulong) void {
    for (dst[0..n], src[0..n]) |*d, s| {
        d.* = s;
    }
}

pub export fn memset(dst: [*]u8, val: c_int, n: c_ulong) void {
    for (dst[0..n]) |*d| {
        d.* = @intCast(val);
    }
}
