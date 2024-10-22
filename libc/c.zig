//! Simple fill-ins for libc functions, since we dont want a hard dependency on libc

pub export fn libc_memcpy(dst: [*]u8, src: [*]u8, n: c_ulong) void {
    @memcpy(dst[0..n], src[0..n]);
}

pub export fn libc_memset(dst: [*]u8, val: c_int, n: c_ulong) void {
    @memset(dst[0..n], @intCast(val));
}
