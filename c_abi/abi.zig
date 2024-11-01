const std = @import("std");

pub const ErrorType = i32;
pub const NoError: ErrorType = -1;

pub const Bool32 = enum(u32) {
    false = 0,
    true = 1,

    pub fn init(val: bool) Bool32 {
        return if (val) .true else .false;
    }

    pub fn toBool(val: Bool32) bool {
        return val == .true;
    }
};

export fn libsce_error_name(err: ErrorType) [*:0]const u8 {
    if (err == NoError) return "No Error";

    return @errorName(@errorFromInt(@as(std.meta.Int(.unsigned, @bitSizeOf(anyerror)), @intCast(err))));
}
