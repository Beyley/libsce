const std = @import("std");
const builtin = @import("builtin");
const sce = @import("sce");

const abi = @import("abi.zig");

const LibSce = @This();
const GPA = std.heap.GeneralPurposeAllocator(.{});
const log = std.log.scoped(.libsce_infra);

const LogCallback = fn (scope: [*:0]const u8, level: u32, message: [*:0]const u8) callconv(.C) void;

pub const std_options: std.Options = .{
    .logFn = struct {
        pub fn logFn(
            comptime message_level: std.log.Level,
            comptime scope: @Type(.enum_literal),
            comptime format: []const u8,
            args: anytype,
        ) void {
            if (log_callback) |log_fn| {
                var buf: [4096:0]u8 = undefined;
                const message = std.fmt.bufPrintZ(&buf, format, args) catch return;

                log_fn(@tagName(scope), @intFromEnum(message_level), message);
            } else {
                std.log.defaultLog(message_level, scope, format, args);
            }
        }
    }.logFn,
    .log_level = if (builtin.mode == .Debug) .debug else .info,
};

var log_callback: ?*const LogCallback = null;

gpa: GPA = .{},
npdrm_keyset: sce.npdrm_keyset.KeySet,
system_keyset: sce.system_keyset.KeySet,

export fn libsce_set_log_callback(callback: *const LogCallback) void {
    log_callback = callback;
}

/// Create's an instance of libsce
export fn libsce_create(out: **LibSce) abi.ErrorType {
    out.* = init() catch |err| {
        return @intFromError(err);
    };

    return abi.NoError;
}

fn init() !*LibSce {
    var gpa: GPA = .{};
    errdefer _ = gpa.deinit();

    const allocator = gpa.allocator();

    const libsce = try allocator.create(LibSce);
    errdefer allocator.destroy(libsce);

    var npdrm_keyset = try sce.npdrm_keyset.read(allocator, @embedFile("npdrm_keys_file"));
    errdefer npdrm_keyset.deinit();

    var system_keyset = try sce.system_keyset.read(allocator, @embedFile("system_keys_file"));
    errdefer system_keyset.deinit();

    libsce.* = .{
        .gpa = gpa,
        .npdrm_keyset = npdrm_keyset,
        .system_keyset = system_keyset,
    };

    return libsce;
}

/// Destroy's an instance of libsce
export fn libsce_destroy(libsce: *LibSce) abi.ErrorType {
    var gpa = libsce.gpa;
    const allocator = gpa.allocator();

    libsce.npdrm_keyset.deinit();
    libsce.system_keyset.deinit();

    allocator.destroy(libsce);

    if (gpa.deinit() == .leak) {
        log.err("Memory leak encountered in libsce, this is non-fatal, but should be reported!", .{});
        return @intFromError(error.MemoryLeak);
    }

    return abi.NoError;
}

export fn libsce_error_name(err: abi.ErrorType) [*:0]const u8 {
    if (err == abi.NoError) return "No Error";

    return @errorName(@errorFromInt(@as(std.meta.Int(.unsigned, @bitSizeOf(anyerror)), @intCast(err))));
}

comptime {
    _ = @import("info.zig");
}
