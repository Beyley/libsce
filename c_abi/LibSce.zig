const std = @import("std");
const builtin = @import("builtin");
const sce = @import("sce");

const abi = @import("abi.zig");

const LibSce = @This();
const GPA = std.heap.GeneralPurposeAllocator(.{ .thread_safe = false });
const log = std.log.scoped(.c_abi_infra);

const LogCallback = fn (scope: [*:0]const u8, level: u32, message: [*:0]const u8) callconv(.C) void;

comptime {
    _ = @import("Self.zig");
    _ = @import("abi.zig");
}

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
thread_safe_allocator: std.heap.ThreadSafeAllocator,
npdrm_keyset: sce.npdrm_keyset.KeySet,
system_keyset: sce.system_keyset.KeySet,

export fn libsce_set_log_callback(callback: ?*const LogCallback) void {
    log_callback = callback;
}

/// Create's an instance of libsce
export fn libsce_create(out: **LibSce) abi.ErrorType {
    out.* = init() catch |err| {
        return @intFromError(err);
    };

    return abi.NoError;
}

/// Frees memory returned by libsce
export fn libsce_free_memory(libsce: *LibSce, elf_ptr: [*]const u8, elf_len: usize) void {
    libsce.thread_safe_allocator.allocator().free(elf_ptr[0..elf_len]);
}

/// Destroy's an instance of libsce
export fn libsce_destroy(libsce: *LibSce) abi.ErrorType {
    // Deinit the objects stored inside
    libsce.npdrm_keyset.deinit();
    libsce.system_keyset.deinit();

    // Copy the GPA to the stack, since we are freeing the data which owns it
    var gpa = libsce.gpa;

    // Free using the stack-copied GPA
    gpa.allocator().destroy(libsce);

    // Check for leaks
    if (gpa.deinit() == .leak) {
        log.err("Memory leak encountered in libsce, this is non-fatal, but should be reported!", .{});
        return @intFromError(error.MemoryLeak);
    }

    return abi.NoError;
}

fn init() !*LibSce {
    const libsce = blk: {
        // Create a temporary stack-allocated GPA
        var gpa: GPA = .{};
        errdefer _ = gpa.deinit();

        const libsce = try gpa.allocator().create(LibSce);

        libsce.gpa = gpa;

        break :blk libsce;
    };
    // If there's a failure, copy the GPA to the stack and deinit the owning pointer
    errdefer {
        var gpa = libsce.gpa;
        gpa.allocator().destroy(libsce);
    }

    // Create an allocator based on the heap-owned GPA
    const allocator = libsce.gpa.allocator();

    var npdrm_keyset = try sce.npdrm_keyset.read(allocator, @embedFile("npdrm_keys_file"));
    errdefer npdrm_keyset.deinit();

    var system_keyset = try sce.system_keyset.read(allocator, @embedFile("system_keys_file"));
    errdefer system_keyset.deinit();

    libsce.* = .{
        .gpa = libsce.gpa,
        .npdrm_keyset = npdrm_keyset,
        .system_keyset = system_keyset,
        .thread_safe_allocator = .{ .child_allocator = allocator },
    };

    return libsce;
}
