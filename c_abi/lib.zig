const std = @import("std");
const builtin = @import("builtin");
const sce = @import("sce");

const LibSce = @This();
const GPA = std.heap.GeneralPurposeAllocator(.{});

const ErrorType = i32;
const NoError: ErrorType = -1;
const NoContentIdError: ErrorType = -2;

const log = std.log.scoped(.libsce);

gpa: GPA = .{},
npdrm_keyset: sce.npdrm_keyset.KeySet,
system_keyset: sce.system_keyset.KeySet,

const LogCallback = fn (scope: [*:0]const u8, level: u32, message: [*:0]const u8) callconv(.C) void;

var log_callback: ?*const LogCallback = null;

export fn libsce_set_log_callback(callback: *const LogCallback) void {
    log_callback = callback;
}

/// Create's an instance of libsce
export fn libsce_create(out: **LibSce) ErrorType {
    out.* = init() catch |err| {
        return @intFromError(err);
    };

    return NoError;
}

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

pub const std_options: std.Options = .{
    .logFn = logFn,
    .log_level = if (builtin.mode == .Debug) .debug else .info,
};

/// Destroy's an instance of libsce
export fn libsce_destroy(libsce: *LibSce) ErrorType {
    var gpa = libsce.gpa;
    const allocator = gpa.allocator();

    libsce.npdrm_keyset.deinit();
    libsce.system_keyset.deinit();

    allocator.destroy(libsce);

    if (gpa.deinit() == .leak) {
        return @intFromError(error.MemoryLeak);
    }

    return NoError;
}

/// Get's the content ID of the passed certified file-wrapped SELF
export fn libsce_get_content_id(libsce: *LibSce, cf_data_ptr: [*]u8, cf_data_len: usize, out_ptr: *sce.ContentId) ErrorType {
    const allocator = libsce.gpa.allocator();

    const cf_data = cf_data_ptr[0..cf_data_len];

    const content_id = libsce.getContentId(allocator, cf_data) catch |err| {
        return @intFromError(err);
    };

    if (content_id) |read_content_id| {
        @memcpy(out_ptr, &read_content_id);

        return NoError;
    }

    return @intFromError(error.NoContentId);
}

export fn libsce_error_name(err: ErrorType) [*:0]const u8 {
    if (err == NoError) return "No Error";

    return @errorName(@errorFromInt(@as(std.meta.Int(.unsigned, @bitSizeOf(anyerror)), @intCast(err))));
}

fn getContentId(libsce: LibSce, allocator: std.mem.Allocator, cf_data: []u8) !?sce.ContentId {
    // Read the certified file
    const certified_file = try sce.certified_file.read(allocator, cf_data, .none, libsce.system_keyset, libsce.npdrm_keyset, true);
    defer certified_file.deinit(allocator);

    switch (certified_file) {
        inline else => |read| {
            // Pull the SELF contents
            const contents: sce.certified_file.Contents = read.contents;

            // If the contents are not a signed ELF, error out
            if (contents != .signed_elf)
                return error.NotSignedElf;

            const self = contents.signed_elf;

            // Iterate through the supplemental headers, looking for the NPDRM header, which is what contains the content ID
            for (self.supplemental_headers) |supplemental_header| {
                switch (supplemental_header) {
                    .ps3_npdrm => |ps3_npdrm| return ps3_npdrm.content_id,
                    .vita_npdrm => |vita_npdrm| return vita_npdrm.content_id,
                    else => {},
                }
            }
        },
    }

    return null;
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
