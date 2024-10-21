const std = @import("std");
const sce = @import("sce");

const LibSce = @This();
const GPA = std.heap.GeneralPurposeAllocator(.{});
const ContentId = [0x30]u8;

const ErrorType = i32;
const NoError: ErrorType = -1;
const NoContentIdError: ErrorType = -2;

gpa: GPA = .{},

/// Create's an instance of libsce
export fn libsce_create(out: **LibSce) ErrorType {
    out.* = init() catch |err| {
        return @intFromError(err);
    };

    return NoError;
}

/// Destroy's an instance of libsce
export fn libsce_destroy(libsce: *LibSce) ErrorType {
    var gpa = libsce.gpa;
    const allocator = gpa.allocator();

    allocator.destroy(libsce);

    if (gpa.deinit() == .leak) {
        return @intFromError(error.MemoryLeak);
    }

    return NoError;
}

/// Get's the content ID of the passed certified file-wrapped SELF
export fn libsce_get_content_id(libsce: *LibSce, cf_data_ptr: [*]u8, cf_data_len: usize, out_ptr: *ContentId) ErrorType {
    const allocator = libsce.gpa.allocator();

    const cf_data = cf_data_ptr[0..cf_data_len];

    const content_id = getContentId(allocator, cf_data) catch |err| {
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

fn getContentId(allocator: std.mem.Allocator, cf_data: []u8) !?ContentId {
    var system_keys = sce.system_keyset.KeySet.init(allocator);
    defer system_keys.deinit();
    var npdrm_keys = sce.npdrm_keyset.KeySet.init(allocator);
    defer npdrm_keys.deinit();

    // Read the certified file
    const certified_file = try sce.certified_file.read(allocator, cf_data, null, system_keys, npdrm_keys);
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

    libsce.* = .{
        .gpa = gpa,
    };

    return libsce;
}
