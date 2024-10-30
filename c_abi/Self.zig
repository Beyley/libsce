const std = @import("std");
const sce = @import("sce");

const abi = @import("abi.zig");
const LibSce = @import("lib.zig");

const Self = @This();

certified_file: sce.certified_file.CertifiedFile,

export fn libsce_self_load(libsce: *LibSce, cf_data_ptr: [*]u8, cf_data_len: usize, out_ptr: **Self) abi.ErrorType {
    const self = loadSelf(libsce, libsce.gpa.allocator(), cf_data_ptr[0..cf_data_len], .none) catch |err| {
        return @intFromError(err);
    };

    out_ptr.* = self;

    return abi.NoError;
}

fn loadSelf(libsce: *const LibSce, allocator: std.mem.Allocator, cf_data: []u8, license_data: sce.certified_file.LicenseData) !*Self {
    const certified_file = try sce.certified_file.read(allocator, cf_data, license_data, libsce.system_keyset, libsce.npdrm_keyset, false);
    errdefer certified_file.deinit(allocator);

    // Make sure the contents of the (f)CF are actually a SELF file
    if (certified_file.contents() != .signed_elf)
        return error.NotSignedElf;

    const ret = try allocator.create(Self);
    errdefer allocator.destroy(ret);

    ret.* = .{ .certified_file = certified_file };

    return ret;
}

export fn libsce_self_get_load_status(self: *const Self) sce.certified_file.CertifiedFile.LoadType {
    return self.certified_file;
}

export fn libsce_self_is_npdrm_application(self: *const Self) abi.Bool32 {
    const contents = self.certified_file.contents().signed_elf;

    return abi.Bool32.init(contents.program_identification_header.program_type == .npdrm_application);
}

export fn libsce_self_get_content_id(self: *const Self, out_ptr: *sce.ContentId) abi.Bool32 {
    const contents = self.certified_file.contents().signed_elf;

    for (contents.supplemental_headers) |supplemental_header| {
        switch (supplemental_header) {
            .ps3_npdrm => |ps3_npdrm| {
                out_ptr.* = ps3_npdrm.content_id;
                return .true;
            },
            else => {},
        }
    }

    return .false;
}

export fn libsce_self_destroy(libsce: *LibSce, self: *Self) abi.ErrorType {
    const allocator = libsce.gpa.allocator();

    self.certified_file.deinit(allocator);

    allocator.destroy(self);

    return abi.NoError;
}
