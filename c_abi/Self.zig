const std = @import("std");
const sce = @import("sce");

const abi = @import("abi.zig");
const LibSce = @import("LibSce.zig");

const Self = @This();

const log = std.log.scoped(.c_abi_self);

certified_file: sce.certified_file.CertifiedFile,
cf_data: []u8,

export fn libsce_self_load_rap(
    libsce: *LibSce,
    cf_data_ptr: [*]u8,
    cf_data_len: usize,
    rap_data: *const [0x10]u8,
    out_ptr: **Self,
) abi.ErrorType {
    out_ptr.* = loadSelf(
        libsce,
        libsce.thread_safe_allocator.allocator(),
        cf_data_ptr[0..cf_data_len],
        .{ .rap = rap_data.* },
        false,
    ) catch |err| {
        return @intFromError(err);
    };

    return abi.NoError;
}

export fn libsce_self_load_rif(
    libsce: *LibSce,
    cf_data_ptr: [*]u8,
    cf_data_len: usize,
    rif_data_ptr: [*]const u8,
    rif_data_len: usize,
    act_dat_data_ptr: [*]const u8,
    act_dat_data_len: usize,
    idps: *const [0x10]u8,
    little_endian: abi.Bool32,
    out_ptr: **Self,
) abi.ErrorType {
    var rif_reader = std.io.fixedBufferStream(rif_data_ptr[0..rif_data_len]);
    var act_dat_reader = std.io.fixedBufferStream(act_dat_data_ptr[0..act_dat_data_len]);
    const endian: std.builtin.Endian = if (little_endian.toBool()) .little else .big;

    const rif = sce.RightsInformationFile.read(rif_reader.reader(), endian) catch |err| {
        return @intFromError(err);
    };

    const act_dat = sce.ActivationData.read(act_dat_reader.reader(), endian) catch |err| {
        return @intFromError(err);
    };

    out_ptr.* = loadSelf(
        libsce,
        libsce.thread_safe_allocator.allocator(),
        cf_data_ptr[0..cf_data_len],
        .{
            .rif = .{
                .rif = rif,
                .act_dat = act_dat,
                .idps = idps.*,
            },
        },
        false,
    ) catch |err| {
        return @intFromError(err);
    };

    return abi.NoError;
}

export fn libsce_self_load(
    libsce: *LibSce,
    cf_data_ptr: [*]u8,
    cf_data_len: usize,
    header_only: abi.Bool32,
    out_ptr: **Self,
) abi.ErrorType {
    out_ptr.* = loadSelf(
        libsce,
        libsce.thread_safe_allocator.allocator(),
        cf_data_ptr[0..cf_data_len],
        .none,
        header_only.toBool(),
    ) catch |err| {
        return @intFromError(err);
    };

    return abi.NoError;
}

export fn libsce_self_get_load_status(self: *const Self) sce.certified_file.CertifiedFile.LoadType {
    return self.certified_file;
}

export fn libsce_self_needs_npdrm_license(self: *const Self) abi.Bool32 {
    const contents = self.certified_file.contents().signed_elf;

    if (contents.program_identification_header.program_type != .npdrm_application)
        return .false;

    for (contents.supplemental_headers) |supplemental_header| {
        switch (supplemental_header) {
            .ps3_npdrm => |ps3_npdrm| {
                // We only actually need an NPDRM license if the DRM type is `local`. `free` DRM applications use a static key.
                return abi.Bool32.init(ps3_npdrm.drm_type == .local);
            },
            else => {},
        }
    }

    return .false;
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

export fn libsce_self_extract_to_elf(libsce: *LibSce, self: *Self, out_ptr_ptr: *[*]u8, out_len_ptr: *usize) abi.ErrorType {
    const elf = extractSelf(self, libsce.thread_safe_allocator.allocator()) catch |err| {
        return @intFromError(err);
    };

    out_ptr_ptr.* = elf.ptr;
    out_len_ptr.* = elf.len;

    return abi.NoError;
}

export fn libsce_self_get_digest(self: *Self, out_ptr: *[0x14]u8) abi.Bool32 {
    const contents = self.certified_file.contents().signed_elf;

    for (contents.supplemental_headers) |supplemental_header| {
        switch (supplemental_header) {
            .ps3_elf_digest => |ps3_elf_digest| {
                switch (ps3_elf_digest) {
                    .large => |large| {
                        out_ptr.* = large.elf_digest;
                        return .true;
                    },
                    .small => |small| {
                        out_ptr.* = small.constant_or_elf_digsest;
                        return .true;
                    },
                }
            },
            else => {},
        }
    }

    return .false;
}

export fn libsce_self_destroy(libsce: *LibSce, self: *Self) void {
    const allocator = libsce.thread_safe_allocator.allocator();

    self.certified_file.deinit(allocator);

    allocator.destroy(self);
}

fn extractSelf(self: *Self, allocator: std.mem.Allocator) ![]u8 {
    const file_size = self.certified_file.header().file_size;

    if (file_size > std.math.maxInt(usize)) {
        log.err("SELF file is too big for the current system. Size is {d} bytes.", .{file_size});
    }

    const elf = try allocator.alloc(u8, @intCast(file_size));
    errdefer allocator.free(elf);

    // Fill the ELF with zeroes, any unused bytes should be zero
    @memset(elf, 0);

    var stream = std.io.fixedBufferStream(elf);

    try sce.unself.extractSelfToElf(
        self.cf_data,
        &self.certified_file,
        stream.seekableStream(),
        stream.writer(),
    );

    return elf;
}

fn loadSelf(
    libsce: *LibSce,
    allocator: std.mem.Allocator,
    cf_data: []u8,
    license_data: sce.certified_file.LicenseData,
    header_only: bool,
) !*Self {
    const certified_file = try sce.certified_file.read(allocator, cf_data, license_data, libsce.system_keyset, libsce.npdrm_keyset, header_only);
    errdefer certified_file.deinit(allocator);

    // Make sure the contents of the (f)CF are actually a SELF file
    if (certified_file.contents() != .signed_elf)
        return error.NotSignedElf;

    const ret = try allocator.create(Self);
    errdefer allocator.destroy(ret);

    ret.* = .{
        .certified_file = certified_file,
        .cf_data = cf_data,
    };

    return ret;
}
