const std = @import("std");
const sce = @import("sce");

const LibSce = @import("lib.zig");
const abi = @import("abi.zig");

const log = std.log.scoped(.libsce_info);

/// Get's the content ID of the passed certified file-wrapped SELF
export fn libsce_get_content_id(libsce: *LibSce, cf_data_ptr: [*]u8, cf_data_len: usize, out_ptr: *sce.ContentId) abi.ErrorType {
    const content_id = getContentId(libsce, cf_data_ptr[0..cf_data_len]) catch |err| {
        return @intFromError(err);
    };

    if (content_id) |read_content_id| {
        @memcpy(out_ptr, &read_content_id);

        return abi.NoError;
    }

    return abi.NoContentIdError;
}

fn getContentId(libsce: *LibSce, cf_data: []u8) !?sce.ContentId {
    const allocator = libsce.gpa.allocator();

    // Read the certified file
    const certified_file = try sce.certified_file.read(allocator, cf_data, .none, libsce.system_keyset, libsce.npdrm_keyset, true);
    defer certified_file.deinit(allocator);

    switch (certified_file) {
        inline else => |read| {
            // Pull the SELF contents
            const contents: sce.certified_file.Contents = read.contents;

            // If the contents are not a signed ELF, error out
            if (contents != .signed_elf) {
                log.err("Unable to handle CF with contents of {s}", .{@tagName(contents)});
                return error.NotSignedElf;
            }

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

/// Gets whether the SELF file is an NPDRM application or not
export fn libsce_is_self_npdrm(libsce: *LibSce, cf_data_ptr: [*]u8, cf_data_len: usize, out_ptr: *abi.Bool32) abi.ErrorType {
    out_ptr.* = abi.Bool32.init(isEbootNpdrm(libsce, cf_data_ptr[0..cf_data_len]) catch |err| {
        return @intFromError(err);
    });

    return abi.NoError;
}

fn isEbootNpdrm(libsce: *LibSce, cf_data: []u8) !bool {
    const allocator = libsce.gpa.allocator();

    // Read the certified file
    const certified_file = try sce.certified_file.read(allocator, cf_data, .none, libsce.system_keyset, libsce.npdrm_keyset, true);
    defer certified_file.deinit(allocator);

    switch (certified_file) {
        inline else => |read| {
            // Pull the SELF contents
            const contents: sce.certified_file.Contents = read.contents;

            // If the contents are not a signed ELF, error out
            if (contents != .signed_elf) {
                log.err("Unable to handle CF with contents of {s}", .{@tagName(contents)});
                return error.NotSignedElf;
            }

            const self = contents.signed_elf;

            return switch (self.program_identification_header.program_type) {
                .application => false,
                .npdrm_application => true,
                else => {
                    log.err("Unable to handle program type of {s}", .{@tagName(self.program_identification_header.program_type)});
                    return error.UnableToHandleProgramType;
                },
            };
        },
    }
}
