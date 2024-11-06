const std = @import("std");

const sce = @import("sce.zig");

const ArrayListStreamSource = @import("ArrayListStreamSource.zig");

const certified_file = sce.certified_file;
const CertifiedFile = sce.certified_file.CertifiedFile;
const Self = sce.Self;

pub const Error = error{
    TemplateMissingContentId,
} || std.fs.File.WriteError || std.fs.File.SeekError || std.compress.zlib.Compressor(std.fs.File.Reader).Error || certified_file.Error;

pub const Template = struct {
    key_revision: u16 = 0xa,
    program_type: Self.ProgramIdentificationHeader.ProgramType,
    program_sceversion: u64 = 0x0001000000000000,
    program_authority_id: Self.ProgramAuthorityId = .{
        .console_generation = .ps3,
        .territory_id = 0x01,
        .program_id = 0x0000001000003,
    },
    program_vender_id: Self.ProgramVenderId = .{
        .guest_os_id = .lv2,
        .territory = 0x0100,
    },
    plaintext_capability: sce.PlaintextCapability = .{
        .ctrl_flag1 = 0,
        .unknown2 = 0,
        .unknown3 = 0,
        .unknown4 = 0,
        .unknown5 = 0,
        .unknown6 = 0,
        .unknown7 = 0,
        .unknown8 = 0,
    },
    encrypted_capability: sce.EncryptedCapability = .{
        .unknown1 = 0x00000000,
        .unknown2 = 0x00000000,
        .unknown3 = 0x00000000,
        .unknown4 = 0x00000000,
        .unknown5 = 0x00000000,
        .unknown6 = 0x0000003B,
        .unknown7 = 0x00000001,
        .unknown8 = 0x00040000,
    },
    required_system_version: u64 = 0x0003005500000000,
    content_id: ?sce.ContentId,
};

fn elfHeaderSize(elf_data: []const u8) !usize {
    var stream = std.io.fixedBufferStream(elf_data);

    const header = try std.elf.Header.read(&stream);

    return if (header.is_64) @sizeOf(std.elf.Elf64_Ehdr) else @sizeOf(std.elf.Elf32_Ehdr);
}

pub fn createSelfFromElf(allocator: std.mem.Allocator, elf_data: []const u8, template: Template) Error![]u8 {
    var stream: ArrayListStreamSource = .init(allocator);
    defer stream.deinit();

    const seekableStream = stream.seekableStream();
    const writer = stream.writer();

    const header: certified_file.Header = .{
        .file_offset = undefined, // TODO: fill this in
        .file_size = elf_data.len,
        .category = .signed_elf,
        .extended_header_size = undefined, // TODO: fill this in
        .key_revision = template.key_revision,
        .version = .ps3,
        .vita_data = null,
    };
    const endian = header.endianness();
    try seekableStream.seekTo(header.byteSize()); // seek past the header

    var extended_header: Self.ExtendedHeader = .{
        .version = .ps3,
        .program_identification_header_offset = stream.pos + Self.ExtendedHeader.byteSize(),
        .supplemental_header_offset = stream.pos + Self.ExtendedHeader.byteSize() + Self.ProgramIdentificationHeader.byteSize(),
        .elf_header_offset = undefined,
        .program_header_offset = undefined, // TODO: fill this in
        .section_header_offset = undefined, // TODO: fill this in
        .segment_extended_header_offset = undefined, // TODO: fill this in
        .version_header_offset = undefined, // TODO: fill this in
        .supplemental_header_size = undefined, // TODO: fill this in
        .padding = 0,
    };
    try seekableStream.seekBy(@intCast(Self.ExtendedHeader.byteSize()));

    const program_identification_header: Self.ProgramIdentificationHeader = .{
        .program_type = .application,
        .program_authority_id = template.program_authority_id,
        .program_sceversion = template.program_sceversion,
        .program_vender_id = template.program_vender_id,
        .padding = 0,
    };
    try seekableStream.seekTo(extended_header.program_identification_header_offset);
    try program_identification_header.write(writer, endian);

    extended_header.supplemental_header_size = blk: {
        const plaintext_capability_header: Self.SupplementalHeader = .{
            .plaintext_capability = template.plaintext_capability,
        };
        const ps3_elf_digest_header: Self.SupplementalHeader = .{
            .ps3_elf_digest = .{
                .large = .{
                    .constant = Self.ConstantDigest,
                    .elf_digest = @splat(0), // TODO: is this actually correct?
                    .required_system_version = template.required_system_version,
                },
            },
        };
        const ps3_npdrm_header: Self.SupplementalHeader = .{
            .ps3_npdrm = .{
                .version = 1,
                .drm_type = .local,
                .app_type = .executable,
                .content_id = template.content_id orelse return Error.TemplateMissingContentId,
                // TODO: this is apparently a digest of the aplication(?), lets actually do that, and not use zeroes
                .digest = .{0} ** 0x10,
                .cid_fn_hash = undefined, // TODO
                .header_hash = undefined, // TODO
                .limited_time_start = null,
                .limited_time_end = null,
            },
        };

        const base_supplemental_headers: []const Self.SupplementalHeader = &.{
            plaintext_capability_header,
            ps3_elf_digest_header,
        };
        const npdrm_supplemental_headers: []const Self.SupplementalHeader = &.{
            plaintext_capability_header,
            ps3_elf_digest_header,
            ps3_npdrm_header,
        };

        try seekableStream.seekTo(extended_header.supplemental_header_offset);
        break :blk try Self.SupplementalHeader.writeTable(
            if (template.program_type == .npdrm_application)
                npdrm_supplemental_headers
            else
                base_supplemental_headers,
            writer,
            endian,
        );
    };

    extended_header.elf_header_offset = extended_header.supplemental_header_offset + extended_header.supplemental_header_size;
    try seekableStream.seekTo(extended_header.elf_header_offset);
    try writer.writeAll(elf_data[0..try elfHeaderSize(elf_data)]);

    // TODO: fill in the missing info into the header
    // After filling in the missing info into the header, write it to the start of the file
    try seekableStream.seekTo(0);
    try header.write(writer);

    // After filling in the missing info into the extended header, write it after the extended header
    try seekableStream.seekTo(header.byteSize());
    try extended_header.write(writer, endian);

    return stream.array_list.toOwnedSlice();
}
