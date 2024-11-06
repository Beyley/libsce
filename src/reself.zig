const std = @import("std");
const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();

const sce = @import("sce.zig");

const ArrayListStreamSource = @import("ArrayListStreamSource.zig");

const certified_file = sce.certified_file;
const CertifiedFile = sce.certified_file.CertifiedFile;
const Self = sce.Self;

const Elf64_Ehdr = std.elf.Elf64_Ehdr;
const Elf32_Ehdr = std.elf.Elf32_Ehdr;

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

fn elfHeader(elf_data: []const u8) !Elf64_Ehdr {
    var hdr_buf: [@sizeOf(Elf64_Ehdr)]u8 align(@alignOf(Elf64_Ehdr)) = elf_data[0..@sizeOf(Elf64_Ehdr)].*;

    const hdr32 = @as(*Elf32_Ehdr, @ptrCast(&hdr_buf));
    const hdr64 = @as(*Elf64_Ehdr, @ptrCast(&hdr_buf));
    if (!std.mem.eql(u8, hdr32.e_ident[0..4], std.elf.MAGIC)) return Error.InvalidElfMagic;
    if (hdr32.e_ident[std.elf.EI_VERSION] != 1) return Error.InvalidElfVersion;

    const is_64 = switch (hdr32.e_ident[std.elf.EI_CLASS]) {
        std.elf.ELFCLASS32 => false,
        std.elf.ELFCLASS64 => true,
        else => return Error.InvalidElfClass,
    };

    const elf_endian: std.builtin.Endian = switch (hdr32.e_ident[std.elf.EI_DATA]) {
        std.elf.ELFDATA2LSB => .little,
        std.elf.ELFDATA2MSB => .big,
        else => return Error.InvalidElfEndian,
    };
    const need_bswap = elf_endian != native_endian;

    if (is_64 and need_bswap)
        std.mem.byteSwapAllFields(Elf64_Ehdr, hdr64)
    else if (need_bswap)
        std.mem.byteSwapAllFields(Elf32_Ehdr, hdr32);

    if (is_64)
        return hdr64.*;

    return .{
        .e_ident = hdr32.e_ident,
        .e_type = hdr32.e_type,
        .e_machine = hdr32.e_machine,
        .e_version = hdr32.e_version,
        .e_entry = hdr32.e_entry,
        .e_phoff = hdr32.e_phoff,
        .e_shoff = hdr32.e_shoff,
        .e_flags = hdr32.e_flags,
        .e_ehsize = hdr32.e_ehsize,
        .e_phentsize = hdr32.e_phentsize,
        .e_phnum = hdr32.e_phnum,
        .e_shentsize = hdr32.e_shentsize,
        .e_shnum = hdr32.e_shnum,
        .e_shstrndx = hdr32.e_shstrndx,
    };
}

pub fn createSelfFromElf(allocator: std.mem.Allocator, elf_data: []const u8, template: Template) Error![]u8 {
    var elf_stream = std.io.fixedBufferStream(elf_data);

    const raw_elf_header = try elfHeader(elf_data);
    const elf_header = try std.elf.Header.read(&elf_stream);

    var stream: ArrayListStreamSource = .init(allocator);
    defer stream.deinit();

    const seekableStream = stream.seekableStream();
    const writer = stream.writer();

    const endian = .big; // TODO: little endian/vita

    // Allocate space for the CF header
    try seekableStream.seekTo(certified_file.Header.versionByteSize(.ps3));

    // Allocate the space for the SELF extended header
    const extended_header_offset = stream.pos;
    _ = extended_header_offset; // autofix
    try seekableStream.seekBy(@intCast(Self.ExtendedHeader.byteSize()));

    // Write out the program identification header
    const program_identification_header_offset = stream.pos;
    const program_identification_header: Self.ProgramIdentificationHeader = .{
        .program_type = .application,
        .program_authority_id = template.program_authority_id,
        .program_sceversion = template.program_sceversion,
        .program_vender_id = template.program_vender_id,
        .padding = 0,
    };
    try program_identification_header.write(writer, endian);

    // Write out the ELF header
    const elf_header_offset = stream.pos;
    try writer.writeAll(elf_data[0..raw_elf_header.e_ehsize]);

    // Write ou the program headers
    const program_header_offset = stream.pos;
    const program_header_size = raw_elf_header.e_phnum * raw_elf_header.e_phentsize;
    try writer.writeAll(elf_data[raw_elf_header.e_phoff..][0..program_header_size]);

    // Allocate the space for the segment extended headers
    const segment_extended_header_offset = stream.pos;
    try seekableStream.seekBy(elf_header.phnum * raw_elf_header.e_phentsize);

    // Allocate the space for the version header
    const version_header_offset = stream.pos;
    try seekableStream.seekBy(@intCast(Self.VersionHeader.byteSize()));

    // Write out the supplemental headers
    const supplemental_header_offset = stream.pos;
    const supplemental_header_size = blk: {
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

        try seekableStream.seekTo(supplemental_header_offset);
        break :blk try Self.SupplementalHeader.writeTable(
            if (template.program_type == .npdrm_application)
                &.{
                    plaintext_capability_header,
                    ps3_elf_digest_header,
                    .{
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
                    },
                }
            else
                &.{
                    plaintext_capability_header,
                    ps3_elf_digest_header,
                },
            writer,
            endian,
        );
    };

    const header: certified_file.Header = .{
        .file_offset = undefined, // TODO: fill this in
        .file_size = elf_data.len,
        .category = .signed_elf,
        .extended_header_size = undefined, // TODO: fill this in
        .key_revision = template.key_revision,
        .version = .ps3,
        .vita_data = null,
    };

    // TODO: fill in the missing info into the header
    // After filling in the missing info into the header, write it to the start of the file
    try seekableStream.seekTo(0);
    try header.write(writer);

    const extended_header: Self.ExtendedHeader = .{
        .version = .ps3,
        .program_identification_header_offset = program_identification_header_offset,
        .supplemental_header_offset = supplemental_header_offset,
        .elf_header_offset = elf_header_offset,
        .program_header_offset = program_header_offset,
        .segment_extended_header_offset = segment_extended_header_offset,
        .supplemental_header_size = supplemental_header_size,
        .section_header_offset = undefined, // TODO: fill this in
        .version_header_offset = version_header_offset,
        .padding = 0,
    };

    // After filling in the missing info into the extended header, write it after the extended header
    try seekableStream.seekTo(header.byteSize());
    try extended_header.write(writer, endian);

    // TODO: write out the segment extended headers
    // try seekableStream.seekTo(extended_header.segment_extended_header_offset);
    // var elf_program_header_iter = elf_header.program_header_iterator(&elf_stream);
    // while (try elf_program_header_iter.next()) |program_header| {
    //     const segment_extended_header: Self.SegmentExtendedHeader = .{
    //         .encryption = switch (program_header.p_type) {
    //             std.elf.PT_LOAD, Self.PT_SCE_PPURELA, Self.PT_SCE_SEGSYM => .completed,
    //             else => .unrequested,
    //         },
    //         .offset = undefined,
    //     };
    //     _ = segment_extended_header;
    // }

    // TODO: write out the version header

    return stream.array_list.toOwnedSlice();
}
