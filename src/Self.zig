const std = @import("std");

const sce = @import("sce.zig");

const Self = @This();

pub const Error = error{
    BadPs3ElfDigestSize,
    BadNpdrmMagic,
    BadVitaNpdrmMagic,
    InvalidElfClass,
    InvalidElfEndian,
    InvalidElfMagic,
    InvalidElfVersion,
} || std.fs.File.Reader.ReadEnumError || std.mem.Allocator.Error || sce.Error || std.meta.IntToEnumError;

/// aka self header
pub const ExtendedHeader = struct {
    pub const Version = enum(u64) {
        ps3 = 3,
        vita = 4,
    };

    /// The version of the extended header
    ///
    /// aka header_type
    version: Version,
    /// The offset to the Program Identification Header
    ///
    /// aka app_info_offset
    program_identification_header_offset: u64,
    /// The offset to the ELF Header
    ///
    /// aka elf_offset
    elf_header_offset: u64,
    /// The offset to the ELF Program Header
    ///
    /// aka phdr_offset
    program_header_offset: u64,
    /// The offset to the ELF Section Header
    ///
    /// aka shdr_offset
    section_header_offset: u64,
    /// The offset to the Segment Extended Header
    ///
    /// aka section_info_offset
    segment_extended_header_offset: u64,
    /// The offset to the Version Header
    ///
    /// aka sce_version_offset
    version_header_offset: u64,
    /// The offset to the Supplemental Header
    ///
    /// aka control_info_offset
    supplemental_header_offset: u64,
    /// The size of the Supplemental Header
    ///
    /// aka control_info_size
    supplemental_header_size: u64,
    padding: u64,

    pub fn byteSize(self: ExtendedHeader) usize {
        _ = self;

        return 0x50;
    }

    pub fn read(reader: anytype, endian: std.builtin.Endian) Error!ExtendedHeader {
        return .{
            .version = try reader.readEnum(Version, endian),
            .program_identification_header_offset = try reader.readInt(u64, endian),
            .elf_header_offset = try reader.readInt(u64, endian),
            .program_header_offset = try reader.readInt(u64, endian),
            .section_header_offset = try reader.readInt(u64, endian),
            .segment_extended_header_offset = try reader.readInt(u64, endian),
            .version_header_offset = try reader.readInt(u64, endian),
            .supplemental_header_offset = try reader.readInt(u64, endian),
            .supplemental_header_size = try reader.readInt(u64, endian),
            .padding = try reader.readInt(u64, endian),
        };
    }
};

/// aka application info/app info
pub const ProgramIdentificationHeader = struct {
    pub const ProgramAuthorityId = packed struct(u64) {
        pub const ConsoleGeneration = enum(u4) {
            ps3 = 1,
            vita = 2,
            ps4 = 3,
        };

        program_id: u52,
        territory_id: u8,
        console_generation: ConsoleGeneration,
    };

    pub const VenderId = packed struct(u32) {
        pub const GuestOsId = enum(u16) {
            none = 0,
            pme = 1,
            lv2 = 2,
            ps2emu = 3,
            linux = 4,
            _,
        };

        guest_os_id: GuestOsId,
        territory: u16,
    };

    pub const ProgramType = enum(u32) {
        /// PS4 update pup
        pup = 0,
        /// PS3 lv0 application
        lv0 = 1,
        /// PS3 lv1 application
        lv1 = 2,
        /// PS3 lv2 application
        lv2 = 3,
        /// PS3 application
        application = 4,
        /// PS3 isolated SPU module
        isolated_spu_module = 5,
        /// PS3 secure loader
        secure_loader = 6,
        /// PS3 kernel or Vita kernel module
        kernel_or_kernel_prx = 7,
        /// PS3/Vita/PS4 npdrm application
        npdrm_application = 8,
        /// Vita boot loader or PS4 plugin
        vita_boot_loader_or_ps4_plugin = 9,
        /// Unknown usage...
        unknown = 10,
        /// Vita Secure module
        vita_secure_module = 11,
        /// PS4 full kernel and/or BIOS
        kernel_or_bios = 12,
        /// Vita system usermode module (.self/EBOOT.BIN/.suprx)
        system_usermode_module = 13,
        /// Unknown usage on Vita, secure module on PS4
        vita_unknown_or_ps4_secure_module = 14,
        /// PS4 secure kernel
        secure_kernel = 15,
    };

    /// The program authority ID
    ///
    /// aka auth_id
    program_authority_id: ProgramAuthorityId,
    /// The program "vender" ID
    ///
    /// aka vendor_id
    program_vender_id: VenderId,
    /// The program type of the Self
    ///
    /// aka self_type
    program_type: ProgramType,
    /// aka version
    program_sceversion: u64,
    padding: u64,

    pub fn read(reader: anytype, endian: std.builtin.Endian) Error!ProgramIdentificationHeader {
        return .{
            .program_authority_id = @bitCast(try reader.readInt(u64, endian)),
            .program_vender_id = @bitCast(try reader.readInt(u32, endian)),
            .program_type = try reader.readEnum(ProgramType, endian),
            .program_sceversion = try reader.readInt(u64, endian),
            .padding = try reader.readInt(u64, endian),
        };
    }
};

pub const SupplementalHeaderTable = struct {
    pub const SupplementalHeaderType = enum(u32) {
        plaintext_capability = 1,
        ps3_elf_digest = 2,
        ps3_npdrm = 3,
        vita_elf_digest = 4,
        vita_npdrm = 5,
        vita_boot_param = 6,
        vita_shared_secret = 7,
    };

    pub const SupplementalHeader = union(SupplementalHeaderType) {
        pub const Ps3ElfDigest = union(enum) {
            pub const Small = struct {
                constant_or_elf_digsest: [0x14]u8,
                padding: [0xc]u8,
            };

            pub const Large = struct {
                constant: [0x14]u8,
                elf_digest: [0x14]u8,
                required_system_version: u64,
            };

            small: Small,
            large: Large,

            pub fn read(reader: anytype, endian: std.builtin.Endian, size: usize) Error!Ps3ElfDigest {
                return switch (size) {
                    0x30 => .{ .small = .{
                        .constant_or_elf_digsest = try reader.readBytesNoEof(0x14),
                        .padding = try reader.readBytesNoEof(0xc),
                    } },
                    0x40 => .{ .large = .{
                        .constant = try reader.readBytesNoEof(0x14),
                        .elf_digest = try reader.readBytesNoEof(0x14),
                        .required_system_version = try reader.readInt(u64, endian),
                    } },
                    else => return Error.BadPs3ElfDigestSize,
                };
            }
        };
        pub const Ps3Npdrm = struct {
            pub const AppType = enum(u32) {
                module = 0,
                executable = 1,
                disc_game_update_module = 0x20,
                disc_game_update_executable = 0x21,
                hdd_game_update_module = 0x30,
                hdd_game_update_executable = 0x31,
            };

            version: u32,
            drm_type: sce.DrmType,
            app_type: AppType,
            content_id: sce.ContentId,
            digest: [0x10]u8,
            cid_fn_hash: [0x10]u8,
            header_hash: [0x10]u8,
            limited_time_start: u64,
            limited_time_end: u64,

            pub fn read(reader: anytype, endian: std.builtin.Endian) Error!Ps3Npdrm {
                if (!std.mem.eql(u8, &(try reader.readBytesNoEof(4)), "NPD\x00"))
                    return Error.BadNpdrmMagic;

                return .{
                    .version = try reader.readInt(u32, endian),
                    .drm_type = try std.meta.intToEnum(sce.DrmType, try reader.readInt(u32, endian)), // this is read as a u32 here, but in other places (like the RIF file, its a u16)
                    .app_type = try reader.readEnum(SupplementalHeader.Ps3Npdrm.AppType, endian),
                    .content_id = try reader.readBytesNoEof(0x30),
                    .digest = try reader.readBytesNoEof(0x10),
                    .cid_fn_hash = try reader.readBytesNoEof(0x10),
                    .header_hash = try reader.readBytesNoEof(0x10),
                    .limited_time_start = try reader.readInt(u64, endian),
                    .limited_time_end = try reader.readInt(u64, endian),
                };
            }
        };
        pub const VitaElfDigest = struct {
            constant: [0x14]u8,
            elf_digest: [0x20]u8,
            padding: u64,
            min_required_fw: u32,

            pub fn read(reader: anytype, endian: std.builtin.Endian) Error!VitaElfDigest {
                return .{
                    .constant = try reader.readBytesNoEof(0x14),
                    .elf_digest = try reader.readBytesNoEof(0x20),
                    .padding = try reader.readInt(u64, endian),
                    .min_required_fw = try reader.readInt(u32, endian),
                };
            }
        };
        pub const VitaNpdrm = struct {
            finalized_flag: u32,
            drm_type: sce.DrmType,
            padding: u32,
            content_id: sce.ContentId,
            digest: [0x10]u8,
            padding_78: [0x78]u8,
            sig: sce.Ecdsa224Signature,

            pub fn read(reader: anytype, endian: std.builtin.Endian) Error!VitaNpdrm {
                if (!std.mem.eql(u8, &(try reader.readBytesNoEof(4)), "\x7FDRM"))
                    return Error.BadVitaNpdrmMagic;

                return .{
                    .finalized_flag = try reader.readInt(u32, endian),
                    .drm_type = try std.meta.intToEnum(sce.DrmType, try reader.readInt(u32, endian)), // this is read as a u32 here, but in other places (like the RIF file, its a u16)
                    .padding = try reader.readInt(u32, endian),
                    .content_id = try reader.readBytesNoEof(0x30),
                    .digest = try reader.readBytesNoEof(0x10),
                    .padding_78 = try reader.readBytesNoEof(0x78),
                    .sig = try sce.Ecdsa224Signature.read(reader),
                };
            }
        };
        pub const VitaBootParam = struct {
            boot_param: [0x100]u8,

            pub fn read(reader: anytype) Error!VitaBootParam {
                return .{
                    .boot_param = try reader.readBytesNoEof(0x100),
                };
            }
        };

        plaintext_capability: sce.PlaintextCapability,
        ps3_elf_digest: Ps3ElfDigest,
        ps3_npdrm: Ps3Npdrm,
        vita_elf_digest: VitaElfDigest,
        vita_npdrm: VitaNpdrm,
        vita_boot_param: VitaBootParam,
        vita_shared_secret: sce.SharedSecret,
    };

    pub fn read(allocator: std.mem.Allocator, raw_reader: anytype, extended_header: ExtendedHeader, endian: std.builtin.Endian) Error![]SupplementalHeader {
        var headers = std.ArrayList(SupplementalHeader).init(allocator);

        var counting_reader = std.io.countingReader(raw_reader);
        const reader = counting_reader.reader();

        while (extended_header.supplemental_header_size > 0) {
            counting_reader.bytes_read = 0;

            const header_type = try reader.readEnum(SupplementalHeaderType, endian);
            const size = try reader.readInt(u32, endian);
            const next = (try reader.readInt(u64, endian)) > 0;

            const supplemental_header: SupplementalHeader = switch (header_type) {
                .plaintext_capability => .{ .plaintext_capability = try sce.PlaintextCapability.read(reader, endian) },
                .ps3_elf_digest => .{ .ps3_elf_digest = try SupplementalHeader.Ps3ElfDigest.read(reader, endian, size) },
                .ps3_npdrm => .{ .ps3_npdrm = try SupplementalHeader.Ps3Npdrm.read(reader, endian) },
                .vita_elf_digest => .{ .vita_elf_digest = try SupplementalHeader.VitaElfDigest.read(reader, endian) },
                .vita_npdrm => .{ .vita_npdrm = try SupplementalHeader.VitaNpdrm.read(reader, endian) },
                .vita_boot_param => .{ .vita_boot_param = try SupplementalHeader.VitaBootParam.read(reader) },
                .vita_shared_secret => .{ .vita_shared_secret = try sce.SharedSecret.read(reader, endian) },
            };

            const to_read = size - counting_reader.bytes_read;
            try reader.skipBytes(to_read, .{});

            try headers.append(supplemental_header);

            if (!next)
                break;
        }

        return try headers.toOwnedSlice();
    }
};

pub const SegmentExtendedHeader = struct {
    pub const Encryption = enum(u64) {
        unrequested = 0,
        completed = 1,
        requested = 2,
    };

    offset: u64,
    size: u64,
    compression: sce.CompressionAlgorithm,
    unknown: u32,
    encryption: Encryption,

    pub fn read(allocator: std.mem.Allocator, reader: anytype, elf_header: std.elf.Header, endianness: std.builtin.Endian) ![]SegmentExtendedHeader {
        const segment_extended_headers = try allocator.alloc(SegmentExtendedHeader, elf_header.phnum);
        errdefer allocator.free(segment_extended_headers);

        for (segment_extended_headers) |*segment_extended_header| {
            segment_extended_header.* = try readSingle(reader, endianness);
        }

        return segment_extended_headers;
    }

    fn readSingle(reader: anytype, endianness: std.builtin.Endian) !SegmentExtendedHeader {
        return .{
            .offset = try reader.readInt(u64, endianness),
            .size = try reader.readInt(u64, endianness),
            .compression = try reader.readEnum(sce.CompressionAlgorithm, endianness),
            .unknown = try reader.readInt(u32, endianness),
            .encryption = try reader.readEnum(Encryption, endianness),
        };
    }
};

pub fn read(self_data: []const u8, stream: anytype, allocator: std.mem.Allocator, endianness: std.builtin.Endian) Error!Self {
    const reader = stream.reader();

    const extended_header = try Self.ExtendedHeader.read(reader, endianness);

    try stream.seekTo(extended_header.program_identification_header_offset);
    const program_identification_header = try ProgramIdentificationHeader.read(reader, endianness);

    try stream.seekTo(extended_header.supplemental_header_offset);
    const supplemental_headers = try SupplementalHeaderTable.read(allocator, reader, extended_header, endianness);
    errdefer allocator.free(supplemental_headers);

    if (extended_header.elf_header_offset > std.math.maxInt(usize))
        return error.InvalidPosOrSizeForPlatform;

    const elf_header_data: [@sizeOf(std.elf.Elf64_Ehdr)]u8 align(@alignOf(std.elf.Elf64_Ehdr)) = self_data[@intCast(extended_header.elf_header_offset)..][0..@sizeOf(std.elf.Elf64_Ehdr)].*;

    // Read the ELF header, as we need to know the amount of program segment headers present to raed the segment extended headers
    const elf_header = try std.elf.Header.parse(&elf_header_data);

    try stream.seekTo(extended_header.segment_extended_header_offset);

    const segment_extended_headers = try SegmentExtendedHeader.read(allocator, reader, elf_header, endianness);
    errdefer allocator.free(segment_extended_headers);

    return .{
        .extended_header = extended_header,
        .program_identification_header = program_identification_header,
        .supplemental_headers = supplemental_headers,
        .elf_header = elf_header,
        .segment_extended_headers = segment_extended_headers,
    };
}

extended_header: ExtendedHeader,
program_identification_header: ProgramIdentificationHeader,
supplemental_headers: []SupplementalHeaderTable.SupplementalHeader,
elf_header: std.elf.Header,
segment_extended_headers: []SegmentExtendedHeader,

pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
    allocator.free(self.supplemental_headers);
    allocator.free(self.segment_extended_headers);
}
