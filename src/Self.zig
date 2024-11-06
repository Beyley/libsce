const std = @import("std");

const sce = @import("sce.zig");

const Self = @This();

const log = std.log.scoped(.self);
const fieldSize = sce.fieldSize;

pub const Error = error{
    BadPs3ElfDigestSize,
    BadNpdrmMagic,
    BadVitaNpdrmMagic,
    InvalidElfClass,
    InvalidElfEndian,
    InvalidElfMagic,
    InvalidElfVersion,
    InvalidPosOrSizeForPlatform,
    FailedToReadSupplementalHeader,
    FailedToWriteSupplementalHeader,
} || std.fs.File.Reader.ReadEnumError || std.mem.Allocator.Error || sce.Error || std.meta.IntToEnumError;

/// The SELF's header, stored in the Extended Header section of the Certified File
///
/// See https://www.psdevwiki.com/ps3/SELF_-_SPRX#Extended_Header
///
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

    pub fn byteSize() usize {
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

    pub fn write(self: ExtendedHeader, writer: anytype, endian: std.builtin.Endian) Error!void {
        try writer.writeInt(std.meta.Tag(Version), @intFromEnum(self.version), endian);
        try writer.writeInt(u64, self.program_identification_header_offset, endian);
        try writer.writeInt(u64, self.elf_header_offset, endian);
        try writer.writeInt(u64, self.program_header_offset, endian);
        try writer.writeInt(u64, self.section_header_offset, endian);
        try writer.writeInt(u64, self.segment_extended_header_offset, endian);
        try writer.writeInt(u64, self.version_header_offset, endian);
        try writer.writeInt(u64, self.supplemental_header_offset, endian);
        try writer.writeInt(u64, self.supplemental_header_size, endian);
        try writer.writeInt(u64, self.padding, endian);
    }
};

/// See https://www.psdevwiki.com/ps3/Program_Authority_ID
pub const ProgramAuthorityId = packed struct(u64) {
    pub const ConsoleGeneration = enum(u4) {
        ps3 = 1,
        vita = 2,
        ps4 = 3,
    };

    /// The program ID
    program_id: u52,
    /// The territory ID this program is for
    territory_id: u8,
    /// The console generation this program is for
    console_generation: ConsoleGeneration,
};

/// See https://www.psdevwiki.com/ps3/Program_Vender_Id
///
/// aka vendor id
pub const ProgramVenderId = packed struct(u32) {
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

/// Contains identification information about the program
///
/// See https://www.psdevwiki.com/ps3/SELF_-_SPRX#Program_Identification_Header
///
/// aka application info/app info
pub const ProgramIdentificationHeader = struct {
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
    program_vender_id: ProgramVenderId,
    /// The program type of the Self
    ///
    /// aka self_type
    program_type: ProgramType,
    /// aka version
    program_sceversion: u64,
    padding: u64,

    pub fn byteSize() usize {
        return 0x20;
    }

    pub fn read(reader: anytype, endian: std.builtin.Endian) Error!ProgramIdentificationHeader {
        return .{
            .program_authority_id = @bitCast(try reader.readInt(u64, endian)),
            .program_vender_id = @bitCast(try reader.readInt(u32, endian)),
            .program_type = try reader.readEnum(ProgramType, endian),
            .program_sceversion = try reader.readInt(u64, endian),
            .padding = try reader.readInt(u64, endian),
        };
    }

    pub fn write(self: ProgramIdentificationHeader, writer: anytype, endian: std.builtin.Endian) Error!void {
        try writer.writeInt(u64, @bitCast(self.program_authority_id), endian);
        try writer.writeInt(u32, @bitCast(self.program_vender_id), endian);
        try writer.writeInt(std.meta.Tag(ProgramType), @intFromEnum(self.program_type), endian);
        try writer.writeInt(u64, self.program_sceversion, endian);
        try writer.writeInt(u64, self.padding, endian);
    }
};

/// The constant that all PS3/Vita SELF files share: 627CB1808AB938E32C8C091708726A579E2586E4
pub const ConstantDigest: [0x14]u8 = .{ 0x62, 0x7C, 0xB1, 0x80, 0x8A, 0xB9, 0x38, 0xE3, 0x2C, 0x8C, 0x09, 0x17, 0x08, 0x72, 0x6A, 0x57, 0x9E, 0x25, 0x86, 0xE4 };

/// Non-essential supplemental information about the SELF
///
/// See https://www.psdevwiki.com/ps3/SELF_-_SPRX#Supplemental_Header_Table
///
/// aka control information
pub const SupplementalHeader = union(Type) {
    pub const Type = enum(u32) {
        plaintext_capability = 1,
        ps3_elf_digest = 2,
        ps3_npdrm = 3,
        vita_elf_digest = 4,
        vita_npdrm = 5,
        vita_boot_param = 6,
        vita_shared_secret = 7,
    };

    /// Contains digest/hash information about the embedded binary
    pub const Ps3ElfDigest = union(enum) {
        pub const Small = struct {
            constant_or_elf_digsest: [0x14]u8,
            padding: [0xc]u8,
        };

        pub const Large = struct {
            /// Same for every PS3/Vita SELF, hardcoded
            constant: [0x14]u8,
            /// A SHA-1 hash of the contained ELF file
            elf_digest: [0x14]u8,
            /// The required system version to run the application, in the format of XX.YYYY (decimal, not hexadecimal)
            required_system_version: u64,
        };

        small: Small,
        large: Large,

        pub fn read(reader: anytype, endian: std.builtin.Endian, size: usize) Error!Ps3ElfDigest {
            return switch (size) {
                0x30 => .{ .small = .{
                    .constant_or_elf_digsest = try reader.readBytesNoEof(fieldSize(Small, "constant_or_elf_digsest")),
                    .padding = try reader.readBytesNoEof(fieldSize(Small, "padding")),
                } },
                0x40 => .{ .large = .{
                    .constant = try reader.readBytesNoEof(fieldSize(Large, "constant")),
                    .elf_digest = try reader.readBytesNoEof(fieldSize(Large, "elf_digest")),
                    .required_system_version = try reader.readInt(u64, endian),
                } },
                else => {
                    log.err("PS3 elf digest header has invalid size {d}", .{size});
                    return Error.BadPs3ElfDigestSize;
                },
            };
        }

        pub fn write(self: Ps3ElfDigest, writer: anytype, endian: std.builtin.Endian) Error!void {
            switch (self) {
                .large => |large| {
                    try writer.writeAll(&large.constant);
                    try writer.writeAll(&large.elf_digest);
                    try writer.writeInt(u64, large.required_system_version, endian);
                },
                .small => |small| {
                    try writer.writeAll(&small.constant_or_elf_digsest);
                    try writer.writeAll(&small.padding);
                },
            }
        }

        pub fn byteSize(self: Ps3ElfDigest) usize {
            return switch (self) {
                .small => 0x20,
                .large => 0x30,
            };
        }
    };

    /// Contains information about the app's NPDRM signature
    ///
    /// aka NPD packet
    pub const Ps3Npdrm = struct {
        pub const AppType = enum(u32) {
            module = 0,
            executable = 1,
            disc_game_update_module = 0x20,
            disc_game_update_executable = 0x21,
            hdd_game_update_module = 0x30,
            hdd_game_update_executable = 0x31,
        };

        /// The version of the NPD packager
        version: u32,
        /// The DRM type of the application
        drm_type: sce.DrmType,
        /// The NPDRM application type
        app_type: AppType,
        /// The content ID of the application
        content_id: sce.ContentId,
        /// The application's digest
        digest: [0x10]u8,
        /// AES-CMAC hash of the concatenation of Content ID (48 bytes) and EDAT/SELF filename (eg "MINIS.EDAT", "EBOOT.BIN") using the npd_cid_fn_hash_aes_cmac_key
        cid_fn_hash: [0x10]u8,
        /// AES-CMAC hash of the 0x60 bytes from the beginning of the NPD packet using (klicensee XOR npd_header_hash_xor_key) as AES-CMAC key
        header_hash: [0x10]u8,
        /// Start of the validity period.
        limited_time_start: ?u64,
        /// End of the validity period
        limited_time_end: ?u64,

        const null_time = 0;

        pub fn byteSize(self: Ps3Npdrm) usize {
            _ = self;

            return 0x80;
        }

        pub fn read(reader: anytype, endian: std.builtin.Endian) Error!Ps3Npdrm {
            const magic = try reader.readBytesNoEof(4);
            if (!std.mem.eql(u8, &magic, "NPD\x00")) {
                log.err("PS3 NPDRM supplemental header has invalid magic of {x}", .{magic});
                return Error.BadNpdrmMagic;
            }

            return .{
                .version = try reader.readInt(u32, endian),
                .drm_type = try std.meta.intToEnum(sce.DrmType, try reader.readInt(u32, endian)), // this is read as a u32 here, but in other places, like the RIF file, its a u16
                .app_type = try reader.readEnum(SupplementalHeader.Ps3Npdrm.AppType, endian),
                .content_id = try reader.readBytesNoEof(0x30),
                .digest = try reader.readBytesNoEof(0x10),
                .cid_fn_hash = try reader.readBytesNoEof(0x10),
                .header_hash = try reader.readBytesNoEof(0x10),
                .limited_time_start = blk: {
                    const time = try reader.readInt(u64, endian);

                    break :blk if (time == null_time) null else time;
                },
                .limited_time_end = blk: {
                    const time = try reader.readInt(u64, endian);

                    break :blk if (time == null_time) null else time;
                },
            };
        }

        pub fn write(self: Ps3Npdrm, writer: anytype, endian: std.builtin.Endian) Error!void {
            try writer.writeAll("NPD\x00");
            try writer.writeInt(u32, self.version, endian);
            try writer.writeInt(u32, @intFromEnum(self.drm_type), endian); // this is written as a u32 here, but in other places, like the RIF file, its a u16, so the type is u16, so we specify u32
            try writer.writeInt(std.meta.Tag(AppType), @intFromEnum(self.app_type), endian);
            try writer.writeAll(&self.content_id);
            try writer.writeAll(&self.digest);
            try writer.writeAll(&self.cid_fn_hash);
            try writer.writeAll(&self.header_hash);
            try writer.writeInt(u64, self.limited_time_start orelse null_time, endian);
            try writer.writeInt(u64, self.limited_time_end orelse null_time, endian);
        }
    };

    /// Contains digest/hash information about the program
    pub const VitaElfDigest = struct {
        /// Same for every PS3/Vita SELF, hardcoded
        constant: [0x14]u8,
        /// SHA-256 of source ELF file
        elf_digest: [0x20]u8,
        padding: u64,
        /// Minimum required firmware to run application, 0x0363 for 3.63, 0xXXYY for (XX.YY)
        min_required_fw: u32,

        pub fn byteSize(self: VitaElfDigest) usize {
            _ = self;
            return 0x40;
        }

        pub fn read(reader: anytype, endian: std.builtin.Endian) Error!VitaElfDigest {
            return .{
                .constant = try reader.readBytesNoEof(0x14),
                .elf_digest = try reader.readBytesNoEof(0x20),
                .padding = try reader.readInt(u64, endian),
                .min_required_fw = try reader.readInt(u32, endian),
            };
        }

        pub fn write(self: VitaElfDigest, writer: anytype, endian: std.builtin.Endian) Error!void {
            try writer.writeAll(&self.constant);
            try writer.writeAll(&self.elf_digest);
            try writer.writeInt(u64, self.padding, endian);
            try writer.writeInt(u32, self.min_required_fw, endian);
        }
    };

    /// Contains the program's NPDRM information
    pub const VitaNpdrm = struct {
        /// Unknown. It may be version like in NPD. ex: 80 00 00 01
        finalized_flag: u32,
        /// The DRM type used for the encrypted sections
        drm_type: sce.DrmType,
        padding: u32,
        /// The content ID of the application
        content_id: sce.ContentId,
        /// Unknown. Maybe SHA-1 hash of debug SELF/SPRX created using make_fself_npdrm? Maybe content_id hash?
        digest: [0x10]u8,
        padding_78: [0x78]u8,
        /// Unknown. Maybe signature of PSVita_npdrm_header? Maybe signature of an external NPDRM file?
        sig: sce.Ecdsa224Signature,

        pub fn byteSize(self: VitaNpdrm) usize {
            _ = self;
            return 0x100;
        }

        pub fn read(reader: anytype, endian: std.builtin.Endian) Error!VitaNpdrm {
            const magic = try reader.readBytesNoEof(4);
            if (!std.mem.eql(u8, &magic, "\x7FDRM")) {
                log.err("Vita NPDRM supplemental header has invalid magic, {x}", .{magic});
                return Error.BadVitaNpdrmMagic;
            }

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

        pub fn write(self: VitaNpdrm, writer: anytype, endian: std.builtin.Endian) Error!void {
            try writer.writeAll("\x7FDRM");
            try writer.writeInt(u32, self.finalized_flag, endian);
            try writer.writeInt(u32, @intFromEnum(self.drm_type), endian); // this is written as a u32 here, but in other places, like the RIF file, its a u16, so the type is u16, so we specify u32
            try writer.writeInt(u32, self.padding, endian);
            try writer.writeAll(&self.content_id);
            try writer.writeAll(&self.digest);
            try writer.writeAll(&self.padding_78);
            try self.sig.write(writer);
        }
    };

    /// Unknown.
    pub const VitaBootParam = struct {
        /// Unknown.
        boot_param: [0x100]u8,

        pub fn byteSize(self: VitaBootParam) usize {
            _ = self;
            return 0x100;
        }

        pub fn read(reader: anytype) Error!VitaBootParam {
            return .{
                .boot_param = try reader.readBytesNoEof(0x100),
            };
        }

        pub fn write(self: VitaBootParam, writer: anytype, endian: std.builtin.Endian) Error!void {
            _ = endian;

            try writer.writeAll(&self.boot_param);
        }
    };

    plaintext_capability: sce.PlaintextCapability,
    ps3_elf_digest: Ps3ElfDigest,
    ps3_npdrm: Ps3Npdrm,
    vita_elf_digest: VitaElfDigest,
    vita_npdrm: VitaNpdrm,
    vita_boot_param: VitaBootParam,
    vita_shared_secret: sce.SharedSecret,

    pub fn byteSize(self: SupplementalHeader) usize {
        return switch (self) {
            inline else => |header| header.byteSize(),
        };
    }

    pub fn readTable(allocator: std.mem.Allocator, raw_reader: anytype, extended_header: ExtendedHeader, endian: std.builtin.Endian) Error![]SupplementalHeader {
        var headers = std.ArrayList(SupplementalHeader).init(allocator);

        var counting_reader = std.io.countingReader(raw_reader);
        const reader = counting_reader.reader();

        while (extended_header.supplemental_header_size > 0) {
            counting_reader.bytes_read = 0;

            const header_type = try reader.readEnum(SupplementalHeader.Type, endian);
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

            if (size != counting_reader.bytes_read) {
                log.err("Failed to read supplemental header, needed to read {d}, but read {d}", .{ size, counting_reader.bytes_read });
                return Error.FailedToReadSupplementalHeader;
            }

            try headers.append(supplemental_header);

            if (!next)
                break;
        }

        return try headers.toOwnedSlice();
    }

    pub fn writeTable(headers: []const SupplementalHeader, raw_writer: anytype, endian: std.builtin.Endian) Error!u64 {
        var counting_writer = std.io.countingWriter(raw_writer);
        const writer = counting_writer.writer();

        for (headers, 0..) |header, i| {
            try writer.writeInt(std.meta.Tag(SupplementalHeader.Type), @intFromEnum(header), endian);
            try writer.writeInt(u32, @intCast(header.byteSize()), endian);
            try writer.writeInt(u64, if (i < headers.len - 1) 1 else 0, endian);

            const write_start = counting_writer.bytes_written;

            switch (header) {
                inline else => |header_data| try header_data.write(writer, endian),
            }

            log.debug("Writing supplemental header of type {s}", .{@tagName(header)});

            const written = counting_writer.bytes_written - write_start;
            if (written != header.byteSize()) {
                log.err("Failed to write supplemental header, wanted to write {d}, wrote {d}", .{ header.byteSize(), written });
                return Error.FailedToWriteSupplementalHeader;
            }
        }

        return counting_writer.bytes_written;
    }
};

// PS3 specific ELF constants.
pub const PT_SCE_RELA = 0x60000000;
pub const PT_SCE_LICINFO_1 = 0x60000001;
pub const PT_SCE_LICINFO_2 = 0x60000002;
pub const PT_SCE_DYNLIBDATA = 0x61000000;
pub const PT_SCE_PROCESS_PARAM = 0x61000001;
pub const PT_SCE_MODULE_PARAM = 0x61000002;
pub const PT_SCE_RELRO = 0x61000010;
pub const PT_SCE_COMMENT = 0x6FFFFF00;
pub const PT_SCE_LIBVERSION = 0x6FFFFF01;
pub const PT_SCE_UNK_70000001 = 0x70000001;
pub const PT_SCE_IOPMOD = 0x70000080;
pub const PT_SCE_EEMOD = 0x70000090;
pub const PT_SCE_PSPRELA = 0x700000A0;
pub const PT_SCE_PSPRELA2 = 0x700000A1;
pub const PT_SCE_PPURELA = 0x700000A4;
pub const PT_SCE_SEGSYM = 0x700000A8;

/// Maps each PHDR in the ELF file to the real offset/size in the Certified File
///
/// See https://www.psdevwiki.com/ps3/SELF_-_SPRX#Segment_Extended_Header
///
/// aka Section Info
///
/// NOTE: psdevwiki claims this is also for SHDR entries, but that doesn't seem to be the case(?)
pub const SegmentExtendedHeader = struct {
    pub const Encryption = enum(u64) {
        unrequested = 0,
        completed = 1,
        requested = 2,
    };

    /// Offset to the data in the certified file, from the start
    offset: u64,
    /// Size of the data in the certified file
    size: u64,
    /// The compression algorithm in use
    compression: sce.CompressionAlgorithm,
    /// Unknown. Always seems to be zero.
    unknown: u32,
    /// The encryption method in use
    encryption: Encryption,

    pub fn read(allocator: std.mem.Allocator, reader: anytype, elf_header: std.elf.Header, endian: std.builtin.Endian) ![]SegmentExtendedHeader {
        const segment_extended_headers = try allocator.alloc(SegmentExtendedHeader, elf_header.phnum);
        errdefer allocator.free(segment_extended_headers);

        for (segment_extended_headers) |*segment_extended_header| {
            segment_extended_header.* = try readSingle(reader, endian);
        }

        return segment_extended_headers;
    }

    fn readSingle(reader: anytype, endian: std.builtin.Endian) !SegmentExtendedHeader {
        return .{
            .offset = try reader.readInt(u64, endian),
            .size = try reader.readInt(u64, endian),
            .compression = try reader.readEnum(sce.CompressionAlgorithm, endian),
            .unknown = try reader.readInt(u32, endian),
            .encryption = try reader.readEnum(Encryption, endian),
        };
    }

    pub fn writeSingle(self: SegmentExtendedHeader, writer: anytype, endian: std.builtin.Endian) Error!void {
        try writer.writeInt(u64, self.offset, endian);
        try writer.writeInt(u64, self.size, endian);
        try writer.writeInt(std.meta.Tag(sce.CompressionAlgorithm), self.compression, endian);
        try writer.writeInt(u32, self.unknown, endian);
        try writer.writeInt(std.meta.Tag(Encryption), self.encryption, endian);
    }
};

/// See https://www.psdevwiki.com/ps3/SELF_-_SPRX#Version_Header
pub const VersionHeader = struct {
    pub const SubHeaderType = enum(u32) {
        sceversion = 1,
    };

    sub_header_type: SubHeaderType,
    present: bool, // u32
    size: u32,
    unknown: u32,

    pub fn byteSize() usize {
        // TODO: psdevwiki claims that the `size` field may not always be 0x10. does the `size` field even refer to the actual version header itself?
        return 0x10;
    }

    pub fn read(reader: anytype, endian: std.builtin.Endian) !VersionHeader {
        return .{
            .sub_header_type = try reader.readEnum(SubHeaderType, endian),
            .present = try reader.readInt(u32, endian) != 0,
            .size = try reader.readInt(u32, endian),
            .unknown = try reader.readInt(u32, endian),
        };
    }

    pub fn write(self: VersionHeader, writer: anytype, endian: std.builtin.Endian) !void {
        try writer.writeInt(std.meta.Tag(SubHeaderType), self.sub_header_type, endian);
        try writer.writeInt(u32, @intFromBool(self.present), endian);
        try writer.writeInt(u32, self.size, endian);
        try writer.writeInt(u32, self.unknown, endian);
    }
};

pub fn read(self_data: []const u8, stream: anytype, allocator: std.mem.Allocator, endian: std.builtin.Endian) Error!Self {
    const reader = stream.reader();

    log.info("Reading extended SELF contents", .{});

    const extended_header = try Self.ExtendedHeader.read(reader, endian);

    log.info("Read extended header", .{});

    try stream.seekTo(extended_header.program_identification_header_offset);
    const program_identification_header = try ProgramIdentificationHeader.read(reader, endian);

    log.info("Read program identification header", .{});

    try stream.seekTo(extended_header.supplemental_header_offset);
    const supplemental_headers = try SupplementalHeader.readTable(allocator, reader, extended_header, endian);
    errdefer allocator.free(supplemental_headers);

    log.info("Read {d} supplemental headers", .{supplemental_headers.len});

    if (extended_header.elf_header_offset > std.math.maxInt(usize)) {
        log.err("Extended header had invalid ELF header offset {d}. Maybe a parsing error or corrupted file?", .{extended_header.elf_header_offset});
        return Error.InvalidPosOrSizeForPlatform;
    }

    const elf_header_data: [@sizeOf(std.elf.Elf64_Ehdr)]u8 align(@alignOf(std.elf.Elf64_Ehdr)) = self_data[@intCast(extended_header.elf_header_offset)..][0..@sizeOf(std.elf.Elf64_Ehdr)].*;

    // Read the ELF header, as we need to know the amount of program segment headers present to raed the segment extended headers
    const elf_header = try std.elf.Header.parse(&elf_header_data);

    log.info("Parsed ELF header", .{});

    try stream.seekTo(extended_header.segment_extended_header_offset);

    const segment_extended_headers = try SegmentExtendedHeader.read(allocator, reader, elf_header, endian);
    errdefer allocator.free(segment_extended_headers);

    log.info("Read {d} segment extended headers", .{segment_extended_headers.len});

    try stream.seekTo(extended_header.version_header_offset);
    const version_header = try VersionHeader.read(reader, endian);

    return .{
        .extended_header = extended_header,
        .program_identification_header = program_identification_header,
        .supplemental_headers = supplemental_headers,
        .elf_header = elf_header,
        .segment_extended_headers = segment_extended_headers,
        .version_header = version_header,
    };
}

extended_header: ExtendedHeader,
program_identification_header: ProgramIdentificationHeader,
supplemental_headers: []SupplementalHeader,
elf_header: std.elf.Header,
segment_extended_headers: []SegmentExtendedHeader,
version_header: VersionHeader,

pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
    allocator.free(self.supplemental_headers);
    allocator.free(self.segment_extended_headers);
}
