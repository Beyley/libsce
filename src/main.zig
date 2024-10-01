const std = @import("std");
const pretty = @import("pretty");

const Aes128 = std.crypto.core.aes.Aes128;
const Aes256 = std.crypto.core.aes.Aes256;

const aes = @cImport(@cInclude("aes.h"));

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer if (gpa.deinit() == .leak) @panic("memory leak");

    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const self_path = args[1];

    const self = try std.fs.cwd().openFile(self_path, .{});
    defer self.close();

    const keysJson = try std.fs.cwd().readFileAlloc(allocator, args[2], std.math.maxInt(usize));
    defer allocator.free(keysJson);

    var keyset = try readKeys(allocator, keysJson);
    defer keyset.deinit();

    const certified_file_header = try CertifiedFile.Header.read(self.reader());

    try pretty.print(allocator, certified_file_header, .{});

    if (certified_file_header.category != .signed_elf)
        return error.OnlySelfSupported;

    const extended_header = try Self.ExtendedHeader.read(self.reader(), certified_file_header.endianness());
    try pretty.print(allocator, extended_header, .{});

    try self.seekTo(extended_header.program_identification_header_offset);
    const program_identification_header = try Self.ProgramIdentificationHeader.read(self.reader(), certified_file_header.endianness());

    try pretty.print(allocator, program_identification_header, .{});

    try self.seekTo(extended_header.supplemental_header_offset);
    const supplemental_headers = try Self.SupplementalHeaderTable.read(allocator, self.reader(), extended_header, certified_file_header.endianness());
    defer allocator.free(supplemental_headers);

    try pretty.print(allocator, supplemental_headers, .{ .array_u8_is_str = true });

    const key = keyset.get(.{
        .revision = certified_file_header.key_revision,
        .self_type = program_identification_header.program_type,
    }) orelse return error.MissingKey;

    try pretty.print(allocator, .{
        .revision = certified_file_header.key_revision,
        .self_type = program_identification_header.program_type,
    }, .{});
    try pretty.print(allocator, key, .{});

    // TODO: dont read the encryption root header for fSELF files
    try self.seekTo(certified_file_header.byteSize() + certified_file_header.extended_header_size);
    const encryption_root_header = try CertifiedFile.EncryptionRootHeader.read(self.reader(), key);

    try pretty.print(allocator, encryption_root_header, .{});

    const certification_header = try CertifiedFile.CertificationHeader.read(self.reader(), encryption_root_header, certified_file_header.endianness());
    try pretty.print(allocator, certification_header, .{});
}

fn readKeys(allocator: std.mem.Allocator, json: []const u8) !KeySet {
    var keyset = KeySet.init(allocator);

    const keys = try std.json.parseFromSlice([]const JsonKey, allocator, json, .{});
    defer keys.deinit();

    for (keys.value) |key| {
        var encryption_round_key: [0x20]u8 = undefined;
        var reset_initialization_vector: [0x10]u8 = undefined;
        var public: [0x28]u8 = undefined;
        var private: [0x15]u8 = undefined;

        if ((try std.fmt.hexToBytes(&encryption_round_key, &key.encryption_round_key)).len != encryption_round_key.len)
            return error.BadEncryptionRoundKey;
        if ((try std.fmt.hexToBytes(&reset_initialization_vector, &key.reset_initialization_vector)).len != reset_initialization_vector.len)
            return error.BadResetInitializationVector;
        if ((try std.fmt.hexToBytes(&public, &key.public)).len != public.len)
            return error.BadPublic;
        if (key.private != null and (try std.fmt.hexToBytes(&private, &key.private.?)).len != private.len)
            return error.BadPrivate;

        try keyset.put(
            .{
                .revision = try std.fmt.parseInt(u16, key.revision, 0),
                .self_type = key.self_type,
            },
            .{
                .encryption_round_key = encryption_round_key,
                .reset_initialization_vector = reset_initialization_vector,
                .public = public,
                .private = if (key.private == null) null else private,
                .curve_type = try std.fmt.parseInt(u32, key.curve_type, 0),
            },
        );
    }

    return keyset;
}

pub const JsonKey = struct {
    revision: []const u8,
    self_type: Self.ProgramIdentificationHeader.ProgramType,
    encryption_round_key: [0x20 * 2]u8,
    reset_initialization_vector: [0x10 * 2]u8,
    public: [0x28 * 2]u8,
    private: ?[0x15 * 2]u8,
    curve_type: []const u8,
};

pub const Key = struct {
    encryption_round_key: [0x20]u8,
    reset_initialization_vector: [0x10]u8,
    public: [0x28]u8,
    private: ?[0x15]u8,
    curve_type: u32,
};

pub const KeySetIndex = struct {
    revision: u16,
    self_type: Self.ProgramIdentificationHeader.ProgramType,
};

pub const KeySet = std.AutoHashMap(KeySetIndex, Key);

pub const DrmType = enum(u32) {
    unknown = 0,
    network = 1,
    local = 2,
    free = 3,
    psp = 4,
    free_psp2_psm = 0xd,
    network_psp_psp2 = 0x100,
    gamecard_psp2 = 0x400,
    unknown_ps3 = 0x2000,
};

pub const Ecdsa224Signature = struct {
    r: [0x1c]u8,
    s: [0x1c]u8,

    pub fn read(reader: anytype) !Ecdsa224Signature {
        return .{
            .r = try reader.readBytesNoEof(0x1c),
            .s = try reader.readBytesNoEof(0x1c),
        };
    }
};

pub const SceSharedSecret = struct {
    shared_secret_0: [0x10]u8,
    klicensee: [0x10]u8,
    shared_secret_2: [0x10]u8,
    shared_secret_3: [4]u32,

    pub fn read(reader: anytype, endian: std.builtin.Endian) !SceSharedSecret {
        return .{
            .shared_secret_0 = try reader.readBytesNoEof(0x10),
            .klicensee = try reader.readBytesNoEof(0x10),
            .shared_secret_2 = try reader.readBytesNoEof(0x10),
            .shared_secret_3 = .{
                try reader.readInt(u32, endian),
                try reader.readInt(u32, endian),
                try reader.readInt(u32, endian),
                try reader.readInt(u32, endian),
            },
        };
    }
};

pub const Self = struct {
    pub const ExtendedHeader = struct {
        pub const Version = enum(u64) {
            ps3 = 3,
            vita = 4,
        };

        /// The version of the extended header
        ///
        /// aka header_type
        extended_header_version: Version,
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

        pub fn read(reader: anytype, endian: std.builtin.Endian) !ExtendedHeader {
            return .{
                .extended_header_version = try reader.readEnum(Version, endian),
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

        pub fn read(reader: anytype, endian: std.builtin.Endian) !ProgramIdentificationHeader {
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
            pub const PlaintextCapability = struct {
                ctrl_flag1: u32,
                unknown2: u32,
                unknown3: u32,
                unknown4: u32,
                unknown5: u32,
                unknown6: u32,
                unknown7: u32,
                unknown8: u32,

                pub fn read(reader: anytype, endian: std.builtin.Endian) !PlaintextCapability {
                    return .{
                        .ctrl_flag1 = try reader.readInt(u32, endian),
                        .unknown2 = try reader.readInt(u32, endian),
                        .unknown3 = try reader.readInt(u32, endian),
                        .unknown4 = try reader.readInt(u32, endian),
                        .unknown5 = try reader.readInt(u32, endian),
                        .unknown6 = try reader.readInt(u32, endian),
                        .unknown7 = try reader.readInt(u32, endian),
                        .unknown8 = try reader.readInt(u32, endian),
                    };
                }
            };
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

                pub fn read(reader: anytype, endian: std.builtin.Endian, size: usize) !Ps3ElfDigest {
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
                        else => return error.BadPs3ElfDigestSize,
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
                drm_type: DrmType,
                app_type: AppType,
                content_id: [0x30]u8,
                digest: [0x10]u8,
                cid_fn_hash: [0x10]u8,
                header_hash: [0x10]u8,
                limited_time_start: u64,
                limited_time_end: u64,

                pub fn read(reader: anytype, endian: std.builtin.Endian) !Ps3Npdrm {
                    if (!std.mem.eql(u8, &(try reader.readBytesNoEof(4)), "NPD\x00"))
                        return error.BadNpdMagic;

                    return .{
                        .version = try reader.readInt(u32, endian),
                        .drm_type = try reader.readEnum(DrmType, endian),
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

                pub fn read(reader: anytype, endian: std.builtin.Endian) !VitaElfDigest {
                    return .{
                        .constant = try reader.readBytesNoEof(0x14),
                        .elf_digest = try reader.readBytesNoEof(0x20),
                        .padding = try reader.readInt(u64, endian),
                        .min_required_fw = try reader.readInt(u32, endian),
                    };
                }
            };
            pub const VitaNpdrm = struct {
                finaled_flag: u32,
                drm_type: DrmType,
                padding: u32,
                content_id: [0x30]u8,
                digest: [0x10]u8,
                padding_78: [0x78]u8,
                sig: Ecdsa224Signature,

                pub fn read(reader: anytype, endian: std.builtin.Endian) !VitaNpdrm {
                    if (!std.mem.eql(u8, &(try reader.readBytesNoEof(4)), "\x7FDRM"))
                        return error.BadVitaNpdrmMagic;

                    return .{
                        .finaled_flag = try reader.readInt(u32, endian),
                        .drm_type = try reader.readEnum(DrmType, endian),
                        .padding = try reader.readInt(u32, endian),
                        .content_id = try reader.readBytesNoEof(0x30),
                        .digest = try reader.readBytesNoEof(0x10),
                        .padding_78 = try reader.readBytesNoEof(0x78),
                        .sig = try Ecdsa224Signature.read(reader),
                    };
                }
            };
            pub const VitaBootParam = struct {
                boot_param: [0x100]u8,

                pub fn read(reader: anytype) !VitaBootParam {
                    return .{
                        .boot_param = try reader.readBytesNoEof(0x100),
                    };
                }
            };

            plaintext_capability: PlaintextCapability,
            ps3_elf_digest: Ps3ElfDigest,
            ps3_npdrm: Ps3Npdrm,
            vita_elf_digest: VitaElfDigest,
            vita_npdrm: VitaNpdrm,
            vita_boot_param: VitaBootParam,
            vita_shared_secret: SceSharedSecret,
        };

        pub fn read(allocator: std.mem.Allocator, raw_reader: anytype, extended_header: ExtendedHeader, endian: std.builtin.Endian) ![]SupplementalHeader {
            var headers = std.ArrayList(SupplementalHeader).init(allocator);

            var counting_reader = std.io.countingReader(raw_reader);
            const reader = counting_reader.reader();

            while (extended_header.supplemental_header_size > 0) {
                counting_reader.bytes_read = 0;

                const header_type = try reader.readEnum(SupplementalHeaderType, endian);
                const size = try reader.readInt(u32, endian);
                const next = (try reader.readInt(u64, endian)) > 0;

                const supplemental_header: SupplementalHeader = switch (header_type) {
                    .plaintext_capability => .{ .plaintext_capability = try SupplementalHeader.PlaintextCapability.read(reader, endian) },
                    .ps3_elf_digest => .{ .ps3_elf_digest = try SupplementalHeader.Ps3ElfDigest.read(reader, endian, size) },
                    .ps3_npdrm => .{ .ps3_npdrm = try SupplementalHeader.Ps3Npdrm.read(reader, endian) },
                    .vita_elf_digest => .{ .vita_elf_digest = try SupplementalHeader.VitaElfDigest.read(reader, endian) },
                    .vita_npdrm => .{ .vita_npdrm = try SupplementalHeader.VitaNpdrm.read(reader, endian) },
                    .vita_boot_param => .{ .vita_boot_param = try SupplementalHeader.VitaBootParam.read(reader) },
                    .vita_shared_secret => .{ .vita_shared_secret = try SceSharedSecret.read(reader, endian) },
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
};

pub const CertifiedFile = struct {
    pub const Version = enum(u32) {
        ps3 = 2,
        vita = 3,
    };

    pub const Category = enum(u16) {
        /// A SELF or SPRX file, both PS3 and Vita
        ///
        /// See https://www.psdevwiki.com/ps3/SELF_-_SPRX
        signed_elf = 1,
        /// A revocation list, both PS3 and Vita
        ///
        /// See https://www.psdevwiki.com/ps3/Revoke_List
        signed_revoke_list = 2,
        /// A system software package, both PS3 and Vita
        ///
        /// See https://www.psdevwiki.com/ps3/PKG_files#System_Software_Update_Packages
        signed_package = 3,
        /// A signed security policy profile, PS3 only
        ///
        /// See https://www.psdevwiki.com/ps3/Default.spp
        signed_security_policy_profile = 4,
        /// A signed diff, Vita only
        signed_diff = 5,
        /// A signed PARAM.SFO file, Vita only
        signed_param_sfo = 6,
    };

    pub const Header = struct {
        pub const VitaData = struct {
            /// The size of the cerified file itself
            certified_file_size: u64,
            /// Padding, always set to 0
            padding: u64,
        };

        /// The version of the certified file
        version: Version,
        /// Corrosponds to the revision of the encryption key
        ///
        /// aka attribute
        key_revision: u16,
        /// The type of file contained with the certified file
        ///
        /// aka header_type
        category: Category,
        /// The size of the extended header, only applicable to SELF category files, set to 0 for all other categories
        ///
        /// aka metadata_offset
        extended_header_size: u32,
        /// The offset to the encapsulated data
        ///
        /// aka header_len
        file_offset: u64,
        /// The size of the encapsulated data
        ///
        /// aka data_len
        file_size: u64,
        /// Data only present on Vita certified files
        vita_data: ?VitaData,

        // The endianness of the rest of the file
        pub fn endianness(self: Header) std.builtin.Endian {
            return switch (self.version) {
                .ps3 => .big,
                .vita => .little,
            };
        }

        /// The size of the header in bytes
        pub fn byteSize(self: Header) usize {
            return switch (self.version) {
                .ps3 => 0x20,
                .vita => 0x30,
            };
        }

        pub fn read(reader: anytype) !Header {
            const endian: std.builtin.Endian = blk: {
                var magic: [4]u8 = undefined;
                try reader.readNoEof(&magic);

                break :blk if (std.mem.eql(u8, &magic, "SCE\x00"))
                    .big
                else if (std.mem.eql(u8, &magic, "\x00ECS"))
                    .little
                else
                    return error.InvalidMagic;
            };

            const version = try reader.readEnum(Version, endian);

            const header: Header = .{
                .version = version,
                .key_revision = try reader.readInt(u16, endian),
                .category = try reader.readEnum(Category, endian),
                .extended_header_size = try reader.readInt(u32, endian),
                .file_offset = try reader.readInt(u64, endian),
                .file_size = try reader.readInt(u64, endian),
                .vita_data = if (version == .vita) .{
                    .certified_file_size = try reader.readInt(u64, endian),
                    .padding = try reader.readInt(u64, endian),
                } else null,
            };

            return header;
        }
    };

    pub const EncryptionRootHeader = struct {
        key: [0x10]u8,
        key_pad: [0x10]u8,
        iv: [0x10]u8,
        iv_pad: [0x10]u8,

        pub fn read(reader: anytype, key: Key) !EncryptionRootHeader {
            var header: [0x40]u8 = undefined;
            try reader.readNoEof(&header);

            try pretty.print(std.heap.page_allocator, .{
                .header = header,
                .erk = key.encryption_round_key,
                .riv = key.reset_initialization_vector,
            }, .{});

            var ctx: aes.aes_context = std.mem.zeroes(aes.aes_context);
            _ = aes.aes_setkey_dec(&ctx, &key.encryption_round_key, key.encryption_round_key.len * 8);

            var iv = key.reset_initialization_vector;
            _ = aes.aes_crypt_cbc(&ctx, aes.AES_DECRYPT, header.len, &iv, &header, &header);

            const ret: EncryptionRootHeader = .{
                .key = header[0..0x10].*,
                .key_pad = header[0x10..0x20].*,
                .iv = header[0x20..0x30].*,
                .iv_pad = header[0x30..0x40].*,
            };

            // Ensure padding is all zeroes
            if (!std.mem.allEqual(u8, &ret.iv_pad, 0) or !std.mem.allEqual(u8, &ret.key_pad, 0)) {
                return error.BadPadding;
            }

            return ret;
        }
    };

    pub const CertificationHeader = struct {
        sign_offset: u64,
        sign_algorithm: u32,
        cert_entry_num: u32,
        attr_entry_num: u32,
        optional_header_size: u32,
        pad: u64,

        pub fn read(reader: anytype, key: EncryptionRootHeader, endian: std.builtin.Endian) !CertificationHeader {
            var header: [0x20]u8 = undefined;
            try reader.readNoEof(&header);

            const aes128 = Aes128.initEnc(key.key);
            std.crypto.core.modes.ctr(@TypeOf(aes128), aes128, &header, &header, key.iv, endian);

            return .{
                .sign_offset = std.mem.readInt(u64, header[0..0x08], endian),
                .sign_algorithm = std.mem.readInt(u32, header[0x08..0x0c], endian),
                .cert_entry_num = std.mem.readInt(u32, header[0x0c..0x10], endian),
                .attr_entry_num = std.mem.readInt(u32, header[0x10..0x14], endian),
                .optional_header_size = std.mem.readInt(u32, header[0x14..0x18], endian),
                .pad = std.mem.readInt(u64, header[0x18..0x20], endian),
            };
        }
    };
};
