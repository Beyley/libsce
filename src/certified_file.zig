const std = @import("std");

const aes = @import("aes");

const sce = @import("sce.zig");
const system_keyset = @import("system_keyset.zig");
const npdrm_keyset = @import("npdrm_keyset.zig");

const Self = @import("Self.zig");

const Aes128 = std.crypto.core.aes.Aes128;

pub const Error = error{
    InvalidCertifiedFileMagic,
    OnlySelfSupported,
    FakeSelfUnsupported,
    MissingNpdrmSupplementalHeader,
    MissingNpdrmKlicKey,
    MissingNpdrmKlicFreeKey,
    MissingRap,
    InvalidRap,
    UnknownNpdrmType,
    OptionalHeaderSizeMismatch,
    OptionalHeaderTableSizeMismatch,
    UnsupportedSignatureType,
    UnsupportedAes128CbcCfbSegment,
    InvalidEncryptionRootHeaderPadding,
} || std.fs.File.Reader.ReadEnumError || std.fs.File.OpenError || Self.Error || npdrm_keyset.Error;

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

    pub fn read(reader: anytype) Error!Header {
        const endian: std.builtin.Endian = blk: {
            var magic: [4]u8 = undefined;
            try reader.readNoEof(&magic);

            break :blk if (std.mem.eql(u8, &magic, "SCE\x00"))
                .big
            else if (std.mem.eql(u8, &magic, "\x00ECS"))
                .little
            else
                return Error.InvalidCertifiedFileMagic;
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

/// aka metadata info
pub const EncryptionRootHeader = struct {
    key: [0x10]u8,
    key_pad: [0x10]u8,
    iv: [0x10]u8,
    iv_pad: [0x10]u8,

    pub fn byteSize(self: EncryptionRootHeader) usize {
        _ = self;
        return 0x10 * 4;
    }

    pub fn readNpdrm(
        reader: anytype,
        self: Self,
        rap_path: ?[]const u8,
        npdrm_keys: npdrm_keyset.KeySet,
        system_key: system_keyset.Key,
    ) Error!EncryptionRootHeader {
        // Search for the PS3 NPDRM header
        const npdrm_header = blk: {
            for (self.supplemental_headers) |supplemental_header| {
                if (supplemental_header == .ps3_npdrm)
                    break :blk supplemental_header.ps3_npdrm;
            }

            return Error.MissingNpdrmSupplementalHeader;
        };

        // Get the key used to decrypt the NPDRM key
        const klic_key = (npdrm_keys.get(.klic_key) orelse return Error.MissingNpdrmKlicKey).aes;
        // Read the NPDRM key
        var npdrm_key: npdrm_keyset.Key.AesKey =
            if (npdrm_header.drm_type == .free)
            // If the CF uses the free NPDRM key, use that
            (npdrm_keys.get(.klic_free) orelse return Error.MissingNpdrmKlicFreeKey).aes
        else if (npdrm_header.drm_type == .local) blk: {
            // If the CF uses a local license, we need to load then decrypt that

            // TODO: RIF+act.dat+IDPS reading
            var rap_file: [0x10]u8 = undefined;
            if ((try std.fs.cwd().readFile(rap_path orelse return Error.MissingRap, &rap_file)).len != rap_file.len)
                return Error.InvalidRap;

            // Convert the RAP file to a Klicensee
            break :blk .{
                .erk = try npdrm_keyset.rapToKlicensee(rap_file, npdrm_keys),
                .riv = .{0} ** 0x10,
            };
        } else {
            // Return an error if we can't handle this NPDRM type
            return Error.UnknownNpdrmType;
        };

        var aes_ctxt: aes.aes_context = undefined;

        // Decrypt the npdrm key
        _ = aes.aes_setkey_dec(&aes_ctxt, &klic_key.erk, @bitSizeOf(@TypeOf(klic_key.erk)));
        _ = aes.aes_crypt_ecb(&aes_ctxt, aes.AES_DECRYPT, &npdrm_key.erk, &npdrm_key.erk);

        // Read the encrypted header
        var header: [0x40]u8 = undefined;
        try reader.readNoEof(&header);

        // Remove the npdrm layer
        var iv: [0x10]u8 = .{0} ** 0x10;
        _ = aes.aes_setkey_dec(&aes_ctxt, &npdrm_key.erk, @bitSizeOf(@TypeOf(npdrm_key.erk)));
        _ = aes.aes_crypt_cbc(&aes_ctxt, aes.AES_DECRYPT, header.len, &iv, &header, &header);

        // Remove the system encryption layer
        iv = system_key.reset_initialization_vector;
        _ = aes.aes_setkey_dec(&aes_ctxt, &system_key.encryption_round_key, @bitSizeOf(@TypeOf(system_key.encryption_round_key)));
        _ = aes.aes_crypt_cbc(&aes_ctxt, aes.AES_DECRYPT, header.len, &iv, &header, &header);

        const ret: EncryptionRootHeader = .{
            .key = header[0..0x10].*,
            .key_pad = header[0x10..0x20].*,
            .iv = header[0x20..0x30].*,
            .iv_pad = header[0x30..0x40].*,
        };

        // Ensure padding is all zeroes
        if (!std.mem.allEqual(u8, &ret.iv_pad, 0) or !std.mem.allEqual(u8, &ret.key_pad, 0)) {
            return Error.InvalidEncryptionRootHeaderPadding;
        }

        return ret;
    }

    pub fn read(reader: anytype, key: system_keyset.Key) Error!EncryptionRootHeader {
        var header: [0x40]u8 = undefined;
        try reader.readNoEof(&header);

        var ctx: aes.aes_context = undefined;

        // Remove the system encryption layer
        var iv = key.reset_initialization_vector;
        _ = aes.aes_setkey_dec(&ctx, &key.encryption_round_key, key.encryption_round_key.len * 8);
        _ = aes.aes_crypt_cbc(&ctx, aes.AES_DECRYPT, header.len, &iv, &header, &header);

        const ret: EncryptionRootHeader = .{
            .key = header[0..0x10].*,
            .key_pad = header[0x10..0x20].*,
            .iv = header[0x20..0x30].*,
            .iv_pad = header[0x30..0x40].*,
        };

        // Ensure padding is all zeroes
        if (!std.mem.allEqual(u8, &ret.iv_pad, 0) or !std.mem.allEqual(u8, &ret.key_pad, 0)) {
            return Error.InvalidEncryptionRootHeaderPadding;
        }

        return ret;
    }
};

/// aka metadata header
pub const CertificationHeader = struct {
    sign_offset: u64,
    sign_algorithm: SigningAlgorithm,
    cert_entry_num: u32,
    attr_entry_num: u32,
    optional_header_size: u32,
    pad: u64,

    /// Reads a pre-decrypted certification header
    pub fn read(reader: anytype, endian: std.builtin.Endian) Error!CertificationHeader {
        var header: [0x20]u8 = undefined;
        try reader.readNoEof(&header);

        return .{
            .sign_offset = std.mem.readInt(u64, header[0..0x08], endian),
            .sign_algorithm = try std.meta.intToEnum(SigningAlgorithm, std.mem.readInt(u32, header[0x08..0x0c], endian)),
            .cert_entry_num = std.mem.readInt(u32, header[0x0c..0x10], endian),
            .attr_entry_num = std.mem.readInt(u32, header[0x10..0x14], endian),
            .optional_header_size = std.mem.readInt(u32, header[0x14..0x18], endian),
            .pad = std.mem.readInt(u64, header[0x18..0x20], endian),
        };
    }
};

pub const SigningAlgorithm = enum(u32) {
    ecdsa160 = 1,
    hmac_sha1 = 2,
    sha1 = 3,
    rsa2048 = 5,
    hmac_sha256 = 6,
};

/// aka metadata section header
pub const SegmentCertificationHeader = struct {
    pub const SegmentType = enum(u32) {
        shdr = 1,
        phdr = 2,
        sceversion = 3,
    };

    pub const EncryptionAlgorithm = enum(u32) {
        none = 1,
        aes128_cbc_cfb = 2,
        aes128_ctr = 3,
    };

    segment_offset: u64,
    segment_size: u64,
    segment_type: SegmentType,
    segment_id: u32,
    signing_algorithm: SigningAlgorithm,
    signing_idx: u32,
    encryption_algorithm: EncryptionAlgorithm,
    key_idx: ?u32,
    iv_idx: ?u32,
    compression_algorithm: sce.CompressionAlgorithm,

    pub fn byteSize(self: SegmentCertificationHeader) usize {
        _ = self;

        return 0x30;
    }

    pub fn read(reader: anytype, allocator: std.mem.Allocator, certifiction_header: CertificationHeader, endian: std.builtin.Endian) Error![]SegmentCertificationHeader {
        const headers = try allocator.alloc(SegmentCertificationHeader, certifiction_header.cert_entry_num);
        errdefer allocator.free(headers);

        for (headers) |*header| {
            header.* = try readSingle(reader, endian);
        }

        return headers;
    }

    pub fn readSingle(reader: anytype, endian: std.builtin.Endian) Error!SegmentCertificationHeader {
        return .{
            .segment_offset = try reader.readInt(u64, endian),
            .segment_size = try reader.readInt(u64, endian),
            .segment_type = try reader.readEnum(SegmentType, endian),
            .segment_id = try reader.readInt(u32, endian),
            .signing_algorithm = try reader.readEnum(SigningAlgorithm, endian),
            .signing_idx = try reader.readInt(u32, endian),
            .encryption_algorithm = try reader.readEnum(EncryptionAlgorithm, endian),
            .key_idx = blk: {
                const idx = try reader.readInt(u32, endian);
                break :blk if (idx == 0xFFFFFFFF) null else idx;
            },
            .iv_idx = blk: {
                const idx = try reader.readInt(u32, endian);
                break :blk if (idx == 0xFFFFFFFF) null else idx;
            },
            .compression_algorithm = try reader.readEnum(sce.CompressionAlgorithm, endian),
        };
    }
};

pub const OptionalHeader = union(Type) {
    pub const Type = enum(u32) {
        capability = 1,
        individual_seed = 2,
        attribute = 3,
    };

    capability: sce.EncryptedCapability,
    individual_seed: [0x100]u8,
    attribute: [0x20]u8,

    pub const IndividualSeed = [0x100]u8;
    pub const Attribute = [0x20]u8;

    pub fn read(raw_reader: anytype, allocator: std.mem.Allocator, certifiction_header: CertificationHeader, endian: std.builtin.Endian) Error![]OptionalHeader {
        if (certifiction_header.optional_header_size == 0)
            return &.{};

        var optional_headers = std.ArrayList(OptionalHeader).init(allocator);
        errdefer optional_headers.deinit();

        var counting_reader = std.io.countingReader(raw_reader);
        const reader = counting_reader.reader();

        var total_read: u64 = 0;
        var to_read: u64 = certifiction_header.optional_header_size;
        while (to_read > 0) : (to_read -= counting_reader.bytes_read) {
            defer counting_reader.bytes_read = 0;

            const header_size = @sizeOf(Type) + @sizeOf(u32) + @sizeOf(u64);

            const optional_header_type = try reader.readEnum(Type, endian);
            const size = try reader.readInt(u32, endian) - header_size;
            const next = try reader.readInt(u64, endian) > 0;

            const read_start = counting_reader.bytes_read;

            try optional_headers.append(switch (optional_header_type) {
                .capability => .{ .capability = try sce.EncryptedCapability.read(reader, endian) },
                .individual_seed => .{ .individual_seed = try reader.readBytesNoEof(@sizeOf(IndividualSeed)) },
                .attribute => .{ .attribute = try reader.readBytesNoEof(@sizeOf(Attribute)) },
            });

            total_read += counting_reader.bytes_read;

            if (counting_reader.bytes_read - read_start != size)
                return Error.OptionalHeaderSizeMismatch;

            if (!next) break;
        }

        if (total_read != certifiction_header.optional_header_size)
            return Error.OptionalHeaderTableSizeMismatch;

        return optional_headers.toOwnedSlice();
    }
};

pub const Signature = union(SigningAlgorithm) {
    ecdsa160: sce.Ecdsa160Signature,
    hmac_sha1: void,
    sha1: void,
    rsa2048: sce.Rsa2048Signature,
    hmac_sha256: void,

    pub fn read(reader: anytype, certification_header: CertificationHeader) Error!Signature {
        return switch (certification_header.sign_algorithm) {
            .ecdsa160 => .{ .ecdsa160 = try sce.Ecdsa160Signature.read(reader) },
            .rsa2048 => .{ .rsa2048 = try sce.Rsa2048Signature.read(reader) },
            else => Error.UnsupportedSignatureType, // https://www.psdevwiki.com/ps3/Certified_File#Signature
        };
    }
};

pub fn read(
    allocator: std.mem.Allocator,
    cf_data: []u8,
    rap_path: ?[]const u8,
    system_keys: system_keyset.KeySet,
    npdrm_keys: npdrm_keyset.KeySet,
) Error!CertifiedFile {
    var stream = std.io.fixedBufferStream(cf_data);

    const reader = stream.reader();

    const header = try Header.read(reader);
    const endianness = header.endianness();

    // TODO: non-SELF file extraction
    if (header.category != .signed_elf)
        return Error.OnlySelfSupported;

    const self = try Self.read(cf_data, &stream, allocator, endianness);
    errdefer self.deinit(allocator);

    // If this is a fake certified file, none of the following contents are present, and there's no encryption
    if (header.key_revision == 0x8000)
        return .{
            .fake = .{
                .header = header,
                .contents = .{ .signed_elf = self },
            },
        };

    const system_key = system_keys.get(.{
        .revision = header.key_revision,
        .self_type = self.program_identification_header.program_type,
    }) orelse return .{ .missing_system_key = .{
        .header = header,
        .contents = .{ .signed_elf = self },
    } };

    // Seek past the extended header
    try stream.seekTo(header.byteSize() + header.extended_header_size);

    // NPDRM applications need to have their encryption root header read differently
    const encryption_root_header = if (header.category == .signed_elf and self.program_identification_header.program_type == .npdrm_application)
        EncryptionRootHeader.readNpdrm(reader, self, rap_path, npdrm_keys, system_key) catch |err| {
            return switch (err) {
                Error.MissingNpdrmKlicKey,
                Error.MissingNpdrmKlicFreeKey,
                Error.MissingRap,
                Error.UnknownNpdrmType,
                Error.InvalidEncryptionRootHeaderPadding,
                Error.MissingRapInitKey,
                Error.MissingRapPBoxKey,
                Error.MissingRapE1Key,
                Error.MissingRapE2Key,
                => .{ .missing_npdrm_key = .{
                    .header = header,
                    .contents = .{ .signed_elf = self },
                } },
                else => err,
            };
        }
    else
        try EncryptionRootHeader.read(reader, system_key);

    { // Decrypt all bytes from now until the start of the encapsulated file
        const pos = try stream.getPos();
        const len = header.file_offset - (header.byteSize() + header.extended_header_size + encryption_root_header.byteSize());

        if (pos > std.math.maxInt(usize) or len > std.math.maxInt(usize))
            return Error.InvalidPosOrSizeForPlatform;

        const data = cf_data[@intCast(pos)..@intCast(pos + len)];

        // decrypt the certification header, segment certification header, and keys
        const aes128 = Aes128.initEnc(encryption_root_header.key);
        std.crypto.core.modes.ctr(@TypeOf(aes128), aes128, data, data, encryption_root_header.iv, endianness);
    }

    const certification_header = try CertificationHeader.read(reader, endianness);

    const segment_certification_headers = try SegmentCertificationHeader.read(reader, allocator, certification_header, endianness);
    errdefer allocator.free(segment_certification_headers);

    // TODO: what the hell is psdevwiki talking about with "attributes"?
    //       we are following what RPCS3/scetool does by reading these as a series of 16-byte keys
    //       psdevwiki: https://www.psdevwiki.com/ps3/Certified_File#Attributes
    //       rpcs3: https://github.com/RPCS3/rpcs3/blob/3e516df214f5c36d4b613aa0580182155247d2ad/rpcs3/Crypto/unself.cpp#L687
    const keys = try allocator.alloc([0x10]u8, certification_header.attr_entry_num);
    errdefer allocator.free(keys);
    for (keys) |*key| try reader.readNoEof(key);

    const optional_headers = try OptionalHeader.read(reader, allocator, certification_header, endianness);
    errdefer allocator.free(optional_headers);

    const signature = try Signature.read(reader, certification_header);

    return .{
        .full = .{
            .header = header,
            .encryption_root_header = encryption_root_header,
            .certification_header = certification_header,
            .segment_certification_headers = segment_certification_headers,
            .keys = keys,
            .optional_headers = optional_headers,
            .signature = signature,
            .contents = .{
                .signed_elf = self,
            },
            .body_decrypted = false,
            .cf_data = cf_data,
        },
    };
}

pub const CertifiedFile = union(enum) {
    /// The full read Certified File
    pub const Full = struct {
        header: Header,
        encryption_root_header: EncryptionRootHeader,
        certification_header: CertificationHeader,
        segment_certification_headers: []const SegmentCertificationHeader,
        keys: []const [0x10]u8,
        optional_headers: []const OptionalHeader,
        signature: Signature,
        contents: Contents,
        cf_data: []u8,
        body_decrypted: bool,

        pub fn decryptBody(self: *Full) !void {
            for (self.segment_certification_headers) |segment_header| {
                if (segment_header.encryption_algorithm != .none) {
                    // Skip segments which are missing a key/iv
                    if (segment_header.key_idx == null or segment_header.iv_idx == null) {
                        continue;
                    }

                    const key_idx = segment_header.key_idx.?;
                    const iv_idx = segment_header.iv_idx.?;

                    // Skip segments with invalid key/iv
                    if (key_idx >= self.certification_header.attr_entry_num or iv_idx >= self.certification_header.attr_entry_num) {
                        continue;
                    }

                    if (segment_header.segment_offset > std.math.maxInt(usize) or segment_header.segment_size > std.math.maxInt(usize))
                        return Error.InvalidPosOrSizeForPlatform;

                    const data = self.cf_data[@intCast(segment_header.segment_offset)..@intCast(segment_header.segment_offset + segment_header.segment_size)];

                    switch (segment_header.encryption_algorithm) {
                        .aes128_ctr => {
                            const aes128 = Aes128.initEnc(self.keys[key_idx]);
                            std.crypto.core.modes.ctr(@TypeOf(aes128), aes128, data, data, self.keys[iv_idx], self.header.endianness());
                        },
                        .aes128_cbc_cfb => {
                            // TODO: lets throw an error so we can hopefully find one of these cbc_cfb SELFs in the wild, and implement support!
                            return Error.UnsupportedAes128CbcCfbSegment;
                        },
                        .none => unreachable,
                    }
                }
            }

            self.body_decrypted = true;
        }
    };

    /// A partially read certified file, returned when a key is missing
    pub const MissingKey = struct {
        header: Header,
        contents: Contents,
    };

    /// A partially read certified file, returned when a key is missing
    pub const Fake = struct {
        header: Header,
        contents: Contents,
    };

    full: Full,
    fake: Fake,
    missing_system_key: MissingKey,
    missing_npdrm_key: MissingKey,

    pub fn deinit(self: CertifiedFile, allocator: std.mem.Allocator) void {
        switch (self) {
            .full => |full| {
                full.contents.deinit(allocator);
                allocator.free(full.segment_certification_headers);
                allocator.free(full.optional_headers);
                allocator.free(full.keys);
            },
            inline .missing_system_key, .missing_npdrm_key, .fake => |missing_key| {
                missing_key.contents.deinit(allocator);
            },
        }
    }
};

pub const Contents = union(Category) {
    signed_elf: Self,
    signed_revoke_list: void,
    signed_package: void,
    signed_security_policy_profile: void,
    signed_diff: void,
    signed_param_sfo: void,

    pub fn deinit(self: Contents, allocator: std.mem.Allocator) void {
        switch (self) {
            .signed_elf => |signed_elf| signed_elf.deinit(allocator),
            else => {},
        }
    }
};
