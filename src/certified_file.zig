const std = @import("std");

const aes = @import("aes");

const sce = @import("sce.zig");
const system_keyset = @import("system_keyset.zig");
const npdrm_keyset = @import("npdrm_keyset.zig");

const Self = @import("Self.zig");

const Aes128 = std.crypto.core.aes.Aes128;

const log = std.log.scoped(.certified_file);

pub const Error = error{
    InvalidCertifiedFileMagic,
    OnlySelfSupported,
    FakeSelfUnsupported,
    MissingNpdrmSupplementalHeader,
    MissingNpdrmKlicKey,
    MissingNpdrmKlicFreeKey,
    MissingLicense,
    InvalidRapFile,
    UnknownNpdrmType,
    OptionalHeaderSizeMismatch,
    OptionalHeaderTableSizeMismatch,
    UnsupportedSignatureType,
    UnsupportedAes128CbcCfbSegment,
    InvalidEncryptionRootHeaderPadding,
    InvalidPosOrSizeForPlatform,
    MissingVitaData,
} || std.fs.File.Reader.ReadEnumError || std.fs.File.OpenError || Self.Error || npdrm_keyset.Error;

pub const Version = enum(u32) {
    ps3 = 2,
    vita = 3,
};

/// See https://www.psdevwiki.com/ps3/Certified_File#Category
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

    pub fn versionByteSize(version: Version) usize {
        return switch (version) {
            .ps3 => 0x20,
            .vita => 0x30,
        };
    }

    /// The size of the header in bytes
    pub fn byteSize(self: Header) usize {
        return versionByteSize(self.version);
    }

    pub fn read(reader: anytype) Error!Header {
        const endian: std.builtin.Endian = blk: {
            var magic: [4]u8 = undefined;
            try reader.readNoEof(&magic);

            break :blk if (std.mem.eql(u8, &magic, "SCE\x00"))
                .big
            else if (std.mem.eql(u8, &magic, "\x00ECS"))
                .little
            else {
                log.err("File has unknown magic of {x}", .{magic});
                return Error.InvalidCertifiedFileMagic;
            };
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

    pub fn write(self: Header, writer: anytype) Error!void {
        const endian = self.endianness();

        switch (endian) {
            .big => try writer.writeAll("SCE\x00"),
            .little => try writer.writeAll("\x00ECS"),
        }

        try writer.writeInt(std.meta.Tag(Version), @intFromEnum(self.version), endian);
        try writer.writeInt(u16, self.key_revision, endian);
        try writer.writeInt(std.meta.Tag(Category), @intFromEnum(self.category), endian);
        try writer.writeInt(u32, self.extended_header_size, endian);
        try writer.writeInt(u64, self.file_offset, endian);
        try writer.writeInt(u64, self.file_size, endian);

        if (self.version == .vita) {
            const vita_data = self.vita_data orelse return Error.MissingVitaData;

            try writer.writeInt(u64, vita_data.certified_file_size, endian);
            try writer.writeInt(u64, vita_data.padding, endian);
        }
    }
};

pub const LicenseData = union(enum) {
    pub const Rif = struct {
        rif: sce.RightsInformationFile,
        act_dat: sce.ActivationData,
        idps: [0x10]u8,
    };

    rap: [0x10]u8,
    rif: Rif,
    none: void,
};

/// Contains the decryption key and IV to decrypt the `CertificationHeader` and certification body (`SegmentCertificationHeader`, the file keys, and the `OptionalHeader` table)
///
/// See https://www.psdevwiki.com/ps3/Certified_File#Encryption_Root_Header
///
/// aka metadata info
pub const EncryptionRootHeader = struct {
    /// The decrypted key to use
    key: [0x10]u8,
    /// Padding bytes. Always equal to .{0} ** 0x10
    key_pad: [0x10]u8,
    /// The decrypted IV to use
    iv: [0x10]u8,
    /// Padding bytes. Always equal to .{0} ** 0x10
    iv_pad: [0x10]u8,

    pub fn byteSize(self: EncryptionRootHeader) usize {
        _ = self;
        return 0x10 * 4;
    }

    pub fn readNpdrm(
        reader: anytype,
        self: Self,
        license_data: LicenseData,
        npdrm_keys: npdrm_keyset.KeySet,
        system_key: system_keyset.Key,
        endian: std.builtin.Endian,
    ) Error!EncryptionRootHeader {
        log.info("Reading NPDRM encryption root header", .{});

        // Search for the PS3 NPDRM header
        const npdrm_header = blk: {
            for (self.supplemental_headers) |supplemental_header| {
                if (supplemental_header == .ps3_npdrm)
                    break :blk supplemental_header.ps3_npdrm;
            }

            log.err("Attempted to read NPDRM encryption root header, but SELF has no PS3 NPDRM supplemental header", .{});
            return Error.MissingNpdrmSupplementalHeader;
        };

        log.info("Got NPDRM header with content ID {s}", .{npdrm_header.content_id});

        // Get the key used to decrypt the NPDRM key
        const klic_key = try npdrm_keyset.getKeyOrError(npdrm_keys, .klic_key, Error.MissingNpdrmKlicKey);

        // Read the NPDRM key
        var npdrm_key: [0x10]u8 =
            if (npdrm_header.drm_type == .free)
            // If the CF uses the free NPDRM key, use that
            try npdrm_keyset.getKeyOrError(npdrm_keys, .klic_free, Error.MissingNpdrmKlicFreeKey)
        else if (npdrm_header.drm_type == .local)
            // If the CF uses a local license, we need to load then decrypt that
            switch (license_data) {
                .none => {
                    log.err("Wanted a license to decrypt encryption root header, but none was provided", .{});
                    return Error.MissingLicense;
                },
                .rap => |rap| try npdrm_keyset.rapToKlicensee(rap, npdrm_keys),
                .rif => |rif| try npdrm_keyset.loadKlicensee(rif.rif, rif.act_dat, rif.idps, npdrm_keys, endian),
            }
        else {
            log.err("Unhandled DRM type {s}", .{@tagName(npdrm_header.drm_type)});
            return Error.UnknownNpdrmType;
        };

        var aes_ctxt: aes.aes_context = undefined;

        // Decrypt the npdrm key
        _ = aes.aes_setkey_dec(&aes_ctxt, &klic_key, @bitSizeOf(@TypeOf(klic_key)));
        _ = aes.aes_crypt_ecb(&aes_ctxt, aes.AES_DECRYPT, &npdrm_key, &npdrm_key);

        log.info("Decrypted NPDRM key", .{});

        // Read the encrypted header
        var header: [0x40]u8 = undefined;
        try reader.readNoEof(&header);

        // Remove the npdrm layer
        var iv: [0x10]u8 = .{0} ** 0x10;
        _ = aes.aes_setkey_dec(&aes_ctxt, &npdrm_key, @bitSizeOf(@TypeOf(npdrm_key)));
        _ = aes.aes_crypt_cbc(&aes_ctxt, aes.AES_DECRYPT, header.len, &iv, &header, &header);

        log.info("Removed NPDRM layer from encryption root header", .{});

        // Remove the system encryption layer
        iv = system_key.reset_initialization_vector;
        _ = aes.aes_setkey_dec(&aes_ctxt, &system_key.encryption_round_key, @bitSizeOf(@TypeOf(system_key.encryption_round_key)));
        _ = aes.aes_crypt_cbc(&aes_ctxt, aes.AES_DECRYPT, header.len, &iv, &header, &header);

        log.info("Removed system layer from encryption root header", .{});

        const ret: EncryptionRootHeader = .{
            .key = header[0..0x10].*,
            .key_pad = header[0x10..0x20].*,
            .iv = header[0x20..0x30].*,
            .iv_pad = header[0x30..0x40].*,
        };

        // Ensure padding is all zeroes
        if (!std.mem.allEqual(u8, &ret.iv_pad, 0) or !std.mem.allEqual(u8, &ret.key_pad, 0)) {
            log.err("Encryption root header padding is not all zeroes! This is likely a decryption error, please make sure the right license is in use!", .{});
            return Error.InvalidEncryptionRootHeaderPadding;
        }

        return ret;
    }

    pub fn read(reader: anytype, key: system_keyset.Key) Error!EncryptionRootHeader {
        log.info("Reading non-NPDRM encryption root header", .{});

        var header: [0x40]u8 = undefined;
        try reader.readNoEof(&header);

        var ctx: aes.aes_context = undefined;

        // Remove the system encryption layer
        var iv = key.reset_initialization_vector;
        _ = aes.aes_setkey_dec(&ctx, &key.encryption_round_key, key.encryption_round_key.len * 8);
        _ = aes.aes_crypt_cbc(&ctx, aes.AES_DECRYPT, header.len, &iv, &header, &header);

        log.info("Removed system layer from encryption root header", .{});

        const ret: EncryptionRootHeader = .{
            .key = header[0..0x10].*,
            .key_pad = header[0x10..0x20].*,
            .iv = header[0x20..0x30].*,
            .iv_pad = header[0x30..0x40].*,
        };

        // Ensure padding is all zeroes
        if (!std.mem.allEqual(u8, &ret.iv_pad, 0) or !std.mem.allEqual(u8, &ret.key_pad, 0)) {
            log.err("Encryption root header padding is not all zeroes! This is likely a decryption error, please make sure the right license is in use!", .{});
            return Error.InvalidEncryptionRootHeaderPadding;
        }

        return ret;
    }

    pub fn write(
        self: EncryptionRootHeader,
        writer: anytype,
        klic: ?[0x10]u8,
        key: system_keyset.Key,
        npdrm_keys: npdrm_keyset.KeySet,
    ) Error!void {
        var ctx: aes.aes_context = undefined;

        var header: [0x40]u8 = undefined;

        // Ensure padding is all zeroes
        if (!std.mem.allEqual(u8, &self.iv_pad, 0) or !std.mem.allEqual(u8, &self.key_pad, 0)) {
            log.err("Encryption root header padding is not all zeroes! This is likely a logic error when creating the ERH!", .{});
            return Error.InvalidEncryptionRootHeaderPadding;
        }

        header[0..0x10].* = self.key;
        header[0x10..0x20].* = self.key_pad;
        header[0x20..0x30].* = self.iv;
        header[0x30..0x40].* = self.iv_pad;

        // Encrypt with the system encryption layer
        var iv = key.reset_initialization_vector;
        _ = aes.aes_setkey_enc(&ctx, &key.encryption_round_key, @bitSizeOf(@TypeOf(key.encryption_round_key)));
        _ = aes.aes_crypt_cbc(&ctx, aes.AES_ENCRYPT, header.len, &iv, &header, &header);

        // If an encrypted NPDRM klicensee is specified, decrypt it, then use it to add the NPDRM encryption layer
        if (klic != null) {
            var klicensee = klic.?;

            const klic_key = try npdrm_keyset.getKeyOrError(npdrm_keys, .klic_key, Error.MissingNpdrmKlicKey);

            // Decrypt the klicensee
            _ = aes.aes_setkey_dec(&ctx, &klic_key, klic_key.len * 8);
            _ = aes.aes_crypt_ecb(&ctx, aes.AES_DECRYPT, &klicensee, &klicensee);

            // Add the NPDRM encryption layer to the ERH
            iv = @splat(0);
            _ = aes.aes_setkey_enc(&ctx, &klicensee, klicensee.len * 8);
            _ = aes.aes_crypt_cbc(&ctx, aes.AES_ENCRYPT, header.len, &iv, &header, &header);
        }

        try writer.writeAll(&header);
    }
};

/// Contains information about the certification/encryption of the data
///
/// See https://www.psdevwiki.com/ps3/Certified_File#Certification_Header
///
/// aka metadata header
pub const CertificationHeader = struct {
    /// The offset in the certified file to where the `Signature` struct is located
    signature_offset: u64,
    /// The algorithm used to certify the app
    signature_algorithm: SigningAlgorithm,
    /// The amount of `SegmentCertificationHeader`s that are present
    cert_entry_num: u32,
    /// The amount of keys in the app
    attr_entry_num: u32,
    /// The size of the optional header table
    optional_header_size: u32,
    /// Padding
    padding: u64,

    /// Reads a pre-decrypted certification header
    pub fn read(reader: anytype, endian: std.builtin.Endian) Error!CertificationHeader {
        return .{
            .signature_offset = try reader.readInt(u64, endian),
            .signature_algorithm = try reader.readEnum(SigningAlgorithm, endian),
            .cert_entry_num = try reader.readInt(u32, endian),
            .attr_entry_num = try reader.readInt(u32, endian),
            .optional_header_size = try reader.readInt(u32, endian),
            .padding = try reader.readInt(u64, endian),
        };
    }

    pub fn write(self: CertificationHeader, writer: anytype, endian: std.builtin.Endian) Error!void {
        try writer.writeInt(u64, self.signature_offset, endian);
        try writer.writeInt(std.meta.Tag(SigningAlgorithm), @intFromEnum(self.signature_algorithm), endian);
        try writer.writeInt(u32, self.cert_entry_num, endian);
        try writer.writeInt(u32, self.attr_entry_num, endian);
        try writer.writeInt(u32, self.optional_header_size, endian);
        try writer.writeInt(u64, self.padding, endian);
    }
};

pub const SigningAlgorithm = enum(u32) {
    ecdsa160 = 1,
    hmac_sha1 = 2,
    sha1 = 3,
    rsa2048 = 5,
    hmac_sha256 = 6,
};

///
///
/// See https://www.psdevwiki.com/ps3/Certified_File#Segment_Certification_Header
///
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

    /// An offset into the certified file where the segment starts
    segment_offset: u64,
    /// The size of the segment
    segment_size: u64,
    /// The type of the segment
    segment_type: SegmentType,
    /// The ID of the segment
    segment_id: u32,
    /// The signature algorithm used to sign this segment
    signature_algorithm: SigningAlgorithm,
    signature_idx: u32,
    /// The algorithm used to encrypt this segment
    encryption_algorithm: EncryptionAlgorithm,
    /// The key index used to decrypt this segment
    key_idx: ?u32,
    /// The IV index used to decrypt this segment
    iv_idx: ?u32,
    /// The compression algorithm in use for this segment
    compression_algorithm: sce.CompressionAlgorithm,

    const null_idx: u32 = 0xFFFFFFFF;

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

    fn readSingle(reader: anytype, endian: std.builtin.Endian) Error!SegmentCertificationHeader {
        return .{
            .segment_offset = try reader.readInt(u64, endian),
            .segment_size = try reader.readInt(u64, endian),
            .segment_type = try reader.readEnum(SegmentType, endian),
            .segment_id = try reader.readInt(u32, endian),
            .signature_algorithm = try reader.readEnum(SigningAlgorithm, endian),
            .signature_idx = try reader.readInt(u32, endian),
            .encryption_algorithm = try reader.readEnum(EncryptionAlgorithm, endian),
            .key_idx = blk: {
                const idx = try reader.readInt(u32, endian);
                break :blk if (idx == null_idx) null else idx;
            },
            .iv_idx = blk: {
                const idx = try reader.readInt(u32, endian);
                break :blk if (idx == null_idx) null else idx;
            },
            .compression_algorithm = try reader.readEnum(sce.CompressionAlgorithm, endian),
        };
    }

    fn writeSingle(self: SegmentCertificationHeader, writer: anytype, endian: std.builtin.Endian) Error!void {
        try writer.writeInt(u64, self.segment_offset, endian);
        try writer.writeInt(u64, self.segment_size, endian);
        try writer.writeInt(std.meta.Tag(SegmentType), @intFromEnum(self.segment_type), endian);
        try writer.writeInt(u32, self.segment_id, endian);
        try writer.writeInt(std.meta.Tag(SigningAlgorithm), @intFromEnum(self.signature_algorithm), endian);
        try writer.writeInt(u32, self.signature_idx, endian);
        try writer.writeInt(std.meta.Tag(EncryptionAlgorithm), @intFromEnum(self.encryption_algorithm), endian);
        try writer.writeInt(u32, self.key_idx orelse null_idx, endian);
        try writer.writeInt(u32, self.iv_idx orelse null_idx, endian);
    }

    pub fn write(headers: []const SegmentCertificationHeader, writer: anytype, endian: std.builtin.Endian) Error!void {
        for (headers) |header| {
            try header.writeSingle(writer, endian);
        }
    }
};

/// An optional header providing extra information to the certified file
///
/// See https://www.psdevwiki.com/ps3/Certified_File#Optional_Header_Table
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

    const header_size = @sizeOf(Type) + @sizeOf(u32) + @sizeOf(u64);

    pub fn byteSize(self: OptionalHeader) usize {
        return switch (self) {
            .capability => |capability| capability.byteSize(),
            inline .individual_seed, .attribute => |bytes| bytes.len,
        };
    }

    pub fn read(raw_reader: anytype, allocator: std.mem.Allocator, certifiction_header: CertificationHeader, endian: std.builtin.Endian) Error![]OptionalHeader {
        if (certifiction_header.optional_header_size == 0) {
            log.info("Optional header size is zero, returning empty array", .{});
            return &.{};
        }

        var optional_headers = std.ArrayList(OptionalHeader).init(allocator);
        errdefer optional_headers.deinit();

        var counting_reader = std.io.countingReader(raw_reader);
        const reader = counting_reader.reader();

        var total_read: u64 = 0;
        var to_read: u64 = certifiction_header.optional_header_size;
        while (to_read > 0) : (to_read -= counting_reader.bytes_read) {
            defer counting_reader.bytes_read = 0;

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

            if (counting_reader.bytes_read - read_start != size) {
                log.err("Failed to read entire optional header, size mismatch. Read {d}, size {d}", .{ counting_reader.bytes_read - read_start, size });
                return Error.OptionalHeaderSizeMismatch;
            }

            if (!next) break;
        }

        if (total_read != certifiction_header.optional_header_size) {
            log.err("Total amount of bytes read does not match specified size of optional header table, read {d}, size {d}", .{ total_read, certifiction_header.optional_header_size });
            return Error.OptionalHeaderTableSizeMismatch;
        }

        return optional_headers.toOwnedSlice();
    }

    pub fn write(headers: []const OptionalHeader, raw_writer: anytype, endian: std.builtin.Endian) Error!u64 {
        var counting_writer = std.io.countingWriter(raw_writer);
        const writer = counting_writer.writer();

        for (headers, 0..) |header, i| {
            try writer.writeInt(std.meta.Tag(Type), @intFromEnum(header), endian);
            try writer.writeInt(u32, header.byteSize() + header_size, endian);
            try writer.writeInt(u64, if (i < headers.len - 1) 0 else 1, endian);

            const write_start = counting_writer.bytes_written;

            switch (header) {
                .capability => |capability| try capability.write(writer, endian),
                inline .individual_seed, .attribute => |bytes| try writer.writeAll(bytes),
            }

            if (counting_writer.bytes_written - write_start != header.byteSize()) {
                return Error.OptionalHeaderSizeMismatch;
            }
        }

        return counting_writer.bytes_written;
    }
};

/// Contains the signature used to certify the file.
/// Signature is calculated upon the decrypted contents from the start of the certified file to `CertificationHeader.signature_offset`
///
/// See https://www.psdevwiki.com/ps3/Certified_File#Signature
pub const Signature = union(SigningAlgorithm) {
    ecdsa160: sce.Ecdsa160Signature,
    hmac_sha1: void,
    sha1: void,
    rsa2048: sce.Rsa2048Signature,
    hmac_sha256: void,

    pub fn read(reader: anytype, certification_header: CertificationHeader) Error!Signature {
        return switch (certification_header.signature_algorithm) {
            .ecdsa160 => .{ .ecdsa160 = try sce.Ecdsa160Signature.read(reader) },
            .rsa2048 => .{ .rsa2048 = try sce.Rsa2048Signature.read(reader) },
            // https://www.psdevwiki.com/ps3/Certified_File#Signature
            else => {
                log.err("Unsupported signature type {s}", .{@tagName(certification_header.signature_algorithm)});
                return Error.UnsupportedSignatureType;
            },
        };
    }

    pub fn write(self: Signature, writer: anytype) Error!Signature {
        switch (self) {
            inline .ecdsa160, .rsa2048 => |sig| try sig.write(writer),
            // https://www.psdevwiki.com/ps3/Certified_File#Signature
            else => {
                return Error.UnsupportedSignatureType;
            },
        }
    }
};

pub fn write() Error!void {}

pub fn read(
    allocator: std.mem.Allocator,
    cf_data: []u8,
    license_data: LicenseData,
    system_keys: system_keyset.KeySet,
    npdrm_keys: npdrm_keyset.KeySet,
    only_read_header: bool,
) Error!CertifiedFile {
    var stream = std.io.fixedBufferStream(cf_data);

    const reader = stream.reader();

    log.info("Reading CF with size {d}", .{cf_data.len});

    const header = try Header.read(reader);
    const endianness = header.endianness();

    log.info("Read CF header with version {s}", .{@tagName(header.version)});

    // TODO: non-SELF file extraction
    if (header.category != .signed_elf) {
        log.err("non-SELF certified file {s} is unsupported", .{@tagName(header.category)});
        return Error.OnlySelfSupported;
    }

    const self = try Self.read(cf_data, &stream, allocator, endianness);
    errdefer self.deinit(allocator);

    log.info("Read SELF data", .{});

    if (only_read_header) {
        log.info("only_read_header specified, returning now that our work is done", .{});
        return .{
            .header_only = .{
                .header = header,
                .contents = .{ .signed_elf = self },
            },
        };
    }

    // If this is a fake certified file, none of the following contents are present, and there's no encryption
    if (header.key_revision == 0x8000) {
        log.info("Found fSELF file, all work done", .{});
        return .{
            .fake = .{
                .header = header,
                .contents = .{ .signed_elf = self },
            },
        };
    }

    const system_key = system_keys.get(.{
        .revision = header.key_revision,
        .self_type = self.program_identification_header.program_type,
    }) orelse {
        log.warn("Missing system key for revision {d} and self type {s}, possibly corrupt CF file?", .{ header.key_revision, @tagName(self.program_identification_header.program_type) });
        return .{ .missing_system_key = .{
            .header = header,
            .contents = .{ .signed_elf = self },
        } };
    };

    log.info("Acquired system key for revision {d} and self type {s}", .{ header.key_revision, @tagName(self.program_identification_header.program_type) });

    // Seek past the extended header
    try stream.seekTo(header.byteSize() + header.extended_header_size);

    // NPDRM applications need to have their encryption root header read differently
    const encryption_root_header = if (header.category == .signed_elf and self.program_identification_header.program_type == .npdrm_application)
        EncryptionRootHeader.readNpdrm(reader, self, license_data, npdrm_keys, system_key, endianness) catch |err| {
            return switch (err) {
                Error.MissingNpdrmKlicKey,
                Error.MissingNpdrmKlicFreeKey,
                Error.MissingLicense,
                Error.UnknownNpdrmType,
                Error.InvalidEncryptionRootHeaderPadding,
                Error.MissingRapInitKey,
                Error.MissingRapPBoxKey,
                Error.MissingRapE1Key,
                Error.MissingRapE2Key,
                Error.MissingRifKey,
                Error.MissingIdpsConstKey,
                => .{ .missing_npdrm_key = .{
                    .header = header,
                    .contents = .{ .signed_elf = self },
                } },
                else => err,
            };
        }
    else
        try EncryptionRootHeader.read(reader, system_key);

    log.info("Read encryption root header", .{});

    { // Decrypt all bytes from now until the start of the encapsulated file
        const pos = try stream.getPos();
        const len = header.file_offset - (header.byteSize() + header.extended_header_size + encryption_root_header.byteSize());

        if (pos > std.math.maxInt(usize) or len > std.math.maxInt(usize)) {
            log.err("Full header decryption cannot continue, invalid pos/len, {d}/{d}", .{ pos, len });
            return Error.InvalidPosOrSizeForPlatform;
        }

        const data = cf_data[@intCast(pos)..@intCast(pos + len)];

        // decrypt the certification header, segment certification header, and keys
        const aes128 = Aes128.initEnc(encryption_root_header.key);
        std.crypto.core.modes.ctr(@TypeOf(aes128), aes128, data, data, encryption_root_header.iv, endianness);

        log.info("Decrypted entire CF header", .{});
    }

    const certification_header = try CertificationHeader.read(reader, endianness);

    log.info("Read certification header", .{});

    const segment_certification_headers = try SegmentCertificationHeader.read(reader, allocator, certification_header, endianness);
    errdefer allocator.free(segment_certification_headers);

    log.info("Read {d} segment certification headers", .{segment_certification_headers.len});

    // TODO: what the hell is psdevwiki talking about with "attributes"?
    //       we are following what RPCS3/scetool does by reading these as a series of 16-byte keys
    //       psdevwiki: https://www.psdevwiki.com/ps3/Certified_File#Attributes
    //       rpcs3: https://github.com/RPCS3/rpcs3/blob/3e516df214f5c36d4b613aa0580182155247d2ad/rpcs3/Crypto/unself.cpp#L687
    const keys = try allocator.alloc([0x10]u8, certification_header.attr_entry_num);
    errdefer allocator.free(keys);
    for (keys) |*key| try reader.readNoEof(key);

    log.info("Read {d} CF keys", .{keys.len});

    const optional_headers = try OptionalHeader.read(reader, allocator, certification_header, endianness);
    errdefer allocator.free(optional_headers);

    log.info("Read {d} optional headers", .{optional_headers.len});

    const signature = try Signature.read(reader, certification_header);

    log.info("Read signature", .{});

    log.info("Finished reading CF", .{});

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

pub const CertifiedFile = union(LoadType) {
    pub const LoadType = enum(u32) {
        full = 0,
        fake = 1,
        header_only = 2,
        missing_system_key = 3,
        missing_npdrm_key = 4,
    };

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
            log.info("Decrypting CF body", .{});

            for (self.segment_certification_headers, 0..) |segment_header, i| {
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

                    if (segment_header.segment_offset > std.math.maxInt(usize) or segment_header.segment_size > std.math.maxInt(usize)) {
                        log.err("Unable to decrypt segment {d}, offset ({d}) or size ({d}) is invalid", .{ i, segment_header.segment_offset, segment_header.segment_size });
                        return Error.InvalidPosOrSizeForPlatform;
                    }

                    const data = self.cf_data[@intCast(segment_header.segment_offset)..@intCast(segment_header.segment_offset + segment_header.segment_size)];

                    switch (segment_header.encryption_algorithm) {
                        .aes128_ctr => {
                            const aes128 = Aes128.initEnc(self.keys[key_idx]);
                            std.crypto.core.modes.ctr(@TypeOf(aes128), aes128, data, data, self.keys[iv_idx], self.header.endianness());
                            log.info("Decrypted segment {d} using aes128_ctr", .{i});
                        },
                        .aes128_cbc_cfb => {
                            // TODO: lets throw an error so we can hopefully find one of these cbc_cfb SELFs in the wild, and implement support!
                            log.err("Unable to decrypt segment {d}, as it uses aes128_cbc_cfb encryption. *Please* let us know what game triggers this error!", .{i});
                            return Error.UnsupportedAes128CbcCfbSegment;
                        },
                        .none => unreachable,
                    }
                }
            }

            self.body_decrypted = true;
        }
    };

    pub const Minimal = struct {
        header: Header,
        contents: Contents,
    };

    full: Full,
    fake: Minimal,
    header_only: Minimal,
    missing_system_key: Minimal,
    missing_npdrm_key: Minimal,

    pub fn header(self: CertifiedFile) Header {
        switch (self) {
            inline else => |cf| {
                return cf.header;
            },
        }
    }

    pub fn contents(self: CertifiedFile) Contents {
        switch (self) {
            inline else => |cf| {
                return cf.contents;
            },
        }
    }

    pub fn deinit(self: CertifiedFile, allocator: std.mem.Allocator) void {
        switch (self) {
            .full => |full| {
                full.contents.deinit(allocator);
                allocator.free(full.segment_certification_headers);
                allocator.free(full.optional_headers);
                allocator.free(full.keys);
            },
            inline .header_only, .missing_system_key, .missing_npdrm_key, .fake => |missing_key| {
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
