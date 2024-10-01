const std = @import("std");

const sce = @import("sce.zig");
const system_keys = @import("system_keyset.zig");
const npdrm_keys = @import("npdrm_keyset.zig");

const Aes128 = std.crypto.core.aes.Aes128;

const aes = @import("aes");

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

    pub fn readNpdrm(reader: anytype, npdrm_key: npdrm_keys.Key.AesKey, system_key: system_keys.Key) !EncryptionRootHeader {
        var header: [0x40]u8 = undefined;
        try reader.readNoEof(&header);

        var ctx: aes.aes_context = std.mem.zeroes(aes.aes_context);
        var iv: [0x10]u8 = .{0} ** 0x10;
        _ = aes.aes_setkey_dec(&ctx, &npdrm_key.erk, @bitSizeOf(@TypeOf(npdrm_key.erk)));
        _ = aes.aes_crypt_cbc(&ctx, aes.AES_DECRYPT, header.len, &iv, &header, &header);

        iv = system_key.reset_initialization_vector;
        _ = aes.aes_setkey_dec(&ctx, &system_key.encryption_round_key, @bitSizeOf(@TypeOf(system_key.encryption_round_key)));
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

    pub fn read(reader: anytype, key: system_keys.Key) !EncryptionRootHeader {
        var header: [0x40]u8 = undefined;
        try reader.readNoEof(&header);

        var ctx: aes.aes_context = std.mem.zeroes(aes.aes_context);
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
