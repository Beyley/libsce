const std = @import("std");

pub const Self = @import("Self.zig");
pub const certified_file = @import("certified_file.zig");

pub const npdrm_keyset = @import("npdrm_keyset.zig");
pub const system_keyset = @import("system_keyset.zig");
pub const unself = @import("unself.zig");

pub const Error = error{
    InvalidEcdsa160SignaturePadding,
} || std.fs.File.Reader.NoEofError;

pub const ContentId = [0x30]u8;

// NOTE: The size of this type is not fully known, its documented as u32 in `Ps3Npdrm`, and u16 in the `RightsInformationFile`
/// The type of DRM in use.
/// See https://www.psdevwiki.com/ps3/NPDRM#DRM_Type
pub const DrmType = enum(u16) {
    /// It does not require any license. Set in SDATA files. This is the official name.
    unknown = 0,
    /// It requires network authentication every time the content is launched.
    network = 1,
    /// It requires first time activation online (paid content but also demo and free of charge content).
    local = 2,
    /// On PS3, it does not require any license file nor console activation (act.dat).
    /// PS3 disc bind contents use this DRM Type. On PSP, when a .rif is present for Free DRM Type,
    /// the RIF NP Account ID is replaced by a Magic Gate Memory Stick command result
    /// and the RIF encrypted account keyring index is replaced by the sha1 digest of this Magic Gate Memory Stick command result.
    free = 3,
    /// This type exists according to PS3 make_package_npdrm.exe revision 1972. However, no .rif holding this DRM Type was ever seen.
    psp = 4,
    /// Used for Free contents but with license (.rif) requirement, unlike DRM Type 3.
    /// Requires either pd0:license/rifname.rif (for Welcome Park) or /app/TITLEID/sce_sys/package/temp.bin (for .pkg installed from PS Store).
    free_psp2_psm = 0xd,
    /// Seen in PSP and PS Vita OS. On PSP, extends the RIF ECDSA signed data with IDPS and Fuse ID.
    /// On PS Vita, forces OpenPSID comparison in RIF and thus RIF RSA signature verification.
    network_psp_psp2 = 0x100,
    /// Requires a .rif stored in the gamecard filesystem and the gamecard to be inserted for authentication.
    gamecard_psp2 = 0x400,
    /// Unknown what this license type is, seen in EP0001-NPEB00560_00-GRAW2PS3REMPKG01.rif.
    unknown_ps3 = 0x2000,
};

fn fieldSize(comptime T: type, comptime field_name: []const u8) comptime_int {
    return @sizeOf(@FieldType(T, field_name));
}

pub const Ecdsa224Signature = struct {
    r: [0x1c]u8,
    s: [0x1c]u8,

    pub fn read(reader: anytype) Error!Ecdsa224Signature {
        return .{
            .r = try reader.readBytesNoEof(fieldSize(Ecdsa224Signature, "r")),
            .s = try reader.readBytesNoEof(fieldSize(Ecdsa224Signature, "s")),
        };
    }
};

pub const Ecdsa160Signature = struct {
    r: [0x15]u8,
    s: [0x15]u8,
    padding: [0x06]u8,

    pub fn read(reader: anytype) Error!Ecdsa160Signature {
        const signature = .{
            .r = try reader.readBytesNoEof(fieldSize(Ecdsa160Signature, "r")),
            .s = try reader.readBytesNoEof(fieldSize(Ecdsa160Signature, "s")),
            .padding = try reader.readBytesNoEof(fieldSize(Ecdsa160Signature, "padding")),
        };

        if (!std.mem.allEqual(u8, &signature.padding, 0))
            return Error.InvalidEcdsa160SignaturePadding;

        return signature;
    }
};

pub const Rsa2048Signature = struct {
    rsa: [0x100]u8,

    pub fn read(reader: anytype) Error!Rsa2048Signature {
        return .{
            .rsa = try reader.readBytesNoEof(fieldSize(Rsa2048Signature, "rsa")),
        };
    }
};

pub const SharedSecret = struct {
    shared_secret_0: [0x10]u8,
    klicensee: [0x10]u8,
    shared_secret_2: [0x10]u8,
    shared_secret_3: [4]u32,

    pub fn read(reader: anytype, endian: std.builtin.Endian) Error!SharedSecret {
        return .{
            .shared_secret_0 = try reader.readBytesNoEof(fieldSize(SharedSecret, "shared_secret_0")),
            .klicensee = try reader.readBytesNoEof(fieldSize(SharedSecret, "klicensee")),
            .shared_secret_2 = try reader.readBytesNoEof(fieldSize(SharedSecret, "shared_secret_2")),
            .shared_secret_3 = .{
                try reader.readInt(u32, endian),
                try reader.readInt(u32, endian),
                try reader.readInt(u32, endian),
                try reader.readInt(u32, endian),
            },
        };
    }
};

pub const CompressionAlgorithm = enum(u32) {
    plain = 1,
    zlib = 2,
};

pub const PlaintextCapability = struct {
    ctrl_flag1: u32,
    unknown2: u32,
    unknown3: u32,
    unknown4: u32,
    unknown5: u32,
    unknown6: u32,
    unknown7: u32,
    unknown8: u32,

    pub fn read(reader: anytype, endian: std.builtin.Endian) Error!PlaintextCapability {
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

pub const EncryptedCapability = struct {
    unknown1: u32,
    unknown2: u32,
    unknown3: u32,
    unknown4: u32,
    unknown5: u32,
    unknown6: u32,
    unknown7: u32,
    unknown8: u32,

    pub fn read(reader: anytype, endian: std.builtin.Endian) Error!EncryptedCapability {
        return .{
            .unknown1 = try reader.readInt(u32, endian),
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

pub const LicenseFlags = packed struct(u16) {
    normal: bool,
    unknown1: bool,
    unknown2: bool,
    unknown3: bool,
    unknown4: bool,
    unknown5: bool,
    unknown6: bool,
    unknown7: bool,
    unknown8: bool,
    yet_to_be_usable_preorder_content: bool,
    unknown10: bool,
    unknown11: bool,
    unknown12: bool,
    unknown13: bool,
    unknown14: bool,
    unknown15: bool,
};

/// A file containing a license for a piece of content
/// See https://wiki.henkaku.xyz/vita/SceNpDrm#RIF and https://www.psdevwiki.com/ps3/RIF
pub const RightsInformationFile = struct {
    pub const SomeFlag = packed struct(u32) { unknown: u32 };

    pub const VitaOnlyData = struct {
        some_flag: SomeFlag,
        provisional_flag: bool, // u32
        /// Used to get klicensee to decrypt NPDRM SELF/SPRX/EDAT/PFS files.
        encrypted_rif_key: [0x10]u8,
        unknown_b0: [0x10]u8,
        /// Checked only if DRM Type is network.
        open_psid: [0x10]u8,
        unknown_d0: [0x10]u8,
        /// Checked only if DRM Type is gamecard_psp2.
        cmd56_handshake_part: [0x14]u8,
        /// Some index related to debug_upgradable. ex: 0 (default), 1 (seen on a PSP2 gamecard). Allowed range is 0 (default) and 1-0x20.
        unknown_index: u32,
        unknown_f8: [0x4]u8,
        /// Some flag related to debug_upgradable.
        sku_flag: u32,
        rsa_signature: Rsa2048Signature,
    };

    pub const Version = enum(u16) {
        early = 0x0000,
        vita_extended = 0x0001,
        ps3 = 0x0100,
    };

    pub const FinalizedFlag = enum(i16) {
        debug = -1,
        default = 0,
    };

    /// Whether or not the RIF file is finalized (true) or debug (false)
    finalized_flag: FinalizedFlag,
    /// The version of the RIF filer
    version: Version,
    /// The flags associated with this license
    license_flags: LicenseFlags,
    /// The DRM type this license is for
    drm_type: DrmType,
    /// NP Account ID (in little-endian) for Network and Local DRM, 8 first bytes of sha-1 of some key for Free DRM.
    np_account_id: [0x8]u8,
    /// The content ID this license is valid for
    content_id: ContentId,
    /// Encrypted account keyring index for Network and Local DRM, 12 last bytes of sha-1 of some key + 4 bytes of zeroes for Free DRM.
    encrypted_account_keyring_index: [0x10]u8,
    /// Used to get klicensee to decrypt NPDRM SELF/SPRX/EDAT/PFS files.
    encrypted_rif_key: [0x10]u8,
    /// The start time of the license, in milliseconds
    license_start_time: u64,
    /// The end time of the license, in milliseconds
    license_end_time: ?u64,
    ecdsa_signature: [0x28]u8,
    /// Data only present on vita RIF files, always present when `version` is .vita, and never present otherwise
    vita_only_data: ?VitaOnlyData,

    pub fn read(reader: anytype, endian: std.builtin.Endian) !RightsInformationFile {
        const finalized_flag = try reader.readEnum(FinalizedFlag, endian);
        // Version number seems to be different between PS3 and vita, so we use endianness here to detect the version
        const version = try reader.readEnum(Version, .little);

        return .{
            .finalized_flag = finalized_flag,
            .version = version,
            .license_flags = @bitCast(try reader.readInt(u16, endian)),
            .drm_type = try std.meta.intToEnum(DrmType, try reader.readInt(u16, endian)), // in some places this is defined as u32, however here, its a u16
            .np_account_id = try reader.readBytesNoEof(fieldSize(RightsInformationFile, "np_account_id")),
            .content_id = try reader.readBytesNoEof(@sizeOf(ContentId)),
            .encrypted_account_keyring_index = try reader.readBytesNoEof(fieldSize(RightsInformationFile, "encrypted_account_keyring_index")),
            .encrypted_rif_key = try reader.readBytesNoEof(fieldSize(RightsInformationFile, "encrypted_rif_key")),
            .license_start_time = try reader.readInt(u64, endian),
            .license_end_time = blk: {
                const time = try reader.readInt(u64, endian);

                break :blk if (time == 0) null else time;
            },
            .ecdsa_signature = try reader.readBytesNoEof(fieldSize(RightsInformationFile, "ecdsa_signature")),
            .vita_only_data = if (version == .vita_extended) .{
                .some_flag = @bitCast(try reader.readInt(u32, endian)),
                .provisional_flag = (try reader.readInt(u32, endian)) != 0,
                .encrypted_rif_key = try reader.readBytesNoEof(fieldSize(VitaOnlyData, "encrypted_rif_key")),
                .unknown_b0 = try reader.readBytesNoEof(fieldSize(VitaOnlyData, "unknown_b0")),
                .open_psid = try reader.readBytesNoEof(fieldSize(VitaOnlyData, "open_psid")),
                .unknown_d0 = try reader.readBytesNoEof(fieldSize(VitaOnlyData, "unknown_d0")),
                .cmd56_handshake_part = try reader.readBytesNoEof(fieldSize(VitaOnlyData, "cmd56_handshake_part")),
                .unknown_index = try reader.readInt(u32, endian),
                .unknown_f8 = try reader.readBytesNoEof(fieldSize(VitaOnlyData, "unknown_f8")),
                .sku_flag = try reader.readInt(u32, endian),
                .rsa_signature = try Rsa2048Signature.read(reader),
            } else null,
        };
    }
};
