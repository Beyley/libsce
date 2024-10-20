const std = @import("std");

pub const Self = @import("Self.zig");
pub const CertifiedFile = @import("CertifiedFile.zig");

pub const npdrm_keyset = @import("npdrm_keyset.zig");
pub const system_keyset = @import("system_keyset.zig");
pub const unself = @import("unself.zig");

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

fn fieldSize(comptime T: type, comptime field_name: []const u8) comptime_int {
    return @sizeOf(@FieldType(T, field_name));
}

pub const Ecdsa224Signature = struct {
    r: [0x1c]u8,
    s: [0x1c]u8,

    pub fn read(reader: anytype) !Ecdsa224Signature {
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

    pub fn read(reader: anytype) !Ecdsa160Signature {
        const signature = .{
            .r = try reader.readBytesNoEof(fieldSize(Ecdsa160Signature, "r")),
            .s = try reader.readBytesNoEof(fieldSize(Ecdsa160Signature, "s")),
            .padding = try reader.readBytesNoEof(fieldSize(Ecdsa160Signature, "padding")),
        };

        if (!std.mem.allEqual(u8, &signature.padding, 0))
            return error.InvalidEcdsa160SignaturePadding;

        return signature;
    }
};

pub const Rsa2048Signature = struct {
    rsa: [0x100]u8,

    pub fn read(reader: anytype) !Rsa2048Signature {
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

    pub fn read(reader: anytype, endian: std.builtin.Endian) !SharedSecret {
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

pub const EncryptedCapability = struct {
    unknown1: u32,
    unknown2: u32,
    unknown3: u32,
    unknown4: u32,
    unknown5: u32,
    unknown6: u32,
    unknown7: u32,
    unknown8: u32,

    pub fn read(reader: anytype, endian: std.builtin.Endian) !EncryptedCapability {
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
