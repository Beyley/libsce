const std = @import("std");

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

pub const SharedSecret = struct {
    shared_secret_0: [0x10]u8,
    klicensee: [0x10]u8,
    shared_secret_2: [0x10]u8,
    shared_secret_3: [4]u32,

    pub fn read(reader: anytype, endian: std.builtin.Endian) !SharedSecret {
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
