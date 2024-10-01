const std = @import("std");

const Self = @import("Self.zig");

pub fn read(allocator: std.mem.Allocator, json: []const u8) !KeySet {
    var keyset = KeySet.init(allocator);
    errdefer keyset.deinit();

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

const JsonKey = struct {
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
