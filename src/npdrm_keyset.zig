const std = @import("std");

pub const KeyType = enum {
    tid,
    ci,
    klic_free,
    klic_key,
    klic_dev,
    sig,
    dat,
    gpkg_key,
};

const JsonKey = struct {
    type: KeyType,
    key: ?[0x10 * 2]u8 = null,
    riv: ?[0x10 * 2]u8 = null,
    public: ?[0x28 * 2]u8 = null,
    ctype: ?u8 = null,
};

pub const Key = union(enum) {
    pub const AesKey = struct {
        key: [0x10]u8,
        riv: [0x10]u8,
    };
    pub const Sig = struct {
        public: [0x28]u8,
        curve_type: u8,
    };

    tid: AesKey,
    ci: AesKey,
    klic_free: AesKey,
    klic_key: AesKey,
    klic_dev: AesKey,
    sig: Sig,
    dat: AesKey,
    gpkg_key: AesKey,
};

pub const KeySet = std.AutoHashMap(KeyType, Key);

pub fn read(allocator: std.mem.Allocator, json: []const u8) !KeySet {
    var keyset = KeySet.init(allocator);
    errdefer keyset.deinit();

    const keys = try std.json.parseFromSlice([]const JsonKey, allocator, json, .{});
    defer keys.deinit();

    for (keys.value) |json_key| {
        switch (json_key.type) {
            inline else => |key_type| {
                const parsed_type = @TypeOf(@field(@as(Key, undefined), @tagName(key_type)));
                switch (parsed_type) {
                    Key.AesKey => {
                        var key_bytes: [0x10]u8 = undefined;
                        var riv_bytes: [0x10]u8 = undefined;
                        if ((try std.fmt.hexToBytes(&key_bytes, &json_key.key.?)).len != key_bytes.len)
                            return error.InvalidNpdrmKey;
                        if (json_key.riv != null and (try std.fmt.hexToBytes(&riv_bytes, &json_key.riv.?)).len != riv_bytes.len)
                            return error.InvalidNpdrmKey;

                        try keyset.put(key_type, @unionInit(Key, @tagName(key_type), .{
                            .key = key_bytes,
                            .riv = riv_bytes,
                        }));
                    },
                    Key.Sig => {
                        var public_key_bytes: [0x28]u8 = undefined;
                        if ((try std.fmt.hexToBytes(&public_key_bytes, &json_key.public.?)).len != public_key_bytes.len)
                            return error.InvalidNpdrmKey;

                        try keyset.put(key_type, @unionInit(Key, @tagName(key_type), .{
                            .public = public_key_bytes,
                            .curve_type = json_key.ctype.?,
                        }));
                    },
                    else => @panic("unhandled key type " ++ @typeName(parsed_type)),
                }
            },
        }
    }

    return keyset;
}
