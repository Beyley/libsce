const std = @import("std");

const aes = @import("aes");

pub const KeyType = enum {
    tid,
    ci,
    klic_free,
    klic_key,
    klic_dev,
    sig,
    dat,
    gpkg_key,
    idps_const,
    rif_key,
    rap_init,
    rap_pbox,
    rap_e1,
    rap_e2,
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
        erk: [0x10]u8,
        riv: [0x10]u8,
    };
    pub const SigKey = struct {
        public: [0x28]u8,
        curve_type: u8,
    };

    aes: AesKey,
    sig: SigKey,
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
                if (key_type != .sig) {
                    var key_bytes: [0x10]u8 = undefined;
                    var riv_bytes: [0x10]u8 = undefined;
                    if ((try std.fmt.hexToBytes(&key_bytes, &json_key.key.?)).len != key_bytes.len)
                        return error.InvalidNpdrmKey;
                    if (json_key.riv != null and (try std.fmt.hexToBytes(&riv_bytes, &json_key.riv.?)).len != riv_bytes.len)
                        return error.InvalidNpdrmKey;

                    try keyset.put(key_type, .{ .aes = .{
                        .erk = key_bytes,
                        .riv = riv_bytes,
                    } });
                } else {
                    var public_key_bytes: [0x28]u8 = undefined;
                    if ((try std.fmt.hexToBytes(&public_key_bytes, &json_key.public.?)).len != public_key_bytes.len)
                        return error.InvalidNpdrmKey;

                    try keyset.put(key_type, .{ .sig = .{
                        .public = public_key_bytes,
                        .curve_type = json_key.ctype.?,
                    } });
                }
            },
        }
    }

    return keyset;
}

pub fn rapToKlicensee(orig_rap: [0x10]u8, keyset: KeySet) [0x10]u8 {
    var aes_ctxt: aes.aes_context = undefined;

    var rap = orig_rap;

    // initial decrypt
    _ = aes.aes_setkey_dec(&aes_ctxt, &keyset.get(.rap_init).?.aes.erk, @bitSizeOf(@TypeOf(rap)));
    _ = aes.aes_crypt_ecb(&aes_ctxt, aes.AES_DECRYPT, &rap, &rap);

    const pbox = keyset.get(.rap_pbox).?.aes.erk;
    const e1 = keyset.get(.rap_e1).?.aes.erk;
    const e2 = keyset.get(.rap_e2).?.aes.erk;

    for (0..5) |_| {
        for (0..16) |i| {
            const p = pbox[i];
            rap[p] ^= e1[p];
        }
        {
            var i: usize = 15;
            while (i >= 1) : (i -= 1) {
                const p = pbox[i];
                const pp = pbox[i - 1];

                rap[p] ^= rap[pp];
            }
        }
        var o: u8 = 0;
        for (0..16) |i| {
            const p = pbox[i];
            const kc = rap[p] - o;
            const ec2 = e2[p];
            if (o != 1 or kc != 0xFF) {
                o = if (kc < ec2) 1 else 0;
                rap[p] = kc -% ec2;
            } else if (kc == 0xFF)
                rap[p] = kc -% ec2
            else
                rap[p] = kc;
        }
    }

    return rap;
}
