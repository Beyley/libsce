const std = @import("std");
const aes = @import("aes");

const sce = @import("sce.zig");

const log = std.log.scoped(.npdrm_keyset);

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

pub const Error = error{
    JsonMissingKey,
    InvalidJsonNpdrmKey,
    InvalidJsonNpdrmRiv,
    InvalidLength,
    NoSpaceLeft,
    JsonMissingPublicKey,
    InvalidNpdrmKey,
    JsonMissingCType,
    MissingRapInitKey,
    MissingRapPBoxKey,
    MissingRapE1Key,
    MissingRapE2Key,
    MissingIdpsConstKey,
    MissingRifKey,
    RifKeyIndexOutOfBounds,
} || std.json.ParseError(std.json.Scanner);

pub fn read(allocator: std.mem.Allocator, json: []const u8) Error!KeySet {
    var keyset = KeySet.init(allocator);
    errdefer keyset.deinit();

    const keys = try std.json.parseFromSlice([]const JsonKey, allocator, json, .{});
    defer keys.deinit();

    for (keys.value) |json_key| {
        switch (json_key.type) {
            inline else => |key_type| {
                if (key_type != .sig) {
                    const key = json_key.key orelse return Error.JsonMissingKey;

                    var key_bytes: [0x10]u8 = undefined;
                    var riv_bytes: [0x10]u8 = undefined;
                    if ((try std.fmt.hexToBytes(&key_bytes, &key)).len != key_bytes.len)
                        return Error.InvalidJsonNpdrmKey;
                    if (json_key.riv) |riv| if ((try std.fmt.hexToBytes(&riv_bytes, &riv)).len != riv_bytes.len)
                        return Error.InvalidJsonNpdrmRiv;

                    try keyset.put(key_type, .{ .aes = .{
                        .erk = key_bytes,
                        .riv = riv_bytes,
                    } });
                } else {
                    const public_key = json_key.public orelse return Error.JsonMissingPublicKey;

                    var public_key_bytes: [0x28]u8 = undefined;
                    if ((try std.fmt.hexToBytes(&public_key_bytes, &public_key)).len != public_key_bytes.len)
                        return Error.InvalidNpdrmKey;

                    try keyset.put(key_type, .{ .sig = .{
                        .public = public_key_bytes,
                        .curve_type = json_key.ctype orelse return Error.JsonMissingCType,
                    } });
                }
            },
        }
    }

    return keyset;
}

pub fn getKeyOrError(keyset: KeySet, comptime key_type: KeyType, err_ret: anytype) ![0x10]u8 {
    if (@typeInfo(@TypeOf(err_ret)) != .error_set)
        @compileError("Error return value must be an error!");

    return (keyset.get(key_type) orelse {
        log.err("Missing " ++ @tagName(key_type) ++ " key", .{});
        return err_ret;
    }).aes.erk;
}

pub fn rapToKlicensee(orig_rap: [0x10]u8, keyset: KeySet) Error![0x10]u8 {
    var aes_ctxt: aes.aes_context = undefined;

    var rap = orig_rap;

    const rap_init = try getKeyOrError(keyset, .rap_init, Error.MissingRapInitKey);

    log.info("Loading Klicensee from RAP", .{});

    // initial decrypt
    _ = aes.aes_setkey_dec(&aes_ctxt, &rap_init, @bitSizeOf(@TypeOf(rap)));
    _ = aes.aes_crypt_ecb(&aes_ctxt, aes.AES_DECRYPT, &rap, &rap);

    log.info("Initial RAP decryption complete", .{});

    const pbox = try getKeyOrError(keyset, .rap_pbox, Error.MissingRapPBoxKey);
    const e1 = try getKeyOrError(keyset, .rap_e1, Error.MissingRapE1Key);
    const e2 = try getKeyOrError(keyset, .rap_e2, Error.MissingRapE2Key);

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

    log.info("Secondary RAP decryption complete", .{});

    return rap;
}

pub fn loadKlicensee(rif: sce.RightsInformationFile, act_dat: sce.ActivationData, idps: [0x10]u8, keyset: KeySet, endian: std.builtin.Endian) Error![0x10]u8 {
    const idps_const_key = try getKeyOrError(keyset, .idps_const, Error.MissingIdpsConstKey);
    const rif_key = try getKeyOrError(keyset, .rif_key, Error.MissingRifKey);

    log.info("Loading Klicensee from RIF + act.dat + IDPS, RIF content ID: {s}", .{rif.content_id});

    var aes_ctx: aes.aes_context = undefined;

    // Acquire the ACT.DAT key
    const act_dat_key = blk: {
        var decrypted_account_keyring_index: [0x10]u8 = undefined;

        // Decrypt the account keyring index
        _ = aes.aes_setkey_dec(&aes_ctx, &rif_key, @bitSizeOf(@TypeOf(rif_key)));
        _ = aes.aes_crypt_ecb(&aes_ctx, aes.AES_DECRYPT, &rif.encrypted_account_keyring_index, &decrypted_account_keyring_index);

        // The last four bytes are the actual index
        const keyring_index = std.mem.readInt(u32, &decrypted_account_keyring_index[12..][0..4].*, endian);

        // This is likely a decryption issue, bad key maybe?
        if (keyring_index >= act_dat.primary_key_table.len) {
            log.err("Index {d} is out of bound of ACT.DAT keyring, this is likely a decryption error, maybe rif_key is wrong?", .{keyring_index});
            return Error.RifKeyIndexOutOfBounds;
        }

        break :blk act_dat.primary_key_table[keyring_index];
    };

    log.info("Acquired and decrypted first layer of ACT.DAT key encryption", .{});

    // Encrypt the constant IDPS key with the console's IDPS
    const idps_key = blk: {
        var idps_key: [0x10]u8 = undefined;
        _ = aes.aes_setkey_enc(&aes_ctx, &idps, @bitSizeOf(@TypeOf(idps)));
        _ = aes.aes_crypt_ecb(&aes_ctx, aes.AES_ENCRYPT, &idps_const_key, &idps_key);
        break :blk idps_key;
    };

    log.info("Encrypted constant IDPS key with console IDPS", .{});

    // Decrypt the account key with the IDPS key to get the Klicensee key
    const klicensee_key = blk: {
        var klicensee_key: [0x10]u8 = undefined;
        _ = aes.aes_setkey_dec(&aes_ctx, &idps_key, @bitSizeOf(@TypeOf(idps_key)));
        _ = aes.aes_crypt_ecb(&aes_ctx, aes.AES_DECRYPT, &act_dat_key, &klicensee_key);
        break :blk klicensee_key;
    };

    log.info("Decrypted ACT.DAT key into Klicensee key", .{});

    // Decrypt the Klicensee
    var klicensee: [0x10]u8 = undefined;
    _ = aes.aes_setkey_dec(&aes_ctx, &klicensee_key, @bitSizeOf(@TypeOf(klicensee_key)));
    _ = aes.aes_crypt_ecb(&aes_ctx, aes.AES_DECRYPT, &rif.encrypted_rif_key, &klicensee);

    log.info("Decrypted Klicensee from RIF", .{});
    return klicensee;
}
