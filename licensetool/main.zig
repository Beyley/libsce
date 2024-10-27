const std = @import("std");
const sce = @import("sce");
const cova = @import("cova");

pub const CommandT = cova.Command.Base();
pub const OptionT = CommandT.OptionT;
pub const ValueT = CommandT.ValueT;

pub const RifInfoOptions = struct {
    rif_file: []const u8,
    endian: std.builtin.Endian = .big,
};

pub const ActInfoOptions = struct {
    act_file: []const u8,
    endian: std.builtin.Endian = .big,
};

pub const setup_cmd: CommandT = .{
    .name = "licensetool",
    .description = "A tool for working with SCE license files.",
    .sub_cmds = &.{
        CommandT.from(RifInfoOptions, .{
            .cmd_name = "rifinfo",
            .cmd_description = "Displays information about a RIF file",
            .sub_descriptions = &.{
                .{ "endian", "The endianness of the RIF file." },
                .{ "rif_file", "The path to the input RIF file." },
            },
        }),
        CommandT.from(ActInfoOptions, .{
            .cmd_name = "actinfo",
            .cmd_description = "Displays information about an ACT.DAT file",
            .sub_descriptions = &.{
                .{ "endian", "The endianness of the RIF file." },
                .{ "act_file", "The path to the input ACT.DAT file." },
            },
        }),
    },
};

pub fn rifinfo(output: anytype, options: RifInfoOptions) !void {
    const file = try std.fs.cwd().openFile(options.rif_file, .{});
    defer file.close();

    const rif = try sce.RightsInformationFile.read(file.reader(), options.endian);

    try output.print("# Rights Information File\n", .{});
    try output.print(
        \\Finalized: {s}
        \\Version: {s}
        \\License Flags: {x}
        \\DRM Type: {s}
        \\NP Account ID: {d}
        \\Content ID: {s}
        \\Encrypted Account Keyring Index: {x}
        \\Encrypted RIF Key: {x}
        \\License Start Time: {d}
        \\License End Time: {?d}
        \\ECDSA Signature: {x}
        \\
    , .{
        @tagName(rif.finalized_flag),
        @tagName(rif.version),
        @as(u16, @bitCast(rif.license_flags)),
        @tagName(rif.drm_type),
        rif.np_account_id,
        rif.content_id,
        rif.encrypted_account_keyring_index,
        rif.encrypted_rif_key,
        rif.license_start_time,
        rif.license_end_time,
        rif.ecdsa_signature,
    });

    if (rif.vita_only_data) |vita_data| {
        try output.print(
            \\Some Flag: {x}
            \\Provisional Flag: {}
            \\Encrypted RIF Key 2: {x}
            \\Unknown B0: {x}
            \\Open PSID: {x}
            \\Unknown D0: {x}
            \\CMD56 Handshake Part: {x}
            \\Unknown Index: {d}
            \\Unknown F8: {x}
            \\SKU Flag: {d}
            \\RSA Signature: {x}
            \\
        , .{
            @as(u32, @bitCast(vita_data.some_flag)),
            vita_data.provisional_flag,
            vita_data.encrypted_rif_key,
            vita_data.unknown_b0,
            vita_data.open_psid,
            vita_data.unknown_d0,
            vita_data.cmd56_handshake_part,
            vita_data.unknown_index,
            vita_data.unknown_f8,
            vita_data.sku_flag,
            vita_data.rsa_signature.rsa,
        });
    }
}

pub fn actinfo(output: anytype, options: ActInfoOptions) !void {
    const file = try std.fs.cwd().openFile(options.act_file, .{});
    defer file.close();

    const act_dat = try sce.ActivationData.read(file.reader(), options.endian);

    try output.print(
        \\# Activation Data
        \\Type: {}
        \\Version Flag: {s}
        \\Parser Version: {s}
        \\PSN Account ID: {d}
        \\Unknown 1: {x}
        \\Open PSID: {x}
        \\RSA Signature: {x}
        \\Unknown Signature: {x}
        \\ECDSA Signature: {x}
        \\
    , .{
        act_dat.type,
        @tagName(act_dat.version_flag),
        @tagName(act_dat.parser_version),
        act_dat.account_id,
        act_dat.unknown_1,
        act_dat.open_psid,
        act_dat.rsa_signature.rsa,
        act_dat.unknown_signature,
        act_dat.ecdsa_signature,
    });

    try output.writeByte('\n');

    switch (act_dat.version_specific_data) {
        .version_1 => |version_1| {
            try output.print(
                \\## Version 1 Data
                \\Unknown 1: {x}
                \\Unknown 2: {x}
                \\
            , .{
                version_1.unknown_encrypted_data_1,
                version_1.unknown_encrypted_data_2,
            });
        },
        .version_2 => |version_2| {
            try output.print(
                \\## Version 2 Data
                \\Unknown: {x}
                \\Padding: {x}
                \\Start Time: {d}
                \\Expiration Time: {?d}
                \\
            , .{
                version_2.unknown,
                version_2.padding,
                version_2.start_time,
                version_2.expiration_time,
            });
        },
    }

    try output.writeByte('\n');

    try output.print("# {d} Primary Keys\n", .{act_dat.primary_key_table.len});
    for (act_dat.primary_key_table, 0..) |primary_key, i| {
        try output.print("[{d}] {x}\n", .{ i, primary_key });
    }

    try output.writeByte('\n');

    try output.print("# {d} Secondary Keys\n", .{act_dat.secondary_table.len});
    for (act_dat.secondary_table, 0..) |secondary_kvey, i| {
        try output.print("[{d}] {x}\n", .{ i, secondary_kvey });
    }
}

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer if (gpa.deinit() == .leak) @panic("memory leak");

    const allocator = gpa.allocator();

    var main_cmd = try setup_cmd.init(allocator, .{});
    defer main_cmd.deinit();
    var args_iter = try cova.ArgIteratorGeneric.init(allocator);
    defer args_iter.deinit();

    cova.parseArgs(&args_iter, CommandT, main_cmd, stdout, .{}) catch |err| switch (err) {
        error.UsageHelpCalled => return,
        else => return err,
    };

    if (main_cmd.matchSubCmd("rifinfo")) |rifinfo_cmd| {
        const rifinfo_args = try rifinfo_cmd.to(RifInfoOptions, .{});

        try rifinfo(stdout, rifinfo_args);
    }

    if (main_cmd.matchSubCmd("actinfo")) |actinfo_cmd| {
        const actinfo_args = try actinfo_cmd.to(ActInfoOptions, .{});

        try actinfo(stdout, actinfo_args);
    }
}
