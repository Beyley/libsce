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
        \\NP Account ID: {x}
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
}
