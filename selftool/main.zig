const std = @import("std");
const pretty = @import("pretty");

const sce = @import("sce");
const cova = @import("cova");

const CertifiedFile = sce.CertifiedFile;
const unself = sce.unself;

const npdrm_keyset = sce.npdrm_keyset;
const system_keyset = sce.system_keyset;

pub const CommandT = cova.Command.Base();
pub const OptionT = CommandT.OptionT;
pub const ValueT = CommandT.ValueT;

pub const setup_cmd: CommandT = .{
    .name = "selftool",
    .description = "A tool for working with SCE (f)SELF files.",
    .sub_cmds = &.{
        CommandT.from(Extract, .{
            .cmd_name = "extract",
            .cmd_description = "Extracts the underlying ELF file of a SELF file",
            .sub_descriptions = &.{
                .{ "self_path", "The path to the SELF file." },
                .{ "out_path", "The path to output the ELF file to." },
                .{ "rap_path", "An optional path to a RAP file to use for decryption." },
                .{ "system_keys_path", "The path to the system keys" },
                .{ "npdrm_keys_path", "The path to the NPDRM keys" },
            },
        }),
    },
};

const Extract = struct {
    self_path: []const u8,
    out_path: ?[]const u8 = "out.elf",
    rap_path: ?[]const u8 = null,
    system_keys_path: ?[]const u8 = "keys/system_keys.json",
    npdrm_keys_path: ?[]const u8 = "keys/npdrm_keys.json",
};

fn extract(allocator: std.mem.Allocator, options: Extract) !void {
    const self_data = try std.fs.cwd().readFileAlloc(allocator, options.self_path, std.math.maxInt(usize));
    defer allocator.free(self_data);

    var self_stream = std.io.fixedBufferStream(self_data);

    const systemKeysJson = try std.fs.cwd().readFileAlloc(allocator, options.system_keys_path.?, std.math.maxInt(usize));
    defer allocator.free(systemKeysJson);

    var system_keys = try system_keyset.read(allocator, systemKeysJson);
    defer system_keys.deinit();

    const npdrmKeysJson = try std.fs.cwd().readFileAlloc(allocator, options.npdrm_keys_path.?, std.math.maxInt(usize));
    defer allocator.free(npdrmKeysJson);

    var npdrm_keys = try npdrm_keyset.read(allocator, npdrmKeysJson);
    defer npdrm_keys.deinit();

    const certified_file = try CertifiedFile.read(allocator, self_data, &self_stream, options.rap_path, system_keys, npdrm_keys);
    defer certified_file.deinit(allocator);

    const output = try std.fs.cwd().createFile(options.out_path.?, .{});
    defer output.close();

    try unself.extractSelfToElf(self_data, certified_file, output.seekableStream(), output.writer());
}

pub fn main() !u8 {
    const stdout = std.io.getStdOut().writer();

    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer if (gpa.deinit() == .leak) @panic("memory leak");

    const allocator = gpa.allocator();

    var main_cmd = try setup_cmd.init(allocator, .{});
    defer main_cmd.deinit();
    var args_iter = try cova.ArgIteratorGeneric.init(allocator);
    defer args_iter.deinit();

    cova.parseArgs(&args_iter, CommandT, main_cmd, stdout, .{}) catch |err| switch (err) {
        error.UsageHelpCalled => return 0,
        error.ExpectedSubCommand => return 1,
        else => return err,
    };

    if (main_cmd.matchSubCmd("extract")) |extract_cmd| {
        const extract_args = try extract_cmd.to(Extract, .{});
        try extract(allocator, extract_args);
    }

    return 0;
}
