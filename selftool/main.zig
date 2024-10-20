const std = @import("std");
const pretty = @import("pretty");

const sce = @import("sce");

const CertifiedFile = sce.CertifiedFile;
const unself = sce.unself;

const npdrm_keyset = sce.npdrm_keyset;
const system_keyset = sce.system_keyset;

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer if (gpa.deinit() == .leak) @panic("memory leak");

    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const self_path = args[1];

    const self_data = try std.fs.cwd().readFileAlloc(allocator, self_path, std.math.maxInt(usize));
    defer allocator.free(self_data);

    var self_stream = std.io.fixedBufferStream(self_data);

    const systemKeysJson = try std.fs.cwd().readFileAlloc(allocator, args[2], std.math.maxInt(usize));
    defer allocator.free(systemKeysJson);

    var system_keys = try system_keyset.read(allocator, systemKeysJson);
    defer system_keys.deinit();

    const npdrmKeysJson = try std.fs.cwd().readFileAlloc(allocator, args[3], std.math.maxInt(usize));
    defer allocator.free(npdrmKeysJson);

    var npdrm_keys = try npdrm_keyset.read(allocator, npdrmKeysJson);
    defer npdrm_keys.deinit();

    const certified_file = try CertifiedFile.read(allocator, self_data, &self_stream, args[4], system_keys, npdrm_keys);
    defer certified_file.deinit(allocator);

    const output = try std.fs.cwd().createFile(args[5], .{});
    defer output.close();

    try unself.extractSelfToElf(self_data, certified_file, output.seekableStream(), output.writer());
}
