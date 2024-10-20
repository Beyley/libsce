const std = @import("std");
const pretty = @import("pretty");

const aes = @import("aes");

const npdrm_keys = @import("npdrm_keyset.zig");
const system_keys = @import("system_keyset.zig");

const CertifiedFile = @import("CertifiedFile.zig");
const Self = @import("Self.zig");

const Aes128 = std.crypto.core.aes.Aes128;

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer if (gpa.deinit() == .leak) @panic("memory leak");

    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const self_path = args[1];

    const self = try std.fs.cwd().readFileAlloc(allocator, self_path, std.math.maxInt(usize));
    defer allocator.free(self);

    var self_stream = std.io.fixedBufferStream(self);
    const reader = self_stream.reader();

    const systemKeysJson = try std.fs.cwd().readFileAlloc(allocator, args[2], std.math.maxInt(usize));
    defer allocator.free(systemKeysJson);

    var system_keyset = try system_keys.read(allocator, systemKeysJson);
    defer system_keyset.deinit();

    const npdrmKeysJson = try std.fs.cwd().readFileAlloc(allocator, args[3], std.math.maxInt(usize));
    defer allocator.free(npdrmKeysJson);

    var npdrm_keyset = try npdrm_keys.read(allocator, npdrmKeysJson);
    defer npdrm_keyset.deinit();

    const certified_file_header = try CertifiedFile.Header.read(reader);
    const endianness = certified_file_header.endianness();

    try pretty.print(allocator, certified_file_header, .{});

    // TODO: non-SELF file extraction
    if (certified_file_header.category != .signed_elf)
        return error.OnlySelfSupported;

    // TODO: fSELF file extraction
    if (certified_file_header.key_revision == 0x8000)
        return error.FselfUnsupported;

    const extended_header = try Self.ExtendedHeader.read(reader, endianness);
    try pretty.print(allocator, extended_header, .{});

    try self_stream.seekTo(extended_header.program_identification_header_offset);
    const program_identification_header = try Self.ProgramIdentificationHeader.read(reader, endianness);

    try pretty.print(allocator, program_identification_header, .{});

    try self_stream.seekTo(extended_header.supplemental_header_offset);
    const supplemental_headers = try Self.SupplementalHeaderTable.read(allocator, reader, extended_header, endianness);
    defer allocator.free(supplemental_headers);

    try pretty.print(allocator, supplemental_headers, .{ .array_u8_is_str = true });

    const system_key = system_keyset.get(.{
        .revision = certified_file_header.key_revision,
        .self_type = program_identification_header.program_type,
    }) orelse return error.MissingKey;

    try pretty.print(allocator, .{
        .revision = certified_file_header.key_revision,
        .self_type = program_identification_header.program_type,
    }, .{});
    try pretty.print(allocator, system_key, .{});

    // TODO: dont read the encryption root header for fSELF files
    try self_stream.seekTo(certified_file_header.byteSize() + certified_file_header.extended_header_size);
    // We need to remove the NPDRM layer with npdrm applications
    const encryption_root_header = if (certified_file_header.category == .signed_elf and program_identification_header.program_type == .npdrm_application) erh: {
        const npdrm_header = blk: {
            for (supplemental_headers) |supplemental_header| {
                if (supplemental_header == .ps3_npdrm)
                    break :blk supplemental_header.ps3_npdrm;
            }

            return error.MissingNpdrmSupplementalHeader;
        };

        var aes_ctxt: aes.aes_context = undefined;

        const klic_key = npdrm_keyset.get(.klic_key).?.aes;
        var npdrm_key: npdrm_keys.Key.AesKey = blk: {
            if (npdrm_header.drm_type == .free)
                break :blk npdrm_keyset.get(.klic_free).?.aes
            else if (npdrm_header.drm_type == .local) {
                // TODO: RIF+act.dat+IDPS reading
                var rap_file: [0x10]u8 = undefined;
                if ((try std.fs.cwd().readFile(args[4], &rap_file)).len != rap_file.len)
                    return error.InvalidRap;

                break :blk .{
                    .erk = npdrm_keys.rapToKlicensee(rap_file, npdrm_keyset),
                    .riv = .{0} ** 0x10,
                };
            } else {
                return error.UnableToFindNpdrmKey;
            }
        };

        // Decrypt the npdrm key
        _ = aes.aes_setkey_dec(&aes_ctxt, &klic_key.erk, @bitSizeOf(@TypeOf(klic_key.erk)));
        _ = aes.aes_crypt_ecb(&aes_ctxt, aes.AES_DECRYPT, &npdrm_key.erk, &npdrm_key.erk);

        break :erh try CertifiedFile.EncryptionRootHeader.readNpdrm(reader, npdrm_key, system_key);
    } else try CertifiedFile.EncryptionRootHeader.read(reader, system_key);

    try pretty.print(allocator, encryption_root_header, .{});

    { // Decrypt all bytes from now until the start of the file
        const pos: usize = @intCast(try self_stream.getPos());
        const len: usize = @intCast(certified_file_header.file_offset - (certified_file_header.byteSize() + certified_file_header.extended_header_size + encryption_root_header.byteSize()));
        const data = self[pos .. pos + len];

        // decrypt the certification header, segment certification header, and keys
        const aes128 = Aes128.initEnc(encryption_root_header.key);
        std.crypto.core.modes.ctr(@TypeOf(aes128), aes128, data, data, encryption_root_header.iv, endianness);
    }

    const certification_header = try CertifiedFile.CertificationHeader.read(reader, endianness);
    try pretty.print(allocator, certification_header, .{});

    const segment_certification_headers = try CertifiedFile.SegmentCertificationHeader.read(reader, allocator, certification_header, endianness);
    defer allocator.free(segment_certification_headers);
    try pretty.print(allocator, segment_certification_headers, .{});

    // TODO: what the hell is psdevwiki talking about with "attributes"?
    //       we are following what RPCS3/scetool does by reading these as a series of 16-byte keys
    //       psdevwiki: https://www.psdevwiki.com/ps3/Certified_File#Attributes
    //       rpcs3: https://github.com/RPCS3/rpcs3/blob/3e516df214f5c36d4b613aa0580182155247d2ad/rpcs3/Crypto/unself.cpp#L687
    const keys = try allocator.alloc([0x10]u8, certification_header.attr_entry_num);
    defer allocator.free(keys);
    for (keys) |*key| try reader.readNoEof(key);
    std.debug.print("read {d} keys: ", .{keys.len});
    try pretty.print(allocator, keys, .{});

    const optional_headers = try CertifiedFile.OptionalHeader.read(reader, allocator, certification_header, endianness);
    defer allocator.free(optional_headers);
    try pretty.print(allocator, optional_headers, .{});

    const signature = try CertifiedFile.Signature.read(reader, certification_header);
    std.debug.print("signature: ", .{});
    try pretty.print(allocator, signature, .{});
}
