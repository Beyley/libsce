const std = @import("std");
const pretty = @import("pretty");

const aes = @import("aes");

const sce = @import("sce");

const npdrm_keyset = sce.npdrm_keyset;
const system_keyset = sce.system_keyset;

const certified_file = sce.certified_file;
const self = sce.self;

const Aes128 = std.crypto.core.aes.Aes128;

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
    const reader = self_stream.reader();

    const systemKeysJson = try std.fs.cwd().readFileAlloc(allocator, args[2], std.math.maxInt(usize));
    defer allocator.free(systemKeysJson);

    var system_keys = try system_keyset.read(allocator, systemKeysJson);
    defer system_keys.deinit();

    const npdrmKeysJson = try std.fs.cwd().readFileAlloc(allocator, args[3], std.math.maxInt(usize));
    defer allocator.free(npdrmKeysJson);

    var npdrm_keys = try npdrm_keyset.read(allocator, npdrmKeysJson);
    defer npdrm_keys.deinit();

    // read/decrypt header

    const certified_file_header = try certified_file.Header.read(reader);
    const endianness = certified_file_header.endianness();

    // TODO: non-SELF file extraction
    if (certified_file_header.category != .signed_elf)
        return error.OnlySelfSupported;

    // TODO: fSELF file extraction
    if (certified_file_header.key_revision == 0x8000)
        return error.FselfUnsupported;

    const extended_header = try self.ExtendedHeader.read(reader, endianness);

    try self_stream.seekTo(extended_header.program_identification_header_offset);
    const program_identification_header = try self.ProgramIdentificationHeader.read(reader, endianness);

    try self_stream.seekTo(extended_header.supplemental_header_offset);
    const supplemental_headers = try self.SupplementalHeaderTable.read(allocator, reader, extended_header, endianness);
    defer allocator.free(supplemental_headers);

    const system_key = system_keys.get(.{
        .revision = certified_file_header.key_revision,
        .self_type = program_identification_header.program_type,
    }) orelse return error.MissingKey;

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

        const klic_key = npdrm_keys.get(.klic_key).?.aes;
        var npdrm_key: npdrm_keyset.Key.AesKey = blk: {
            if (npdrm_header.drm_type == .free)
                break :blk npdrm_keys.get(.klic_free).?.aes
            else if (npdrm_header.drm_type == .local) {
                // TODO: RIF+act.dat+IDPS reading
                var rap_file: [0x10]u8 = undefined;
                if ((try std.fs.cwd().readFile(args[4], &rap_file)).len != rap_file.len)
                    return error.InvalidRap;

                break :blk .{
                    .erk = npdrm_keyset.rapToKlicensee(rap_file, npdrm_keys),
                    .riv = .{0} ** 0x10,
                };
            } else {
                return error.UnableToFindNpdrmKey;
            }
        };

        // Decrypt the npdrm key
        _ = aes.aes_setkey_dec(&aes_ctxt, &klic_key.erk, @bitSizeOf(@TypeOf(klic_key.erk)));
        _ = aes.aes_crypt_ecb(&aes_ctxt, aes.AES_DECRYPT, &npdrm_key.erk, &npdrm_key.erk);

        break :erh try certified_file.EncryptionRootHeader.readNpdrm(reader, npdrm_key, system_key);
    } else try certified_file.EncryptionRootHeader.read(reader, system_key);

    { // Decrypt all bytes from now until the start of the file
        const pos: usize = @intCast(try self_stream.getPos());
        const len: usize = @intCast(certified_file_header.file_offset - (certified_file_header.byteSize() + certified_file_header.extended_header_size + encryption_root_header.byteSize()));
        const data = self_data[pos .. pos + len];

        // decrypt the certification header, segment certification header, and keys
        const aes128 = Aes128.initEnc(encryption_root_header.key);
        std.crypto.core.modes.ctr(@TypeOf(aes128), aes128, data, data, encryption_root_header.iv, endianness);
    }

    const certification_header = try certified_file.CertificationHeader.read(reader, endianness);

    const segment_certification_headers = try certified_file.SegmentCertificationHeader.read(reader, allocator, certification_header, endianness);
    defer allocator.free(segment_certification_headers);

    // TODO: what the hell is psdevwiki talking about with "attributes"?
    //       we are following what RPCS3/scetool does by reading these as a series of 16-byte keys
    //       psdevwiki: https://www.psdevwiki.com/ps3/Certified_File#Attributes
    //       rpcs3: https://github.com/RPCS3/rpcs3/blob/3e516df214f5c36d4b613aa0580182155247d2ad/rpcs3/Crypto/unself.cpp#L687
    const keys = try allocator.alloc([0x10]u8, certification_header.attr_entry_num);
    defer allocator.free(keys);
    for (keys) |*key| try reader.readNoEof(key);

    const optional_headers = try certified_file.OptionalHeader.read(reader, allocator, certification_header, endianness);
    defer allocator.free(optional_headers);

    const signature = try certified_file.Signature.read(reader, certification_header);
    _ = signature; // autofix

    // decrypt data

    for (segment_certification_headers, 0..) |segment_header, i| {
        _ = i; // autofix
        if (segment_header.encryption_algorithm != .none) blk: {
            if (segment_header.key_idx == null or segment_header.iv_idx == null or segment_header.key_idx.? >= certification_header.attr_entry_num or segment_header.iv_idx.? >= certification_header.attr_entry_num) {
                break :blk;
            }

            const key_idx = segment_header.key_idx.?;
            const iv_idx = segment_header.iv_idx.?;

            const data = self_data[segment_header.segment_offset .. segment_header.segment_offset + segment_header.segment_size];

            switch (segment_header.encryption_algorithm) {
                .aes128_ctr => {
                    const aes128 = Aes128.initEnc(keys[key_idx]);
                    std.crypto.core.modes.ctr(@TypeOf(aes128), aes128, data, data, keys[iv_idx], endianness);
                },
                .aes128_cbc_cfb => {
                    // TODO: lets throw an error so we can hopefully find one of these cbc_cfb SELFs in the wild, and implement support!
                    return error.TodoAes128CbcCfb;
                },
                .none => unreachable,
            }
        }
    }

    // begin unself

    const program_type = program_identification_header.program_type;

    const elf_header_data: [@sizeOf(std.elf.Elf64_Ehdr)]u8 align(@alignOf(std.elf.Elf64_Ehdr)) = self_data[extended_header.elf_header_offset..][0..@sizeOf(std.elf.Elf64_Ehdr)].*;

    const elf_header = try std.elf.Header.parse(&elf_header_data);
    if (program_type == .secure_loader or program_type == .isolated_spu_module or !elf_header.is_64)
        try writeElf(self_data, args[5], false, extended_header, segment_certification_headers)
    else
        try writeElf(self_data, args[5], true, extended_header, segment_certification_headers);
}

fn writeElf(
    self_data: []u8,
    out_path: []const u8,
    comptime is_64_bit: bool,
    extended_header: self.ExtendedHeader,
    segment_certification_headers: []const certified_file.SegmentCertificationHeader,
) !void {
    const PhdrType, const ShdrType = if (is_64_bit) .{ std.elf.Elf64_Phdr, std.elf.Elf64_Shdr } else .{ std.elf.Elf32_Phdr, std.elf.Elf32_Shdr };

    const output = try std.fs.cwd().createFile(out_path, .{});
    defer output.close();

    var buffered_writer = std.io.bufferedWriter(output.writer());
    defer buffered_writer.flush() catch unreachable; //TODO: this should *not* be unreachable!

    const writer = buffered_writer.writer();

    const elf_header_data: [@sizeOf(std.elf.Elf64_Ehdr)]u8 align(@alignOf(std.elf.Elf64_Ehdr)) = self_data[extended_header.elf_header_offset..][0..@sizeOf(std.elf.Elf64_Ehdr)].*;

    const elf_header = try std.elf.Header.parse(&elf_header_data);

    // Write the elf header
    try writer.writeAll(elf_header_data[0..@sizeOf(std.elf.Elf32_Ehdr)]);

    // Write the program headers
    const program_headers_data = self_data[extended_header.program_header_offset .. extended_header.program_header_offset + @sizeOf(PhdrType) * elf_header.phnum];
    try writer.writeAll(program_headers_data);

    const program_headers = std.mem.bytesAsSlice(PhdrType, program_headers_data);

    // Write the program data
    for (segment_certification_headers) |segment_header| {
        if (segment_header.segment_type == .phdr) {
            // Flush before seeking
            try buffered_writer.flush();
            try output.seekTo(@byteSwap(program_headers[segment_header.segment_id].p_offset));

            const program_data = self_data[segment_header.segment_offset .. segment_header.segment_offset + segment_header.segment_size];
            var program_data_stream = std.io.fixedBufferStream(program_data);

            switch (segment_header.compression_algorithm) {
                // Write the segment program data to the ELF
                .plain => try output.writeAll(program_data),
                // Decompress the segment program data into the ELF
                .zlib => try std.compress.zlib.decompress(program_data_stream.reader(), writer),
            }
        }
    }

    if (extended_header.section_header_offset != 0) {
        // Flush before seeking
        try buffered_writer.flush();
        try output.seekTo(elf_header.shoff);
        // Write the section headers to the ELf
        try output.writeAll(self_data[extended_header.section_header_offset .. extended_header.section_header_offset + elf_header.shnum * @sizeOf(ShdrType)]);
    }
}
