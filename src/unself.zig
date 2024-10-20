const std = @import("std");

const sce = @import("sce.zig");
const CertifiedFile = sce.CertifiedFile;
const Self = sce.Self;

pub fn extractSelfToElf(
    self_data: []u8,
    certified_file: CertifiedFile,
    output_stream: anytype,
    output_writer: anytype,
) !void {
    const self = certified_file.contents.signed_elf;

    const program_type = self.program_identification_header.program_type;

    const elf_header_data: [@sizeOf(std.elf.Elf64_Ehdr)]u8 align(@alignOf(std.elf.Elf64_Ehdr)) = self_data[self.extended_header.elf_header_offset..][0..@sizeOf(std.elf.Elf64_Ehdr)].*;

    const elf_header = try std.elf.Header.parse(&elf_header_data);
    if (program_type == .secure_loader or program_type == .isolated_spu_module or !elf_header.is_64)
        try writeElfInternal(self_data, false, self.extended_header, certified_file.segment_certification_headers, output_stream, output_writer)
    else
        try writeElfInternal(self_data, true, self.extended_header, certified_file.segment_certification_headers, output_stream, output_writer);
}

fn writeElfInternal(
    self_data: []u8,
    comptime is_64_bit: bool,
    extended_header: Self.ExtendedHeader,
    segment_certification_headers: []const CertifiedFile.SegmentCertificationHeader,
    output_stream: anytype,
    output_writer: anytype,
) !void {
    const PhdrType, const ShdrType = if (is_64_bit) .{ std.elf.Elf64_Phdr, std.elf.Elf64_Shdr } else .{ std.elf.Elf32_Phdr, std.elf.Elf32_Shdr };

    var buffered_writer = std.io.bufferedWriter(output_writer);

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
            try output_stream.seekTo(@byteSwap(program_headers[segment_header.segment_id].p_offset));

            const program_data = self_data[segment_header.segment_offset .. segment_header.segment_offset + segment_header.segment_size];
            var program_data_stream = std.io.fixedBufferStream(program_data);

            switch (segment_header.compression_algorithm) {
                // Write the segment program data to the ELF
                .plain => try writer.writeAll(program_data),
                // Decompress the segment program data into the ELF
                .zlib => try std.compress.zlib.decompress(program_data_stream.reader(), writer),
            }
        }
    }

    if (extended_header.section_header_offset != 0) {
        // Flush before seeking
        try buffered_writer.flush();
        try output_stream.seekTo(elf_header.shoff);
        // Write the section headers to the ELf
        try writer.writeAll(self_data[extended_header.section_header_offset .. extended_header.section_header_offset + elf_header.shnum * @sizeOf(ShdrType)]);
    }

    try buffered_writer.flush();
}
