const std = @import("std");
const builtin = @import("builtin");

const sce = @import("sce.zig");
const certified_file = sce.certified_file;
const CertifiedFile = sce.certified_file.CertifiedFile;
const Self = sce.Self;

const log = std.log.scoped(.unself);

pub const Error = error{
    InvalidElfClass,
    InvalidElfEndian,
    InvalidElfMagic,
    InvalidElfVersion,
    CantExtractFailedRead,
} || std.fs.File.WriteError || std.fs.File.SeekError || std.compress.zlib.Decompressor(std.fs.File.Reader).Error || certified_file.Error;

pub fn extractSelfToElf(
    self_data: []u8,
    read_certified_file: *CertifiedFile,
    output_stream: anytype,
    output_writer: anytype,
) Error!void {
    log.info("Extracting SELF file to ELF", .{});

    const self, const segment_certification_headers = switch (read_certified_file.*) {
        .full => |full| blk: {
            if (!full.body_decrypted)
                try read_certified_file.full.decryptBody();

            break :blk .{ full.contents.signed_elf, full.segment_certification_headers };
        },
        .fake => |fake| .{ fake.contents.signed_elf, null },
        else => {
            log.err("Cant extract SELF file, failed to read whole contents, expected full or fake, but got {s}", .{@tagName(read_certified_file.*)});
            return Error.CantExtractFailedRead;
        },
    };

    const program_type = self.program_identification_header.program_type;

    if (self.extended_header.elf_header_offset > std.math.maxInt(usize)) {
        log.err("Cannot continue extracting ELF file. ELF header offset ({d}) is invalid.", .{self.extended_header.elf_header_offset});
        return Error.InvalidPosOrSizeForPlatform;
    }

    const elf_header_data: [@sizeOf(std.elf.Elf64_Ehdr)]u8 align(@alignOf(std.elf.Elf64_Ehdr)) = self_data[@intCast(self.extended_header.elf_header_offset)..][0..@sizeOf(std.elf.Elf64_Ehdr)].*;

    const elf_header = try std.elf.Header.parse(&elf_header_data);
    if (program_type == .secure_loader or program_type == .isolated_spu_module or !elf_header.is_64)
        try writeElfInternal(self_data, false, read_certified_file.* == .fake, self, segment_certification_headers, output_stream, output_writer)
    else
        try writeElfInternal(self_data, true, read_certified_file.* == .fake, self, segment_certification_headers, output_stream, output_writer);

    log.info("Successfully extracted ELF file from SELF", .{});
}

fn writeElfInternal(
    self_data: []u8,
    comptime is_64_bit: bool,
    fake: bool,
    self: Self,
    segment_certification_headers: ?[]const certified_file.SegmentCertificationHeader,
    output_stream: anytype,
    output_writer: anytype,
) Error!void {
    const HeaderType, const PhdrType, const ShdrType = if (is_64_bit) .{
        std.elf.Elf64_Ehdr,
        std.elf.Elf64_Phdr,
        std.elf.Elf64_Shdr,
    } else .{
        std.elf.Elf32_Ehdr,
        std.elf.Elf32_Phdr,
        std.elf.Elf32_Shdr,
    };

    var buffered_writer = std.io.bufferedWriter(output_writer);

    const writer = buffered_writer.writer();

    if (self.extended_header.elf_header_offset > std.math.maxInt(usize)) {
        log.err("Cannot write ELF file, ELF header offset ({d}) is invalid", .{self.extended_header.elf_header_offset});
        return Error.InvalidPosOrSizeForPlatform;
    }

    const elf_header_data: [@sizeOf(std.elf.Elf64_Ehdr)]u8 align(@alignOf(std.elf.Elf64_Ehdr)) = self_data[@intCast(self.extended_header.elf_header_offset)..][0..@sizeOf(std.elf.Elf64_Ehdr)].*;

    // Write the elf header
    try writer.writeAll(elf_header_data[0..@sizeOf(HeaderType)]);

    log.info("Wrote ELF header", .{});

    const program_headers_end = self.extended_header.program_header_offset + @sizeOf(PhdrType) * self.elf_header.phnum;
    if (self.extended_header.program_header_offset > std.math.maxInt(usize) or program_headers_end > std.math.maxInt(usize)) {
        log.err("Cannot write ELF file, program header offset ({d}) or end offset ({d}) is invalid", .{ self.extended_header.program_header_offset, program_headers_end });
        return Error.InvalidPosOrSizeForPlatform;
    }

    // Write the program headers
    const program_headers_data = self_data[@intCast(self.extended_header.program_header_offset)..@intCast(program_headers_end)];
    try writer.writeAll(program_headers_data);

    log.info("Wrote {d} program headers", .{self.elf_header.phnum});

    const program_headers = std.mem.bytesAsSlice(PhdrType, program_headers_data);
    if (builtin.cpu.arch.endian() != self.elf_header.endian)
        for (program_headers) |*program_header| {
            var aligned_program_header = program_header.*;

            std.mem.byteSwapAllFields(PhdrType, &aligned_program_header);

            program_header.* = aligned_program_header;
        };

    // Write the program data
    if (fake) {
        // For fake SELF files, pull out the ELF file using
        for (self.segment_extended_headers, 0..) |segment_header, i| {
            // Flush before seeking
            try buffered_writer.flush();
            try output_stream.seekTo(program_headers[i].p_offset);

            if (segment_header.offset > std.math.maxInt(usize) or segment_header.size > std.math.maxInt(usize)) {
                log.err("Failed to write ELF segment {d}, segment offset ({d}) or size ({d}) is invalid", .{ i, segment_header.offset, segment_header.size });
                return Error.InvalidPosOrSizeForPlatform;
            }

            const program_data = self_data[@intCast(segment_header.offset)..@intCast(segment_header.offset + segment_header.size)];
            var program_data_stream = std.io.fixedBufferStream(program_data);

            switch (segment_header.compression) {
                // Write the segment program data to the ELF
                .plain => try writer.writeAll(program_data),
                // Decompress the segment program data into the ELF
                .zlib => try std.compress.zlib.decompress(program_data_stream.reader(), writer),
            }

            log.info("Wrote program segment {d}", .{i});
        }
    } else {
        for (segment_certification_headers.?, 0..) |segment_header, i| {
            if (segment_header.segment_type == .phdr) {
                // Flush before seeking
                try buffered_writer.flush();
                try output_stream.seekTo(program_headers[segment_header.segment_id].p_offset);

                if (segment_header.segment_offset > std.math.maxInt(usize) or segment_header.segment_size > std.math.maxInt(usize)) {
                    log.err("Failed to write ELF segment {d}, segment offset ({d}) or size ({d}) is invalid", .{ i, segment_header.segment_offset, segment_header.segment_size });
                    return Error.InvalidPosOrSizeForPlatform;
                }

                const program_data = self_data[@intCast(segment_header.segment_offset)..@intCast(segment_header.segment_offset + segment_header.segment_size)];
                var program_data_stream = std.io.fixedBufferStream(program_data);

                switch (segment_header.compression_algorithm) {
                    // Write the segment program data to the ELF
                    .plain => try writer.writeAll(program_data),
                    // Decompress the segment program data into the ELF
                    .zlib => try std.compress.zlib.decompress(program_data_stream.reader(), writer),
                }

                log.info("Wrote program segment {d}", .{i});
            }
        }
    }

    if (self.extended_header.section_header_offset != 0) {
        // Flush before seeking
        try buffered_writer.flush();
        try output_stream.seekTo(self.elf_header.shoff);

        const section_header_end = self.extended_header.section_header_offset + self.elf_header.shnum * @sizeOf(ShdrType);
        if (self.extended_header.section_header_offset > std.math.maxInt(usize) or section_header_end > std.math.maxInt(usize)) {
            log.err("Failed to write section header, offset ({d}) or end ({d}) is invalid", .{ self.extended_header.section_header_offset, section_header_end });
            return Error.InvalidPosOrSizeForPlatform;
        }

        // Write the section headers to the ELf
        try writer.writeAll(self_data[@intCast(self.extended_header.section_header_offset)..@intCast(section_header_end)]);

        log.info("Wrote ELF section header", .{});
    }

    try buffered_writer.flush();
}
