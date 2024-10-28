const std = @import("std");

const sce = @import("sce");
const cova = @import("cova");

const certified_file = sce.certified_file;
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
        CommandT.from(ExtractOptions, .{
            .cmd_name = "extract",
            .cmd_description = "Extracts the underlying ELF file of a SELF file",
            .sub_descriptions = &.{
                .{ "self_path", "The path to the SELF file." },
                .{ "out_path", "The path to output the ELF file to." },
                .{ "rap_path", "An optional path to a RAP file to use for decryption." },
                .{ "rif_path", "An optional path to a RIF file to use for decrypting NPDRM content." },
                .{ "act_dat_path", "An optional path to an ACT.DAT file to use for decrypting the RIF file." },
                .{ "idps_path", "An optional path to an IDPS file to use for decrypting the ACT.DAT key." },
                .{ "license_endianness", "The endianness to use when reading the license files." },
                .{ "system_keys_path", "The path to the system keys" },
                .{ "npdrm_keys_path", "The path to the NPDRM keys" },
            },
        }),
        CommandT.from(ExtractOptions, .{
            .cmd_name = "info",
            .cmd_description = "Displays info about a SELF file",
            .sub_descriptions = &.{
                .{ "self_path", "The path to the SELF file." },
                .{ "rap_path", "An optional path to a RAP file to use for decryption." },
                .{ "rif_path", "An optional path to a RIF file to use for decrypting NPDRM content." },
                .{ "act_dat_path", "An optional path to an ACT.DAT file to use for decrypting the RIF file." },
                .{ "idps_path", "An optional path to an IDPS file to use for decrypting the ACT.DAT key." },
                .{ "license_endianness", "The endianness to use when reading the license files." },
                .{ "system_keys_path", "The path to the system keys" },
                .{ "npdrm_keys_path", "The path to the NPDRM keys" },
            },
        }),
    },
};

const ExtractOptions = struct {
    self_path: []const u8,
    out_path: ?[]const u8 = "out.elf",
    rap_path: ?[]const u8 = null,
    rif_path: ?[]const u8 = null,
    act_dat_path: ?[]const u8 = null,
    idps_path: ?[]const u8 = null,
    license_endianness: ?std.builtin.Endian = null,
    system_keys_path: ?[]const u8 = "keys/system_keys.json",
    npdrm_keys_path: ?[]const u8 = "keys/npdrm_keys.json",
};

const InfoOptions = struct {
    self_path: []const u8,
    rap_path: ?[]const u8 = null,
    rif_path: ?[]const u8 = null,
    act_dat_path: ?[]const u8 = null,
    idps_path: ?[]const u8 = null,
    license_endianness: ?std.builtin.Endian = null,
    system_keys_path: ?[]const u8 = "keys/system_keys.json",
    npdrm_keys_path: ?[]const u8 = "keys/npdrm_keys.json",
};

fn readLicenseData(rap_path: ?[]const u8, rif_path: ?[]const u8, act_dat_path: ?[]const u8, idps_path: ?[]const u8, license_endianness: ?std.builtin.Endian) !certified_file.LicenseData {
    if (rap_path) |rap_file_path| {
        var rap: [0x10]u8 = undefined;
        if ((try std.fs.cwd().readFile(rap_file_path, &rap)).len != rap.len)
            return error.BadRapFile;
        return .{ .rap = rap };
    } else {
        const endianness = license_endianness orelse return error.MissingLicenseEndianness;

        const rif = rif_blk: {
            const rif_file = try std.fs.cwd().openFile(rif_path orelse return error.MissingRifPath, .{});
            defer rif_file.close();

            break :rif_blk try sce.RightsInformationFile.read(rif_file.reader(), endianness);
        };
        const act_dat = act_dat_blk: {
            const act_dat_file = try std.fs.cwd().openFile(act_dat_path orelse return error.MissingActDatPath, .{});
            defer act_dat_file.close();

            break :act_dat_blk try sce.ActivationData.read(act_dat_file.reader(), endianness);
        };
        const idps = idps_blk: {
            var idps: [0x10]u8 = undefined;
            if ((try std.fs.cwd().readFile(idps_path orelse return error.MissingIdpsPath, &idps)).len != idps.len)
                return error.BadIdpsFile;
            break :idps_blk idps;
        };

        return .{
            .rif = .{
                .rif = rif,
                .act_dat = act_dat,
                .idps = idps,
            },
        };
    }
}

fn extract(allocator: std.mem.Allocator, options: ExtractOptions) !void {
    const self_data = try std.fs.cwd().readFileAlloc(allocator, options.self_path, std.math.maxInt(usize));
    defer allocator.free(self_data);

    const systemKeysJson = try std.fs.cwd().readFileAlloc(allocator, options.system_keys_path.?, std.math.maxInt(usize));
    defer allocator.free(systemKeysJson);

    var system_keys = try system_keyset.read(allocator, systemKeysJson);
    defer system_keys.deinit();

    const npdrmKeysJson = try std.fs.cwd().readFileAlloc(allocator, options.npdrm_keys_path.?, std.math.maxInt(usize));
    defer allocator.free(npdrmKeysJson);

    var npdrm_keys = try npdrm_keyset.read(allocator, npdrmKeysJson);
    defer npdrm_keys.deinit();

    const license_data = try readLicenseData(
        options.rap_path,
        options.rif_path,
        options.act_dat_path,
        options.idps_path,
        options.license_endianness,
    );

    var read_certified_file = try certified_file.read(allocator, self_data, license_data, system_keys, npdrm_keys, false);
    defer read_certified_file.deinit(allocator);

    if (read_certified_file != .full and read_certified_file != .fake) {
        std.debug.print("wanted to read full CF or fCF, got {s}\n", .{@tagName(read_certified_file)});
        return error.UnableToFullyReadCertifiedFile;
    }

    const output = try std.fs.cwd().createFile(options.out_path.?, .{});
    defer output.close();

    try unself.extractSelfToElf(self_data, &read_certified_file, output.seekableStream(), output.writer());
}

fn printInfo(allocator: std.mem.Allocator, options: InfoOptions) !void {
    const self_data = try std.fs.cwd().readFileAlloc(allocator, options.self_path, std.math.maxInt(usize));
    defer allocator.free(self_data);

    const systemKeysJson = try std.fs.cwd().readFileAlloc(allocator, options.system_keys_path.?, std.math.maxInt(usize));
    defer allocator.free(systemKeysJson);

    var system_keys = try system_keyset.read(allocator, systemKeysJson);
    defer system_keys.deinit();

    const npdrmKeysJson = try std.fs.cwd().readFileAlloc(allocator, options.npdrm_keys_path.?, std.math.maxInt(usize));
    defer allocator.free(npdrmKeysJson);

    var npdrm_keys = try npdrm_keyset.read(allocator, npdrmKeysJson);
    defer npdrm_keys.deinit();

    const license_data = try readLicenseData(
        options.rap_path,
        options.rif_path,
        options.act_dat_path,
        options.idps_path,
        options.license_endianness,
    );

    const read_certified_file = try certified_file.read(allocator, self_data, license_data, system_keys, npdrm_keys, false);
    defer read_certified_file.deinit(allocator);

    const stdout = std.io.getStdOut().writer();

    switch (read_certified_file) {
        inline else => |read| {
            const header: certified_file.Header = read.header;
            const contents: certified_file.Contents = read.contents;

            try stdout.print(
                \\# CF Header
                \\- Version: {s}
                \\- Key Revision: {d}
                \\- Category: {s}
                \\- Extended Header Size: {d}
                \\- File Offset: {d}
                \\- File Size: {d}
                \\
            , .{
                @tagName(header.version),
                header.key_revision,
                @tagName(header.category),
                header.extended_header_size,
                header.file_offset,
                header.file_size,
            });

            if (header.vita_data) |vita_data| {
                try stdout.print(
                    \\- Certified File Size: {d}
                    \\- Padding: {d}
                    \\
                , .{
                    vita_data.certified_file_size,
                    vita_data.padding,
                });
            }

            try stdout.writeByte('\n');

            switch (contents) {
                .signed_elf => |self| {
                    try stdout.print(
                        \\# SELF Extended Header
                        \\- Version: {s}
                        \\- Program Identification Header Offset: {d}
                        \\- ELF Header Offset: {d}
                        \\- Program Header Offset: {d}
                        \\- Section Header Offset: {d}
                        \\- Segment Extended Header Offset: {d}
                        \\- Version Header Offset: {d}
                        \\- Supplemental Header Offset: {d}
                        \\- Supplemental Header Size: {d}
                        \\- Padding: {d}
                        \\
                    , .{
                        @tagName(self.extended_header.version),
                        self.extended_header.program_identification_header_offset,
                        self.extended_header.elf_header_offset,
                        self.extended_header.program_header_offset,
                        self.extended_header.section_header_offset,
                        self.extended_header.segment_extended_header_offset,
                        self.extended_header.version_header_offset,
                        self.extended_header.supplemental_header_offset,
                        self.extended_header.supplemental_header_size,
                        self.extended_header.padding,
                    });

                    try stdout.writeByte('\n');

                    try stdout.print(
                        \\# SELF Program Identification Header
                        \\- Program Authority ID: {d}-{d}-{s} (0x{x})
                        \\- Program Vender ID: {s}-{d} (0x{x})
                        \\- Program Type: {s}
                        \\- Program SCE Version: 0x{x}
                        \\- Padding: {d}
                        \\
                    , .{
                        self.program_identification_header.program_authority_id.program_id,
                        self.program_identification_header.program_authority_id.territory_id,
                        @tagName(self.program_identification_header.program_authority_id.console_generation),
                        @as(u64, @bitCast(self.program_identification_header.program_authority_id)),
                        @tagName(self.program_identification_header.program_vender_id.guest_os_id),
                        self.program_identification_header.program_vender_id.territory,
                        @as(u32, @bitCast(self.program_identification_header.program_vender_id)),
                        @tagName(self.program_identification_header.program_type),
                        self.program_identification_header.program_sceversion,
                        self.program_identification_header.padding,
                    });

                    try stdout.writeByte('\n');

                    try stdout.print("# {d} SELF Supplemental Headers \n", .{self.supplemental_headers.len});

                    for (self.supplemental_headers, 0..) |supplemental_header, i| {
                        try stdout.print("## {s} Supplemental Header {d}\n", .{ @tagName(supplemental_header), i });
                        switch (supplemental_header) {
                            .plaintext_capability => |plaintext_capability| {
                                try stdout.print(
                                    \\- Control Flag 1: {d}
                                    \\- Unknown 2: {d}
                                    \\- Unknown 3: {d}
                                    \\- Unknown 4: {d}
                                    \\- Unknown 5: {d}
                                    \\- Unknown 6: {d}
                                    \\- Unknown 7: {d}
                                    \\- Unknown 8: {d}
                                    \\
                                , .{
                                    plaintext_capability.ctrl_flag1,
                                    plaintext_capability.unknown2,
                                    plaintext_capability.unknown3,
                                    plaintext_capability.unknown4,
                                    plaintext_capability.unknown5,
                                    plaintext_capability.unknown6,
                                    plaintext_capability.unknown7,
                                    plaintext_capability.unknown8,
                                });
                            },
                            .ps3_elf_digest => |ps3_elf_digest| {
                                try stdout.print("- Type: {s}\n", .{@tagName(ps3_elf_digest)});
                                switch (ps3_elf_digest) {
                                    .small => |small| {
                                        try stdout.print(
                                            \\- Constant or ELF Digest: {x}
                                            \\- Padding: {x}
                                            \\
                                        , .{
                                            small.constant_or_elf_digsest,
                                            small.padding,
                                        });
                                    },
                                    .large => |large| {
                                        try stdout.print(
                                            \\- Constant: {x}
                                            \\- ELF Digest: {x}
                                            \\- Required System Version: {d} (0x{x})
                                            \\
                                        , .{
                                            large.constant,
                                            large.elf_digest,
                                            large.required_system_version,
                                            large.required_system_version,
                                        });
                                    },
                                }
                            },
                            .ps3_npdrm => |ps3_npdrm| {
                                try stdout.print(
                                    \\- Version: {d}
                                    \\- DRM Type: {s}
                                    \\- App Type: {s}
                                    \\- Content ID: {s}
                                    \\- Digest: {x}
                                    \\- CID FN Hash: {x}
                                    \\- Header Hash: {x}
                                    \\- Limited Time Start: {d}
                                    \\- Limited Time End: {d}
                                    \\
                                , .{
                                    ps3_npdrm.version,
                                    @tagName(ps3_npdrm.drm_type),
                                    @tagName(ps3_npdrm.app_type),
                                    ps3_npdrm.content_id,
                                    ps3_npdrm.digest,
                                    ps3_npdrm.cid_fn_hash,
                                    ps3_npdrm.header_hash,
                                    ps3_npdrm.limited_time_start,
                                    ps3_npdrm.limited_time_end,
                                });
                            },
                            .vita_elf_digest => |vita_elf_digest| {
                                try stdout.print(
                                    \\- Constant: {x}
                                    \\- ELF Digest: {x}
                                    \\- Padding: {d}
                                    \\- Minimum Required Firmware: {d} (0x{x})
                                    \\
                                , .{
                                    vita_elf_digest.constant,
                                    vita_elf_digest.elf_digest,
                                    vita_elf_digest.padding,
                                    vita_elf_digest.min_required_fw,
                                    vita_elf_digest.min_required_fw,
                                });
                            },
                            .vita_npdrm => |vita_npdrm| {
                                try stdout.print(
                                    \\- Finalized Flag: {d} (0x{x})
                                    \\- DRM Type: {s}
                                    \\- Padding: {d}
                                    \\- Content ID: {s}
                                    \\- Digest: {x}
                                    \\- Padding: {x}
                                    \\- Signature: (r: {x}, s: {x})
                                    \\
                                , .{
                                    vita_npdrm.finalized_flag,
                                    vita_npdrm.finalized_flag,
                                    @tagName(vita_npdrm.drm_type),
                                    vita_npdrm.padding,
                                    vita_npdrm.content_id,
                                    vita_npdrm.digest,
                                    vita_npdrm.padding_78,
                                    vita_npdrm.sig.r,
                                    vita_npdrm.sig.s,
                                });
                            },
                            .vita_boot_param => |vita_boot_param| {
                                try stdout.print(
                                    \\- Boot Params: {x}
                                    \\
                                , .{vita_boot_param.boot_param});
                            },
                            .vita_shared_secret => |vita_shared_secret| {
                                try stdout.print(
                                    \\- Shared Secret 0: {x}
                                    \\- Klicensee: {x}
                                    \\- Shared Secret 2: {x}
                                    \\- Shared Secret 3: {d}
                                    \\
                                , .{
                                    vita_shared_secret.shared_secret_0,
                                    vita_shared_secret.klicensee,
                                    vita_shared_secret.shared_secret_2,
                                    vita_shared_secret.shared_secret_3,
                                });
                            },
                        }
                    }

                    try stdout.writeByte('\n');

                    try stdout.print("# {d} Segment Extended Headers\n", .{self.segment_extended_headers.len});
                    for (self.segment_extended_headers, 0..) |segment_extended_header, i| {
                        try stdout.print(
                            \\## Segment Extended Header {d}
                            \\- Offset: {d}
                            \\- Size: {d}
                            \\- Compression: {s}
                            \\- Unknown: {d}
                            \\- Encryption: {s}
                            \\
                        , .{
                            i,
                            segment_extended_header.offset,
                            segment_extended_header.size,
                            @tagName(segment_extended_header.compression),
                            segment_extended_header.unknown,
                            @tagName(segment_extended_header.encryption),
                        });
                    }
                    try stdout.writeByte('\n');
                },
                else => try stdout.print("TODO: Contents type {s}\n", .{@tagName(contents)}),
            }
        },
    }

    if (read_certified_file == .full) {
        const full_certified_file = read_certified_file.full;

        try stdout.print(
            \\# Encryption Root Header
            \\- Key: {x}
            \\- Key Padding: {x}
            \\- IV: {x}
            \\- IV Padding: {x}
            \\
        , .{
            full_certified_file.encryption_root_header.key,
            full_certified_file.encryption_root_header.key_pad,
            full_certified_file.encryption_root_header.iv,
            full_certified_file.encryption_root_header.iv_pad,
        });
        try stdout.writeByte('\n');

        try stdout.print(
            \\# Certification Header
            \\- Sign Offset: {d}
            \\- Signing Algorithm: {s}
            \\- Num Segment Certification Headers: {d}
            \\- Num Attributes (Keys): {d}
            \\- Optional Header Size: {d}
            \\- Padding: {d}
            \\
        , .{
            full_certified_file.certification_header.sign_offset,
            @tagName(full_certified_file.certification_header.sign_algorithm),
            full_certified_file.certification_header.cert_entry_num,
            full_certified_file.certification_header.attr_entry_num,
            full_certified_file.certification_header.optional_header_size,
            full_certified_file.certification_header.pad,
        });
        try stdout.writeByte('\n');

        try stdout.print("# {d} Segment Certification Headers\n", .{full_certified_file.segment_certification_headers.len});
        for (full_certified_file.segment_certification_headers, 0..) |segment_certification_header, i| {
            try stdout.print(
                \\## Segment Certification Header {d}
                \\- Segment Offset: {d}
                \\- Segment Size: {d}
                \\- Segment Type: {s}
                \\- Segment ID: {d}
                \\- Signing Algorithm: {s}
                \\- Signing Index: {d}
                \\- Encryption Algorithm: {s}
                \\- Key Index: {?d}
                \\- IV Index: {?d}
                \\- Compression Algorithm: {s}
                \\
            , .{
                i,
                segment_certification_header.segment_offset,
                segment_certification_header.segment_size,
                @tagName(segment_certification_header.segment_type),
                segment_certification_header.segment_id,
                @tagName(segment_certification_header.signing_algorithm),
                segment_certification_header.signing_idx,
                @tagName(segment_certification_header.encryption_algorithm),
                segment_certification_header.key_idx,
                segment_certification_header.iv_idx,
                @tagName(segment_certification_header.compression_algorithm),
            });
        }
        try stdout.writeByte('\n');

        try stdout.print("# {d} Keys\n", .{full_certified_file.keys.len});
        for (full_certified_file.keys, 0..) |key, i| {
            try stdout.print(
                \\## Key {d} (0x{x}): {x}
                \\
            , .{ i, i, key });
        }
        try stdout.writeByte('\n');

        try stdout.print("# {d} Optional Headers\n", .{full_certified_file.optional_headers.len});
        for (full_certified_file.optional_headers, 0..) |optional_header, i| {
            try stdout.print(
                \\## {s} Optional Header {d}
                \\
            , .{ @tagName(optional_header), i });

            switch (optional_header) {
                .capability => |capability| {
                    try stdout.print(
                        \\- Unknown 1: {d}
                        \\- Unknown 2: {d}
                        \\- Unknown 3: {d}
                        \\- Unknown 4: {d}
                        \\- Unknown 5: {d}
                        \\- Unknown 6: {d}
                        \\- Unknown 7: {d}
                        \\- Unknown 8: {d}
                        \\
                    , .{
                        capability.unknown1,
                        capability.unknown2,
                        capability.unknown3,
                        capability.unknown4,
                        capability.unknown5,
                        capability.unknown6,
                        capability.unknown7,
                        capability.unknown8,
                    });
                },
                .individual_seed => |individual_seed| {
                    try stdout.print("- Individual Seed: {x}\n", .{individual_seed});
                },
                .attribute => |attribute| {
                    try stdout.print("- Attribute: {x}\n", .{attribute});
                },
            }
        }
        try stdout.writeByte('\n');

        try stdout.print("# {s} Signature\n", .{@tagName(full_certified_file.signature)});
        switch (full_certified_file.signature) {
            .ecdsa160 => |ecdsa160| {
                try stdout.print(
                    \\- r: {x}
                    \\- s: {x}
                    \\- padding: {x}
                    \\
                , .{
                    ecdsa160.r,
                    ecdsa160.s,
                    ecdsa160.padding,
                });
            },
            .rsa2048 => |rsa2048| {
                try stdout.print(
                    \\- rsa: {x}
                    \\
                , .{rsa2048.rsa});
            },
            else => try stdout.print("- TODO\n", .{}),
        }
        try stdout.writeByte('\n');
    }
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
        const extract_args = try extract_cmd.to(ExtractOptions, .{});
        try extract(allocator, extract_args);
    }

    if (main_cmd.matchSubCmd("info")) |info_cmd| {
        const extract_args = try info_cmd.to(InfoOptions, .{});
        try printInfo(allocator, extract_args);
    }

    return 0;
}
