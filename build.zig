const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) !void {
    const install_target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const aes = createAes(b, install_target, optimize, createLibc(b, install_target, optimize));
    const libsce = createLibsce(b, install_target, optimize, aes);
    const selftool = createSelftool(b, install_target, optimize, libsce, aes);
    const licensetool = createLicensetool(b, install_target, optimize, libsce);
    const libsce_c_abi = createLibSceCAbi(b, install_target, optimize, libsce, null);

    b.installArtifact(selftool);
    b.installArtifact(licensetool);
    b.installArtifact(libsce_c_abi);

    const run_selftool = b.addRunArtifact(selftool);
    run_selftool.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_selftool.addArgs(args);
    }

    const selftool_run_step = b.step("selftool", "Run the app");
    selftool_run_step.dependOn(&run_selftool.step);

    const run_licensetool = b.addRunArtifact(licensetool);
    run_licensetool.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_licensetool.addArgs(args);
    }

    const licensetool_run_step = b.step("licensetool", "Run the app");
    licensetool_run_step.dependOn(&run_licensetool.step);

    const package_targets: []const std.Build.ResolvedTarget = &.{
        std.Build.resolveTargetQuery(b, std.Target.Query{
            .abi = .gnu,
            .glibc_version = .{
                .major = 2,
                .minor = 17,
                .patch = 0,
            },
            .cpu_arch = .x86_64,
            .os_tag = .linux,
        }),
        std.Build.resolveTargetQuery(b, std.Target.Query{
            .abi = .gnu,
            .glibc_version = .{
                .major = 2,
                .minor = 17,
                .patch = 0,
            },
            .cpu_arch = .aarch64,
            .os_tag = .linux,
        }),
        std.Build.resolveTargetQuery(b, std.Target.Query{
            .abi = .gnueabihf,
            .glibc_version = .{
                .major = 2,
                .minor = 17,
                .patch = 0,
            },
            .cpu_arch = .arm,
            .os_tag = .linux,
        }),
        std.Build.resolveTargetQuery(b, std.Target.Query{
            .cpu_arch = .aarch64,
            .os_tag = .windows,
        }),
        std.Build.resolveTargetQuery(b, std.Target.Query{
            .cpu_arch = .x86_64,
            .os_tag = .windows,
        }),
        std.Build.resolveTargetQuery(b, std.Target.Query{
            .cpu_arch = .aarch64,
            .os_tag = .macos,
        }),
        std.Build.resolveTargetQuery(b, std.Target.Query{
            .cpu_arch = .x86_64,
            .os_tag = .macos,
        }),
        std.Build.resolveTargetQuery(b, std.Target.Query{
            .cpu_arch = .x86_64,
            .os_tag = .linux,
            .abi = .android,
        }),
        std.Build.resolveTargetQuery(b, std.Target.Query{
            .cpu_arch = .aarch64,
            .os_tag = .linux,
            .abi = .android,
        }),
        std.Build.resolveTargetQuery(b, std.Target.Query{
            .cpu_arch = .arm,
            .os_tag = .linux,
            .abi = .androideabi,
        }),
        std.Build.resolveTargetQuery(b, std.Target.Query{
            .cpu_arch = .aarch64,
            .os_tag = .ios,
        }),
        std.Build.resolveTargetQuery(b, std.Target.Query{
            .cpu_arch = .x86_64,
            .os_tag = .ios,
            .abi = .simulator,
        }),
        std.Build.resolveTargetQuery(b, std.Target.Query{
            .cpu_arch = .aarch64,
            .os_tag = .ios,
            .abi = .simulator,
        }),
    };

    const ndk_version: usize = b.option(usize, "ndk_version", "The android NDK version to use when build") orelse 21;

    // attempts in order of cmd option, env var, default unix path
    const ndk_root: ?[]const u8 = b.option([]const u8, "ndk_root", "The NDK root") orelse
        if (try std.process.hasEnvVar(b.allocator, "ANDROID_NDK_ROOT"))
        try std.process.getEnvVarOwned(b.allocator, "ANDROID_NDK_ROOT")
    else
        null;

    const ios_sdk_root = b.option([]const u8, "ios_sdk_root", "The root of the iOS SDK");
    const ios_simulator_sdk_root = b.option([]const u8, "ios_simulator_sdk_root", "The root of the iOS simulator SDK");

    const publish_step = b.step("publish_libsce", "Automatically publishes the libsce C API into a .NET runtime folder structure");

    for (package_targets) |package_target| {
        const target = package_target.result;

        // If we don't have the Android NDK, skip Android builds
        if (ndk_root == null and target.isAndroid()) continue;
        // If we dont have the iOS SDK, skip iOS builds
        if (ios_sdk_root == null and target.os.tag == .ios) continue;
        // If we don't have the iOS Simulator SDK, skip iOS Simulator Builds
        if (ios_simulator_sdk_root == null and target.abi == .simulator) continue;

        const libc_file = blk: {
            if (target.isAndroid())
                break :blk try createAndroidLibCFile(b, target, ndk_root.?, ndk_version);

            if (target.os.tag == .ios)
                break :blk try createIosLibCFile(b, target, ios_sdk_root.?);

            if (target.abi == .simulator)
                break :blk try createIosLibCFile(b, target, ios_simulator_sdk_root.?);

            break :blk null;
        };

        const package_aes = createAes(b, package_target, optimize, createLibc(b, package_target, optimize));
        const package_libsce = createLibsce(b, package_target, optimize, package_aes);
        const package_libsce_c_abi = createLibSceCAbi(b, package_target, optimize, package_libsce, libc_file);

        const install_step = b.addInstallLibFile(package_libsce_c_abi.getEmittedBin(), getDotnetRuntimePath(b, target));
        install_step.step.dependOn(&package_libsce_c_abi.step);
        publish_step.dependOn(&install_step.step);
    }
}

fn createLibSceCAbi(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    libsce: *std.Build.Module,
    libc_file: ?std.Build.LazyPath,
) *std.Build.Step.Compile {
    const libsce_c_abi = b.addSharedLibrary(.{
        .name = "sce",
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("c_abi/lib.zig"),
        .pic = true,
    });
    // If a libc file is specified, link libc and set the libc file
    if (libc_file) |libc| {
        libc.addStepDependencies(&libsce_c_abi.step);

        libsce_c_abi.setLibCFile(libc);
        libsce_c_abi.linkLibC();
    }

    // HACK: Works around https://github.com/ziglang/zig/issues/20625
    if (target.result.abi.isGnu())
        libsce_c_abi.linkLibC();

    libsce_c_abi.root_module.addImport("sce", libsce);

    libsce_c_abi.root_module.addAnonymousImport("npdrm_keys_file", .{ .root_source_file = b.path("keys/npdrm_keys.json") });
    libsce_c_abi.root_module.addAnonymousImport("system_keys_file", .{ .root_source_file = b.path("keys/system_keys.json") });

    return libsce_c_abi;
}

fn createLibc(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step.Compile {
    // Libc reimplementations
    const c = b.addStaticLibrary(.{
        .name = "c_polyfill",
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("libc/c.zig"),
        .pic = true, // we end up linking this into a shared library, so it needs to be pic
    });
    c.installHeader(b.path("libc/c.h"), "c.h");

    if (target.result.isAndroid())
        c.pie = true;

    return c;
}

fn createAes(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    c: *std.Build.Step.Compile,
) *std.Build.Step.Compile {
    const aes_header = b.addTranslateC(.{
        .link_libc = false,
        .optimize = optimize,
        .target = target,
        .root_source_file = b.path("aes/aes.h"),
    });
    aes_header.addIncludePath(b.path("libc"));

    const aes = b.addStaticLibrary(.{
        .name = "aes",
        .target = target,
        .optimize = optimize,
        .root_source_file = aes_header.getOutput(),
        .pic = true,
    });
    aes.step.dependOn(&aes_header.step);
    aes.linkLibrary(c);
    aes.addCSourceFile(.{ .file = b.path("aes/aes.c") });
    aes.installHeader(b.path("aes/aes.h"), "aes.h");

    return aes;
}

fn createLibsce(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    aes: *std.Build.Step.Compile,
) *std.Build.Module {
    const libsce = b.addModule("libsce", .{
        .root_source_file = b.path("src/sce.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true,
    });
    libsce.linkLibrary(aes);
    libsce.addImport("aes", &aes.root_module);

    return libsce;
}

fn createSelftool(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    libsce: *std.Build.Module,
    aes: *std.Build.Step.Compile,
) *std.Build.Step.Compile {
    const selftool = b.addExecutable(.{
        .name = "selftool",
        .root_source_file = b.path("selftool/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // HACK: Works around https://github.com/ziglang/zig/issues/20625
    if (target.result.abi.isGnu())
        selftool.linkLibC();

    selftool.root_module.addImport("sce", libsce);
    selftool.root_module.addImport("aes", &aes.root_module);

    selftool.root_module.addImport("cova", b.dependency("cova", .{ .target = target, .optimize = optimize }).module("cova"));

    return selftool;
}

fn createLicensetool(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    libsce: *std.Build.Module,
) *std.Build.Step.Compile {
    const licensetool = b.addExecutable(.{
        .name = "licensetool",
        .root_source_file = b.path("licensetool/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    // HACK: Works around https://github.com/ziglang/zig/issues/20625
    if (target.result.abi.isGnu())
        licensetool.linkLibC();

    licensetool.root_module.addImport("sce", libsce);

    licensetool.root_module.addImport("cova", b.dependency("cova", .{ .target = target, .optimize = optimize }).module("cova"));

    return licensetool;
}

fn getDotnetRuntimePath(b: *std.Build, target: std.Target) []const u8 {
    const dotnet_os = if (target.isAndroid())
        "android"
    else switch (target.os.tag) {
        .linux => "linux",
        .macos => "osx",
        .windows => "win",
        .ios => "ios",
        else => @panic("unknown os, sorry"),
    };
    const dotnet_arch = switch (target.cpu.arch) {
        .x86_64 => "x64",
        .arm => "arm",
        .aarch64 => "arm64",
        else => @panic("unknown arch, sorry"),
    };
    const final_name = switch (target.os.tag) {
        .linux => "libsce.so",
        .windows => "sce.dll",
        .macos => "libsce.dylib",
        .ios => "libsce.a", // we build static libraries on iOS
        else => @panic("unknown os, sorry"),
    };

    return b.fmt("{s}-{s}/native/{s}", .{
        dotnet_os,
        dotnet_arch,
        final_name,
    });
}

fn createLibCFile(b: *std.Build, file_name: []const u8, include_dir: []const u8, sys_include_dir: []const u8, crt_dir: []const u8) !std.Build.LazyPath {
    var contents = std.ArrayList(u8).init(b.allocator);
    errdefer contents.deinit();

    var writer = contents.writer();

    //  The directory that contains `stdlib.h`.
    //  On POSIX-like systems, include directories be found with: `cc -E -Wp,-v -xc /dev/null
    try writer.print("include_dir={s}\n", .{include_dir});

    // The system-specific include directory. May be the same as `include_dir`.
    // On Windows it's the directory that includes `vcruntime.h`.
    // On POSIX it's the directory that includes `sys/errno.h`.
    try writer.print("sys_include_dir={s}\n", .{sys_include_dir});

    try writer.print("crt_dir={s}\n", .{crt_dir});
    try writer.writeAll("msvc_lib_dir=\n");
    try writer.writeAll("kernel32_lib_dir=\n");
    try writer.writeAll("gcc_dir=\n");

    const step = b.addWriteFiles();
    return step.add(file_name, contents.items);
}

fn createAndroidLibCFile(b: *std.Build, target: std.Target, ndk_root: []const u8, ndk_version: usize) !std.Build.LazyPath {
    const android_triple = androidTriple(target);

    const lib_dir = b.fmt("{s}/toolchains/llvm/prebuilt/{s}/sysroot/usr/lib/{s}/{d}/", .{
        ndk_root,
        comptime androidToolchainHostTag(),
        android_triple,
        ndk_version,
    });
    const include_dir = try std.fs.path.resolve(b.allocator, &.{
        ndk_root,
        "toolchains",
        "llvm",
        "prebuilt",
        comptime androidToolchainHostTag(),
        "sysroot",
        "usr",
        "include",
    });
    const system_include_dir = try std.fs.path.resolve(b.allocator, &.{
        include_dir,
        android_triple,
    });

    return try createLibCFile(
        b,
        b.fmt("android-{d}-{s}.conf", .{ ndk_version, @tagName(target.cpu.arch) }),
        include_dir,
        system_include_dir,
        lib_dir,
    );
}

fn createIosLibCFile(b: *std.Build, target: std.Target, ios_sdk_root: []const u8) !std.Build.LazyPath {
    const lib_dir = try std.fs.path.resolve(b.allocator, &.{ ios_sdk_root, "usr", "lib" });
    const include_dir = try std.fs.path.resolve(b.allocator, &.{ ios_sdk_root, "usr", "include" });

    return try createLibCFile(
        b,
        b.fmt(
            "ios-{s}-{s}.conf",
            .{ @tagName(target.cpu.arch), @tagName(target.abi) },
        ),
        include_dir,
        include_dir,
        lib_dir,
    );
}

fn androidToolchainHostTag() []const u8 {
    return @tagName(builtin.os.tag) ++ "-" ++ @tagName(builtin.cpu.arch);
}

fn androidTriple(target: std.Target) []const u8 {
    return switch (target.cpu.arch) {
        .x86_64 => "x86_64-linux-android",
        .aarch64 => "aarch64-linux-android",
        .arm => "arm-linux-androideabi",
        else => @panic("TODO"),
    };
}
