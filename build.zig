const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const aes = createAes(b, target, optimize, createLibc(b, target, optimize));
    const libsce = createLibsce(b, target, optimize, aes);
    const selftool = createSelftool(b, target, optimize, libsce, aes);
    const licensetool = createLicensetool(b, target, optimize, libsce);
    const libsce_c_abi = createLibSceCAbi(b, target, optimize, libsce);

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
}

fn createLibSceCAbi(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    libsce: *std.Build.Module,
) *std.Build.Step.Compile {
    const libsce_c_abi = b.addSharedLibrary(.{
        .name = "sce",
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("c_abi/lib.zig"),
    });
    libsce_c_abi.root_module.addImport("sce", libsce);

    return libsce_c_abi;
}

fn createLibc(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step.Compile {
    // Libc reimplementations
    const c = b.addStaticLibrary(.{
        .name = "c",
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("libc/c.zig"),
        .pic = true,
    });
    c.installHeader(b.path("libc/c.h"), "c.h");

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
    licensetool.root_module.addImport("sce", libsce);

    licensetool.root_module.addImport("cova", b.dependency("cova", .{ .target = target, .optimize = optimize }).module("cova"));

    return licensetool;
}
