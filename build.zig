const std = @import("std");

// runner.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const aes = createAes(b, target, optimize, createLibc(b, target, optimize));
    const libsce = createLibsce(b, target, optimize, aes);
    const selftool = createSelftool(b, target, optimize, libsce, aes);

    b.installArtifact(selftool);

    const run_selftool = b.addRunArtifact(selftool);
    run_selftool.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_selftool.addArgs(args);
    }

    const run_step = b.step("selftool", "Run the app");
    run_step.dependOn(&run_selftool.step);
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

    selftool.root_module.addImport("pretty", b.dependency("pretty", .{ .target = target, .optimize = optimize }).module("pretty"));

    return selftool;
}
