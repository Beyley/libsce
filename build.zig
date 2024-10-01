const std = @import("std");

// runner.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Libc reimplementations
    const c = b.addStaticLibrary(.{
        .name = "c",
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("libc/c.zig"),
    });
    c.installHeader(b.path("libc/c.h"), "c.h");

    const aes = b.addStaticLibrary(.{
        .name = "aes",
        .target = target,
        .optimize = optimize,
    });
    aes.linkLibrary(c);
    aes.addCSourceFile(.{ .file = b.path("aes/aes.c") });
    aes.installHeader(b.path("aes/aes.h"), "aes.h");

    const exe = b.addExecutable(.{
        .name = "selftool",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe.linkLibrary(c);
    exe.linkLibrary(aes);

    exe.root_module.addImport("pretty", b.dependency("pretty", .{ .target = target, .optimize = optimize }).module("pretty"));

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
