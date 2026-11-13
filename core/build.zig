const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    if (target.result.os.tag != .windows) @panic("This build is for the Windows Zeptun archive");

    const zeptun = b.dependency("zeptun", .{ .target = target, .optimize = optimize });
    const engine = zeptun.module("zeptun");
    engine.link_libc = true;
    const ffi = b.createModule(.{
        .root_source_file = zeptun.path("src/ffi/ffi.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
    });
    ffi.addImport("zeptun", engine);
    const lib = b.addLibrary(.{ .name = "zeptun", .root_module = ffi, .linkage = .static });
    b.installArtifact(lib);
}
