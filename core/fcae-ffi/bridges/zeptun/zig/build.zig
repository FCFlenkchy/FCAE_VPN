const std = @import("std");

/// Builds the static `libzeptun.a` this bridge links in-process.
///
/// Lives in the bridge, not in `core/`: it is the zeptun bridge's build, and the
/// only thing that runs it is `build.rs` (or the CI step that pre-populates the
/// archive). The dependency resolves to the `core/zeptun` submodule four levels
/// up — the zon beside this file is the source of truth for that path.
///
/// Windows is the only target that needs this wrapper: zeptun's own build links
/// its TLS-backed SMP allocator, which a Windows host cannot provide, so the
/// engine is pinned to the C allocator path here. The other platforms are built
/// by zeptun's own `make` / `zig build` / `scripts/build_android.sh`.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    if (target.result.os.tag != .windows) {
        std.debug.panic(
            "fcae zeptun bridge: this build produces the Windows archive only (got {s}-{s})",
            .{ @tagName(target.result.cpu.arch), @tagName(target.result.os.tag) },
        );
    }

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
