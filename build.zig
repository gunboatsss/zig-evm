const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const setup_wf = b.addWriteFiles();
    _ = setup_wf.addCopyFile(b.path("vendor/c-kzg-4844/src/trusted_setup.txt"), "trusted_setup.txt");
    const setup_src = setup_wf.add("trusted_setup_txt.zig", "pub const txt = @embedFile(\"trusted_setup.txt\");\n");
    const setup_mod = b.createModule(.{ .root_source_file = setup_src });

    const ckzg_c = b.addTranslateC(.{
        .root_source_file = b.path("vendor/c-kzg-4844/src/ckzg.h"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    ckzg_c.addIncludePath(b.path("vendor/c-kzg-4844/src"));
    ckzg_c.addIncludePath(b.path("vendor/blst/bindings"));
    const ckzg_c_mod = ckzg_c.createModule();

    const root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    add_ckzg(b, root_module, target, ckzg_c_mod, setup_mod);

    const exe = b.addExecutable(.{
        .name = "zig-evm",
        .root_module = root_module,
    });
    b.installArtifact(exe);

    const test_module = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    add_ckzg(b, test_module, target, ckzg_c_mod, setup_mod);

    const unit_tests = b.addTest(.{
        .root_module = test_module,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    const run_jsontest = b.addRunArtifact(exe);
    run_jsontest.setCwd(b.path("."));
    run_jsontest.addArg("jsontest");
    if (b.option([]const u8, "jsontest-path", "EEST JSON file or directory")) |path| {
        run_jsontest.addArg(path);
    }
    const jsontest_step = b.step("jsontest", "Run execution-spec state tests");
    jsontest_step.dependOn(&run_jsontest.step);

    const run_chaintest = b.addRunArtifact(exe);
    run_chaintest.setCwd(b.path("."));
    run_chaintest.addArg("chaintest");
    if (b.option([]const u8, "chaintest-path", "EEST blockchain JSON file or directory")) |path| {
        run_chaintest.addArg(path);
    }
    const chaintest_step = b.step("chaintest", "Run execution-spec blockchain tests");
    chaintest_step.dependOn(&run_chaintest.step);
}

fn add_ckzg(
    b: *std.Build,
    mod: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    ckzg_c_mod: *std.Build.Module,
    setup_mod: *std.Build.Module,
) void {
    mod.addImport("ckzg_c", ckzg_c_mod);
    mod.addImport("kzg_trusted_setup_txt", setup_mod);
    mod.addIncludePath(b.path("vendor/c-kzg-4844/src"));
    mod.addIncludePath(b.path("vendor/blst/bindings"));
    const flags: []const []const u8 = &.{ "-O2", "-ffreestanding", "-D__BLST_PORTABLE__" };
    switch (target.result.cpu.arch) {
        .aarch64, .x86_64 => {
            mod.addCSourceFiles(.{
                .root = b.path("vendor/blst"),
                .files = &.{"src/server.c"},
                .flags = flags,
            });
            mod.addCSourceFiles(.{
                .root = b.path("vendor/c-kzg-4844"),
                .files = &.{"src/ckzg.c"},
                .flags = flags,
            });
            mod.addAssemblyFile(b.path("vendor/blst/build/assembly.S"));
        },
        else => {
            const no_asm: []const []const u8 = &.{
                "-O2", "-ffreestanding", "-D__BLST_PORTABLE__", "-D__BLST_NO_ASM__",
            };
            mod.addCSourceFiles(.{
                .root = b.path("vendor/blst"),
                .files = &.{"src/server.c"},
                .flags = no_asm,
            });
            mod.addCSourceFiles(.{
                .root = b.path("vendor/c-kzg-4844"),
                .files = &.{"src/ckzg.c"},
                .flags = no_asm,
            });
        },
    }
}
