const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "zig-evm",
        .root_module = root_module,
    });
    b.installArtifact(exe);

    const test_module = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

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
}
