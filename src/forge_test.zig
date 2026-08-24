//! Run Foundry `test*` functions from `forge build` artifacts.
//! Cheatcodes at the hevm address are supported. No fuzz or invariants.

const std = @import("std");
const artifact = @import("artifact.zig");
const evm = @import("evm.zig");
const limits = @import("limits.zig");

pub const default_sender: u256 = 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38;
pub const default_balance: u256 = @as(u256, 1) << 96;
pub const tx_gas: u64 = 30_000_000;

pub const Kind = enum { unit, test_fail, fuzz };

pub const Case = struct {
    name: []const u8,
    selector: [4]u8,
    kind: Kind,
};

pub const Suite = struct {
    bytecode: []const u8,
    setup: ?[4]u8,
    failed: ?[4]u8,
    cases: []Case,

    pub fn deinit(self: Suite, allocator: std.mem.Allocator) void {
        allocator.free(self.bytecode);
        for (self.cases) |case| allocator.free(case.name);
        allocator.free(self.cases);
    }
};

pub const Outcome = enum { pass, fail, skip };

pub const Summary = struct {
    passed: u32 = 0,
    failed: u32 = 0,
    skipped: u32 = 0,
};

const AbiInput = struct {
    type: []const u8 = "",
    name: []const u8 = "",
};

const AbiFn = struct {
    type: []const u8 = "",
    name: []const u8 = "",
    inputs: []const AbiInput = &.{},
};

const JsonBytecode = struct {
    object: []const u8 = "",
};

const JsonArtifact = struct {
    abi: []const AbiFn = &.{},
    bytecode: JsonBytecode = .{},
};

pub fn selector_of(signature: []const u8) [4]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(signature, &hash, .{});
    return hash[0..4].*;
}

pub fn parse_artifact(allocator: std.mem.Allocator, json: []const u8) !?Suite {
    var parsed = try std.json.parseFromSlice(JsonArtifact, allocator, json, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();
    const object = parsed.value.bytecode.object;
    if (object.len == 0 or std.mem.eql(u8, object, "0x") or std.mem.eql(u8, object, "0X")) {
        return null;
    }
    if (std.mem.indexOf(u8, object, "__") != null) return null;
    if (!has_is_test(parsed.value.abi)) return null;
    const bytecode = try parse_hex(allocator, object);
    errdefer allocator.free(bytecode);
    return try collect_suite(allocator, parsed.value.abi, bytecode);
}

fn has_is_test(abi: []const AbiFn) bool {
    for (abi) |item| {
        if (std.mem.eql(u8, item.type, "function") and
            std.mem.eql(u8, item.name, "IS_TEST") and
            item.inputs.len == 0) return true;
    }
    return false;
}

fn collect_suite(allocator: std.mem.Allocator, abi: []const AbiFn, bytecode: []const u8) !Suite {
    var cases: std.ArrayList(Case) = .empty;
    errdefer {
        for (cases.items) |case| allocator.free(case.name);
        cases.deinit(allocator);
    }
    var setup: ?[4]u8 = null;
    var failed: ?[4]u8 = null;
    for (abi) |item| {
        if (!std.mem.eql(u8, item.type, "function")) continue;
        const sel = selector_for(item.name, item.inputs);
        if (std.mem.eql(u8, item.name, "setUp") and item.inputs.len == 0) {
            setup = sel;
            continue;
        }
        if (std.mem.eql(u8, item.name, "failed") and item.inputs.len == 0) {
            failed = sel;
            continue;
        }
        try maybe_append_case(allocator, &cases, item, sel);
    }
    return .{
        .bytecode = bytecode,
        .setup = setup,
        .failed = failed,
        .cases = try cases.toOwnedSlice(allocator),
    };
}

fn maybe_append_case(
    allocator: std.mem.Allocator,
    cases: *std.ArrayList(Case),
    item: AbiFn,
    sel: [4]u8,
) !void {
    if (!std.mem.startsWith(u8, item.name, "test")) return;
    const kind: Kind = if (item.inputs.len != 0)
        .fuzz
    else if (std.mem.startsWith(u8, item.name, "testFail"))
        .test_fail
    else
        .unit;
    const name = try allocator.dupe(u8, item.name);
    errdefer allocator.free(name);
    try cases.append(allocator, .{ .name = name, .selector = sel, .kind = kind });
}

fn selector_for(name: []const u8, inputs: []const AbiInput) [4]u8 {
    var buf: [limits.forge_sig_bytes_max]u8 = undefined;
    var n: u32 = 0;
    std.debug.assert(name.len + 2 <= buf.len);
    @memcpy(buf[0..name.len], name);
    n = @intCast(name.len);
    buf[n] = '(';
    n += 1;
    for (inputs, 0..) |input, i| {
        if (i != 0) {
            buf[n] = ',';
            n += 1;
        }
        std.debug.assert(n + input.type.len < buf.len);
        @memcpy(buf[n .. n + input.type.len], input.type);
        n += @intCast(input.type.len);
    }
    buf[n] = ')';
    n += 1;
    return selector_of(buf[0..n]);
}

pub fn run_case(
    allocator: std.mem.Allocator,
    bytecode: []const u8,
    case: Case,
    setup: ?[4]u8,
    failed: ?[4]u8,
    fork: evm.Fork,
    artifacts: ?*const artifact.Store,
) !Outcome {
    if (case.kind == .fuzz) return .skip;
    const vm = try allocator.create(evm.Vm);
    defer allocator.destroy(vm);
    vm.init_session(fork) catch return .fail;
    vm.cheats.artifacts = artifacts;
    try vm.world.set_balance(default_sender, default_balance);
    var ctx = evm.ExecutionContext.default();
    ctx.caller = default_sender;
    ctx.origin = default_sender;
    const addr = try vm.apply_create(bytecode, tx_gas, 0, ctx);
    if (addr == 0) return .fail;
    if (setup) |sel| {
        const status = vm.apply_call(addr, &sel, tx_gas, ctx) catch return .fail;
        if (!succeeded(status)) return .fail;
    }
    const status = vm.apply_call(addr, &case.selector, tx_gas, ctx) catch return .fail;
    return finish_case(vm, addr, ctx, case, failed, status);
}

fn finish_case(
    vm: *evm.Vm,
    addr: u256,
    ctx: evm.ExecutionContext,
    case: Case,
    failed: ?[4]u8,
    status: evm.Status,
) !Outcome {
    if (vm.cheats.skipped) return .skip;
    const ok = succeeded(status);
    if (case.kind == .test_fail) return if (ok) .fail else .pass;
    if (!ok) return .fail;
    const sel = failed orelse return .pass;
    const failed_status = vm.apply_call(addr, &sel, tx_gas, ctx) catch return .fail;
    if (!succeeded(failed_status)) return .fail;
    if (is_nonzero(vm.output_buffer[0..vm.output_len])) return .fail;
    return .pass;
}

fn succeeded(status: evm.Status) bool {
    return status == .returned or status == .stopped;
}

fn is_nonzero(data: []const u8) bool {
    for (data) |byte| {
        if (byte != 0) return true;
    }
    return false;
}

pub const MatchedTest = struct {
    suite: Suite,
    case_index: u32,
    contract: []u8,
    allocator: std.mem.Allocator,

    pub fn case(self: *const MatchedTest) Case {
        return self.suite.cases[self.case_index];
    }

    pub fn deinit(self: *MatchedTest) void {
        self.allocator.free(self.contract);
        self.suite.deinit(self.allocator);
    }
};

/// Unique `test*` function whose name contains `test_filter`.
/// `contract_filter` empty matches any artifact basename.
pub fn match_test(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir_path: []const u8,
    test_filter: []const u8,
    contract_filter: []const u8,
) !MatchedTest {
    std.debug.assert(test_filter.len > 0);
    var dir = try std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true });
    defer dir.close(io);
    var walker = try dir.walk(allocator);
    defer walker.deinit();
    var found: ?MatchedTest = null;
    errdefer if (found) |*m| m.deinit();
    var match_count: u32 = 0;
    while (try walker.next(io)) |entry| {
        if (!artifact.is_artifact_file(entry)) continue;
        const bytes = try entry.dir.readFileAlloc(
            io,
            entry.basename,
            allocator,
            .limited(limits.forge_artifact_bytes_max),
        );
        defer allocator.free(bytes);
        const suite = (try parse_artifact(allocator, bytes)) orelse continue;
        const contract = strip_json_suffix(entry.basename);
        if (contract_filter.len != 0 and std.mem.indexOf(u8, contract, contract_filter) == null) {
            suite.deinit(allocator);
            continue;
        }
        var local: u32 = 0;
        var local_index: u32 = 0;
        for (suite.cases, 0..) |case, i| {
            if (std.mem.indexOf(u8, case.name, test_filter) == null) continue;
            local += 1;
            local_index = @intCast(i);
        }
        if (local == 0) {
            suite.deinit(allocator);
            continue;
        }
        match_count += local;
        if (match_count > 1) {
            suite.deinit(allocator);
            return error.AmbiguousTest;
        }
        const name = allocator.dupe(u8, contract) catch |err| {
            suite.deinit(allocator);
            return err;
        };
        found = .{
            .suite = suite,
            .case_index = local_index,
            .contract = name,
            .allocator = allocator,
        };
    }
    var matched = found orelse return error.NoMatchingTest;
    found = null;
    errdefer matched.deinit();
    if (matched.case().kind == .fuzz) return error.FuzzTest;
    return matched;
}

pub fn run_dir(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir_path: []const u8,
    writer: *std.Io.Writer,
    fork: evm.Fork,
) !Summary {
    const store = try allocator.create(artifact.Store);
    defer allocator.destroy(store);
    store.init();
    try store.load(allocator, io, dir_path);
    var dir = try std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true });
    defer dir.close(io);
    var walker = try dir.walk(allocator);
    defer walker.deinit();
    var summary = Summary{};
    while (try walker.next(io)) |entry| {
        if (!artifact.is_artifact_file(entry)) continue;
        try run_artifact_file(allocator, io, entry, writer, fork, store, &summary);
    }
    return summary;
}

fn run_artifact_file(
    allocator: std.mem.Allocator,
    io: std.Io,
    entry: std.Io.Dir.Walker.Entry,
    writer: *std.Io.Writer,
    fork: evm.Fork,
    artifacts: *const artifact.Store,
    summary: *Summary,
) !void {
    const bytes = try entry.dir.readFileAlloc(
        io,
        entry.basename,
        allocator,
        .limited(limits.forge_artifact_bytes_max),
    );
    defer allocator.free(bytes);
    const suite = (try parse_artifact(allocator, bytes)) orelse return;
    defer suite.deinit(allocator);
    const contract = strip_json_suffix(entry.basename);
    for (suite.cases) |case| {
        const outcome = try run_case(
            allocator,
            suite.bytecode,
            case,
            suite.setup,
            suite.failed,
            fork,
            artifacts,
        );
        try writer.print("{s}:{s} {s}\n", .{ contract, case.name, @tagName(outcome) });
        try writer.flush();
        tally(summary, outcome);
    }
}

fn strip_json_suffix(name: []const u8) []const u8 {
    if (std.mem.endsWith(u8, name, ".json")) return name[0 .. name.len - 5];
    return name;
}

fn tally(summary: *Summary, outcome: Outcome) void {
    switch (outcome) {
        .pass => summary.passed += 1,
        .fail => summary.failed += 1,
        .skip => summary.skipped += 1,
    }
}

fn parse_hex(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    var trimmed = text;
    if (std.mem.startsWith(u8, trimmed, "0x") or std.mem.startsWith(u8, trimmed, "0X")) {
        trimmed = trimmed[2..];
    }
    if (trimmed.len % 2 != 0) return error.InvalidHex;
    const out = try allocator.alloc(u8, trimmed.len / 2);
    var index: u32 = 0;
    while (index < out.len) : (index += 1) {
        out[index] = try std.fmt.parseInt(u8, trimmed[index * 2 .. index * 2 + 2], 16);
    }
    return out;
}

pub fn wrap_runtime(runtime: []const u8, out: []u8) []const u8 {
    std.debug.assert(runtime.len <= 255);
    std.debug.assert(out.len >= 12 + runtime.len);
    const off: u8 = 12;
    const len: u8 = @intCast(runtime.len);
    const prelude = [_]u8{ 0x60, len, 0x60, off, 0x60, 0x00, 0x39, 0x60, len, 0x60, 0x00, 0xf3 };
    @memcpy(out[0..12], &prelude);
    @memcpy(out[12 .. 12 + runtime.len], runtime);
    return out[0 .. 12 + runtime.len];
}

test "parse IS_TEST artifact" {
    const json =
        \\{"abi":[
        \\{"type":"function","name":"IS_TEST","inputs":[]},
        \\{"type":"function","name":"setUp","inputs":[]},
        \\{"type":"function","name":"testFoo","inputs":[]},
        \\{"type":"function","name":"testFailBoom","inputs":[]},
        \\{"type":"function","name":"testFuzz","inputs":[{"type":"uint256","name":"x"}]},
        \\{"type":"function","name":"failed","inputs":[]}
        \\],"bytecode":{"object":"0x6000"}}
    ;
    const suite = (try parse_artifact(std.testing.allocator, json)).?;
    defer suite.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), suite.bytecode.len);
    try std.testing.expect(suite.setup != null);
    try std.testing.expect(suite.failed != null);
    try std.testing.expectEqual(@as(usize, 3), suite.cases.len);
    try std.testing.expectEqual(Kind.unit, suite.cases[0].kind);
    try std.testing.expectEqual(Kind.test_fail, suite.cases[1].kind);
    try std.testing.expectEqual(Kind.fuzz, suite.cases[2].kind);
}

test "run passing STOP test" {
    const runtime = [_]u8{0x00};
    var buf: [16]u8 = undefined;
    const init_code = wrap_runtime(&runtime, &buf);
    const case = Case{ .name = "testOk", .selector = selector_of("testOk()"), .kind = .unit };
    const outcome = try run_case(std.testing.allocator, init_code, case, null, null, .osaka, null);
    try std.testing.expectEqual(Outcome.pass, outcome);
}

test "run reverting test fails" {
    const runtime = [_]u8{ 0x60, 0x00, 0x60, 0x00, 0xfd };
    var buf: [20]u8 = undefined;
    const init_code = wrap_runtime(&runtime, &buf);
    const case = Case{ .name = "testOk", .selector = selector_of("testOk()"), .kind = .unit };
    const outcome = try run_case(std.testing.allocator, init_code, case, null, null, .osaka, null);
    try std.testing.expectEqual(Outcome.fail, outcome);
}

test "forge-test breakpoint is not a pass" {
    const runtime = [_]u8{0xcc};
    var buf: [16]u8 = undefined;
    const init_code = wrap_runtime(&runtime, &buf);
    const case = Case{ .name = "testBreak", .selector = selector_of("testBreak()"), .kind = .unit };
    const halted = try run_case(std.testing.allocator, init_code, case, null, null, .osaka_breakpoint, null);
    try std.testing.expectEqual(Outcome.fail, halted);
    const invalid = try run_case(std.testing.allocator, init_code, case, null, null, .osaka, null);
    try std.testing.expectEqual(Outcome.fail, invalid);
}

test "testFail passes on revert" {
    const runtime = [_]u8{ 0x60, 0x00, 0x60, 0x00, 0xfd };
    var buf: [20]u8 = undefined;
    const init_code = wrap_runtime(&runtime, &buf);
    const case = Case{ .name = "testFailBoom", .selector = selector_of("testFailBoom()"), .kind = .test_fail };
    const outcome = try run_case(std.testing.allocator, init_code, case, null, null, .osaka, null);
    try std.testing.expectEqual(Outcome.pass, outcome);
}

test "failed flag fails the test" {
    const runtime = [_]u8{ 0x60, 0x01, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3 };
    var buf: [24]u8 = undefined;
    const init_code = wrap_runtime(&runtime, &buf);
    const case = Case{ .name = "testOk", .selector = selector_of("testOk()"), .kind = .unit };
    const outcome = try run_case(
        std.testing.allocator,
        init_code,
        case,
        null,
        selector_of("failed()"),
        .osaka,
        null,
    );
    try std.testing.expectEqual(Outcome.fail, outcome);
}

test "fuzz cases are skipped" {
    const case = Case{ .name = "testFuzz", .selector = selector_of("testFuzz(uint256)"), .kind = .fuzz };
    const outcome = try run_case(std.testing.allocator, &[_]u8{0x00}, case, null, null, .osaka, null);
    try std.testing.expectEqual(Outcome.skip, outcome);
}
