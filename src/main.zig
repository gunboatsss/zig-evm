const std = @import("std");
const evm = @import("evm.zig");
const debug = @import("debug.zig");
const forge_test = @import("forge_test.zig");
const jsontest = @import("jsontest.zig");
const chaintest = @import("chaintest.zig");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buffer);
    const stdout = &stdout_writer.interface;

    var stderr_buffer: [4096]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writer(io, &stderr_buffer);
    const stderr = &stderr_writer.interface;

    if (args.len < 2) {
        try print_usage(stderr, args[0]);
        try stderr.flush();
        return;
    }

    if (std.mem.eql(u8, args[1], "run")) {
        try run_command(stdout, arena, args[2..]);
        try stdout.flush();
        return;
    }

    if (std.mem.eql(u8, args[1], "forge-test")) {
        var heap: std.heap.DebugAllocator(.{}) = .init;
        defer _ = heap.deinit();
        try forge_test_command(stdout, heap.allocator(), init.io, args[2..]);
        try stdout.flush();
        return;
    }

    if (std.mem.eql(u8, args[1], "jsontest")) {
        // Arena `destroy` is a no-op; each case heap-allocates a ~100MB Vm.
        var heap: std.heap.DebugAllocator(.{}) = .init;
        defer _ = heap.deinit();
        const result = jsontest_command(stdout, heap.allocator(), init.io, args[2..]);
        try stdout.flush();
        return result;
    }

    if (std.mem.eql(u8, args[1], "chaintest")) {
        var heap: std.heap.DebugAllocator(.{}) = .init;
        defer _ = heap.deinit();
        const result = chaintest_command(stdout, heap.allocator(), init.io, args[2..]);
        try stdout.flush();
        return result;
    }

    if (std.mem.eql(u8, args[1], "debug")) {
        var heap: std.heap.DebugAllocator(.{}) = .init;
        defer _ = heap.deinit();
        try debug_command(stdout, heap.allocator(), init.io, args[2..]);
        try stdout.flush();
        return;
    }

    if (std.mem.eql(u8, args[1], "test-bytecode")) {
        try test_bytecode_command(stdout, arena);
        try stdout.flush();
        return;
    }

    try print_usage(stderr, args[0]);
    try stderr.flush();
}

fn print_usage(writer: *std.Io.Writer, program: []const u8) !void {
    try writer.print(
        \\Usage:
        \\  {s} run [--fork prague|osaka|amsterdam|prague_breakpoint|osaka_breakpoint|amsterdam_breakpoint] <hex-bytecode> [hex-calldata]
        \\  {s} debug [--fork prague|osaka|amsterdam|prague_breakpoint|osaka_breakpoint|amsterdam_breakpoint] [--gas N] <hex-bytecode> [hex-calldata] <cmd> [k=v...]
        \\  {s} debug [--fork prague|osaka|amsterdam|prague_breakpoint|osaka_breakpoint|amsterdam_breakpoint] --match-test <name> [--match-contract <name>] [out-dir] <cmd> [k=v...]
        \\  {s} forge-test [--fork prague|osaka|amsterdam|osaka_breakpoint] [out-dir]
        \\  {s} jsontest [--fork prague|osaka|amsterdam] [file-or-dir]
        \\  {s} chaintest [--fork prague|osaka|amsterdam] [file-or-dir]
        \\  {s} test-bytecode
        \\
        \\Default fork is osaka. `run` is a plain EVM (no hevm cheatcodes).
        \\`debug` prints JSON for LLM traces: overview, state, step, pc, opcode,
        \\call-tree, storage-diff, explain, trace, diff.
        \\`0xcc` is BREAKPOINT only on `prague_breakpoint` / `osaka_breakpoint` /
        \\`amsterdam_breakpoint`. Prague, Osaka, and Amsterdam treat it as invalid.
        \\`--match-test` loads a `forge-test` artifact and traces setUp plus the
        \\test call with hevm cheatcodes (constructor is omitted). Default dir is `out`.
        \\`forge-test` enables Foundry cheatcodes at 0x7109… and runs `test*`
        \\functions from `forge build` artifacts (no fuzz or invariants).
        \\`jsontest` runs EEST / GeneralStateTests JSON from
        \\`tests/eest/state_tests` (fetch with scripts/fetch_eest_fixtures.sh).
        \\A 32-byte post.hash is the Merkle Patricia state root. EIP-6780 is
        \\included (Osaka SELFDESTRUCT); pre-Cancun posts for it are skipped.
        \\`chaintest` runs EEST blockchain_tests (valid blocks: skip exceptions,
        \\uncles, withdrawals). Fetch with
        \\scripts/fetch_eest_fixtures.sh --blockchain.
        \\
        \\Examples:
        \\  {s} run 0x60011e00
        \\  {s} debug 0x600160020100 overview
        \\  {s} debug 0x600160020100 state step=3
        \\  {s} debug --fork osaka_breakpoint 0x6001cc opcode opcode=BREAKPOINT
        \\  {s} debug --fork osaka_breakpoint --match-test testFoo overview
        \\  {s} forge-test out
        \\  {s} jsontest
        \\  {s} chaintest
        \\
    , .{
        program, program, program, program, program, program, program,
        program, program, program, program, program, program, program,
        program,
    });
}

fn run_command(writer: *std.Io.Writer, allocator: std.mem.Allocator, args: []const [:0]const u8) !void {
    var rest = args;
    var fork: evm.Fork = .osaka;
    if (rest.len >= 2 and std.mem.eql(u8, rest[0], "--fork")) {
        fork = evm.Fork.from_name(rest[1]) orelse return error.UnknownFork;
        rest = rest[2..];
    }
    if (rest.len == 0) return error.MissingBytecode;
    const code = try parse_hex(rest[0], allocator);
    const calldata = if (rest.len >= 2) try parse_hex(rest[1], allocator) else &[_]u8{};

    var context = evm.ExecutionContext.default();
    context.address = 0xdeadbeef;

    const result = try evm.execute_with_fork(allocator, code, calldata, 1_000_000, context, fork);
    try writer.print("fork: {s}\n", .{fork.name()});
    try writer.print("status: {s}\n", .{@tagName(result.status)});
    try writer.print("gas_used: {d}\n", .{result.gas_used});
    try writer.print("return_data: 0x", .{});
    for (result.return_data()) |byte| try writer.print("{x:0>2}", .{byte});
    try writer.print("\n", .{});
}

fn debug_command(writer: *std.Io.Writer, allocator: std.mem.Allocator, io: std.Io, args: []const [:0]const u8) !void {
    var rest = args;
    var fork: evm.Fork = .osaka;
    var gas_limit: u64 = 1_000_000;
    var match_test: ?[]const u8 = null;
    var match_contract: []const u8 = "";
    while (rest.len >= 2) {
        if (std.mem.eql(u8, rest[0], "--fork")) {
            fork = evm.Fork.from_name(rest[1]) orelse return error.UnknownFork;
            rest = rest[2..];
            continue;
        }
        if (std.mem.eql(u8, rest[0], "--gas")) {
            gas_limit = try std.fmt.parseInt(u64, rest[1], 10);
            rest = rest[2..];
            continue;
        }
        if (std.mem.eql(u8, rest[0], "--match-test")) {
            match_test = rest[1];
            rest = rest[2..];
            continue;
        }
        if (std.mem.eql(u8, rest[0], "--match-contract")) {
            match_contract = rest[1];
            rest = rest[2..];
            continue;
        }
        break;
    }
    if (match_test) |filter| {
        try debug_forge(writer, allocator, io, rest, fork, filter, match_contract);
        return;
    }
    if (rest.len < 2) return error.MissingDebugArgs;
    const code = try parse_hex(rest[0], allocator);
    defer allocator.free(code);
    rest = rest[1..];
    var calldata: []const u8 = &.{};
    var calldata_owned = false;
    if (looks_like_hex(rest[0])) {
        calldata = try parse_hex(rest[0], allocator);
        calldata_owned = true;
        rest = rest[1..];
    }
    defer if (calldata_owned) allocator.free(calldata);
    if (rest.len == 0) return error.MissingDebugCommand;
    const command = rest[0];
    const params = try debug.parse_params(rest[1..]);
    try debug.run_query(allocator, code, calldata, gas_limit, fork, command, params, writer);
    try writer.writeByte('\n');
}

fn debug_forge(
    writer: *std.Io.Writer,
    allocator: std.mem.Allocator,
    io: std.Io,
    args: []const [:0]const u8,
    fork: evm.Fork,
    test_filter: []const u8,
    contract_filter: []const u8,
) !void {
    var rest = args;
    var dir: []const u8 = "out";
    if (rest.len == 0) return error.MissingDebugCommand;
    if (!debug.is_command(rest[0]) and std.mem.indexOfScalar(u8, rest[0], '=') == null) {
        dir = rest[0];
        rest = rest[1..];
    }
    if (rest.len == 0) return error.MissingDebugCommand;
    const command = rest[0];
    const params = try debug.parse_params(rest[1..]);
    try debug.run_query_forge(allocator, io, dir, test_filter, contract_filter, fork, command, params, writer);
    try writer.writeByte('\n');
}

fn looks_like_hex(text: []const u8) bool {
    return std.mem.startsWith(u8, text, "0x") or std.mem.startsWith(u8, text, "0X");
}

fn forge_test_command(
    writer: *std.Io.Writer,
    allocator: std.mem.Allocator,
    io: std.Io,
    args: []const [:0]const u8,
) !void {
    var rest = args;
    var fork: evm.Fork = .osaka;
    if (rest.len >= 2 and std.mem.eql(u8, rest[0], "--fork")) {
        fork = evm.Fork.from_name(rest[1]) orelse return error.UnknownFork;
        rest = rest[2..];
    }
    const path = if (rest.len >= 1) rest[0] else "out";
    const summary = try forge_test.run_dir(allocator, io, path, writer, fork);
    try writer.print("{d} passed, {d} failed, {d} skipped\n", .{
        summary.passed,
        summary.failed,
        summary.skipped,
    });
    try writer.flush();
    if (summary.failed != 0) return error.ForgeTestsFailed;
}

fn jsontest_command(
    writer: *std.Io.Writer,
    allocator: std.mem.Allocator,
    io: std.Io,
    args: []const [:0]const u8,
) !void {
    var rest = args;
    var fork: evm.Fork = .osaka;
    if (rest.len >= 2 and std.mem.eql(u8, rest[0], "--fork")) {
        fork = evm.Fork.from_name(rest[1]) orelse return error.UnknownFork;
        rest = rest[2..];
    }
    const path = if (rest.len >= 1) rest[0] else jsontest.default_path;
    const summary = jsontest.run_path(allocator, io, path, writer, fork) catch |err| {
        if (rest.len == 0) {
            try writer.print(
                "missing {s}; run scripts/fetch_eest_fixtures.sh\n",
                .{path},
            );
        }
        return err;
    };
    try writer.print("{d} passed, {d} failed, {d} skipped\n", .{
        summary.passed,
        summary.failed,
        summary.skipped,
    });
    if (summary.failed != 0) return error.JsonTestsFailed;
}

fn chaintest_command(
    writer: *std.Io.Writer,
    allocator: std.mem.Allocator,
    io: std.Io,
    args: []const [:0]const u8,
) !void {
    var rest = args;
    var fork: evm.Fork = .osaka;
    if (rest.len >= 2 and std.mem.eql(u8, rest[0], "--fork")) {
        fork = evm.Fork.from_name(rest[1]) orelse return error.UnknownFork;
        rest = rest[2..];
    }
    const path = if (rest.len >= 1) rest[0] else chaintest.default_path;
    const summary = chaintest.run_path(allocator, io, path, writer, fork) catch |err| {
        if (rest.len == 0) {
            try writer.print(
                "missing {s}; run scripts/fetch_eest_fixtures.sh --blockchain\n",
                .{path},
            );
        }
        return err;
    };
    try writer.print("{d} passed, {d} failed, {d} skipped\n", .{
        summary.passed,
        summary.failed,
        summary.skipped,
    });
    if (summary.failed != 0) return error.ChainTestsFailed;
}

fn test_bytecode_command(writer: *std.Io.Writer, allocator: std.mem.Allocator) !void {
    const code = [_]u8{
        0x60, 0x2a, // PUSH1 42
        0x60, 0x00, // PUSH1 0
        0x52, // MSTORE
        0x60, 0x20, // PUSH1 32
        0x60, 0x00, // PUSH1 0
        0xf3, // RETURN
    };
    const result = try evm.execute(allocator, &code, &[_]u8{}, 1_000_000, evm.ExecutionContext.default());
    try writer.print("embedded test status: {s}\n", .{@tagName(result.status)});
    try writer.print("return len: {d}\n", .{result.return_data().len});
}

fn parse_hex(text: []const u8, allocator: std.mem.Allocator) ![]u8 {
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
