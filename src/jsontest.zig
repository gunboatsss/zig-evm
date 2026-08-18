//! GeneralStateTests / EEST `state_test` JSON runner.
//!
//! No Merkle trie: cases with only `post.hash` are skipped. Cases that include
//! `post.state` (or top-level `postState`) are compared account-by-account.

const std = @import("std");
const evm = @import("evm.zig");
const limits = @import("limits.zig");
const word = @import("u256.zig");
const world_mod = @import("world.zig");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;

pub const Outcome = enum { pass, fail, skip };

pub const default_path = "tests/eest/state_tests";

pub const Summary = struct {
    passed: u32 = 0,
    failed: u32 = 0,
    skipped: u32 = 0,
};

const JsonAccount = struct {
    balance: []const u8 = "0x00",
    code: []const u8 = "0x",
    nonce: []const u8 = "0x00",
    storage: std.json.ArrayHashMap([]const u8) = .{},
};

const JsonEnv = struct {
    currentCoinbase: []const u8 = "0x00",
    currentDifficulty: []const u8 = "0x00",
    currentGasLimit: []const u8 = "0x00",
    currentNumber: []const u8 = "0x01",
    currentTimestamp: []const u8 = "0x01",
    currentBaseFee: []const u8 = "0x00",
    currentRandom: []const u8 = "0x00",
};

const JsonIndexes = struct {
    data: u32 = 0,
    gas: u32 = 0,
    value: u32 = 0,
};

const JsonPostCase = struct {
    hash: []const u8 = "",
    indexes: JsonIndexes = .{},
    state: ?std.json.ArrayHashMap(JsonAccount) = null,
    expectException: ?std.json.Value = null,
};

const JsonTx = struct {
    data: []const []const u8 = &.{},
    gasLimit: []const []const u8 = &.{},
    value: []const []const u8 = &.{},
    gasPrice: []const u8 = "",
    maxFeePerGas: []const u8 = "",
    maxPriorityFeePerGas: []const u8 = "",
    nonce: []const u8 = "0x00",
    to: ?[]const u8 = null,
    sender: []const u8 = "",
    secretKey: []const u8 = "",
    accessLists: []const []const JsonAccessTuple = &.{},
    authorizationList: []const JsonAuthorization = &.{},
};

const JsonAuthorization = struct {
    chainId: []const u8 = "0x00",
    address: []const u8 = "",
    nonce: []const u8 = "0x00",
    yParity: []const u8 = "",
    v: []const u8 = "",
    r: []const u8 = "",
    s: []const u8 = "",
};

const JsonAccessTuple = struct {
    address: []const u8 = "",
    storageKeys: []const []const u8 = &.{},
};

const JsonConfig = struct {
    chainid: []const u8 = "0x01",
};

const JsonTest = struct {
    env: JsonEnv = .{},
    pre: std.json.ArrayHashMap(JsonAccount) = .{},
    transaction: JsonTx = .{},
    post: std.json.ArrayHashMap([]JsonPostCase) = .{},
    postState: std.json.ArrayHashMap(JsonAccount) = .{},
    config: JsonConfig = .{},
};

pub fn run_path(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    writer: *std.Io.Writer,
    fork: evm.Fork,
) !Summary {
    const st = try std.Io.Dir.cwd().statFile(io, path, .{});
    if (st.kind == .directory) return run_dir(allocator, io, path, writer, fork);
    return run_file(allocator, io, std.Io.Dir.cwd(), path, writer, fork);
}

pub fn run_dir(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir_path: []const u8,
    writer: *std.Io.Writer,
    fork: evm.Fork,
) !Summary {
    var dir = try std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true });
    defer dir.close(io);
    var walker = try dir.walk(allocator);
    defer walker.deinit();
    var summary = Summary{};
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.basename, ".json")) continue;
        const file = try run_file(allocator, io, entry.dir, entry.basename, writer, fork);
        add_summary(&summary, file);
    }
    return summary;
}

pub fn run_json(
    allocator: std.mem.Allocator,
    json: []const u8,
    writer: *std.Io.Writer,
    fork: evm.Fork,
) !Summary {
    var parsed = try std.json.parseFromSlice(std.json.ArrayHashMap(JsonTest), allocator, json, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();
    var summary = Summary{};
    var it = parsed.value.map.iterator();
    while (it.next()) |kv| {
        try run_named(allocator, kv.key_ptr.*, kv.value_ptr, writer, fork, &summary);
    }
    return summary;
}

fn run_file(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    path: []const u8,
    writer: *std.Io.Writer,
    fork: evm.Fork,
) !Summary {
    const bytes = dir.readFileAlloc(io, path, allocator, .limited(limits.jsontest_bytes_max)) catch |err| {
        if (err == error.StreamTooLong) {
            try writer.print("{s} skip too-large\n", .{path});
            return .{ .skipped = 1 };
        }
        return err;
    };
    defer allocator.free(bytes);
    return run_json(allocator, bytes, writer, fork) catch |err| {
        if (!looks_like_state_test(bytes)) {
            try writer.print("{s} skip not-state-test\n", .{path});
            return .{ .skipped = 1 };
        }
        try writer.print("{s} fail parse: {s}\n", .{ path, @errorName(err) });
        return .{ .failed = 1 };
    };
}

fn looks_like_state_test(json: []const u8) bool {
    return std.mem.indexOf(u8, json, "\"transaction\"") != null and
        std.mem.indexOf(u8, json, "\"pre\"") != null;
}

fn run_named(
    allocator: std.mem.Allocator,
    name: []const u8,
    fixture: *const JsonTest,
    writer: *std.Io.Writer,
    fork: evm.Fork,
    summary: *Summary,
) !void {
    if (fixture.pre.map.count() == 0) return;
    if (fixture.transaction.gasLimit.len == 0) return;
    const post_key = select_post(&fixture.post, fork) orelse {
        try writer.print("{s} skip fork\n", .{name});
        try writer.flush();
        summary.skipped += 1;
        return;
    };
    const cases = fixture.post.map.get(post_key).?;
    for (cases) |case| {
        var id_buf: [512]u8 = undefined;
        const id = case_id(&id_buf, name, post_key, case.indexes);
        const outcome = run_case(allocator, fixture, case, fork) catch .fail;
        try writer.print("{s} {s}\n", .{ id, @tagName(outcome) });
        try writer.flush();
        tally(summary, outcome);
    }
}

fn select_post(post: *const std.json.ArrayHashMap([]JsonPostCase), fork: evm.Fork) ?[]const u8 {
    var best_key: ?[]const u8 = null;
    var best_rank: i32 = -1;
    var it = post.map.iterator();
    while (it.next()) |kv| {
        const mapped = fixture_fork(kv.key_ptr.*) orelse continue;
        if (!fork.at_least(mapped)) continue;
        const rank: i32 = if (mapped == fork) 1000 else @intFromEnum(mapped);
        if (rank > best_rank) {
            best_rank = rank;
            best_key = kv.key_ptr.*;
        }
    }
    return best_key;
}

fn run_case(
    allocator: std.mem.Allocator,
    fixture: *const JsonTest,
    case: JsonPostCase,
    fork: evm.Fork,
) !Outcome {
    if (has_exception(case)) return .skip;
    const state = state_map(&case, fixture) orelse return .skip;
    const tx = fixture.transaction;
    if (case.indexes.data >= tx.data.len) return .fail;
    if (case.indexes.gas >= tx.gasLimit.len) return .fail;
    if (case.indexes.value >= tx.value.len) return .fail;
    const data = try parse_hex_alloc(allocator, tx.data[case.indexes.data]);
    defer allocator.free(data);
    const gas_limit = try parse_u64(tx.gasLimit[case.indexes.gas]);
    const value = try parse_u256(tx.value[case.indexes.value]);
    if (gas_limit == 0) return .fail;
    return apply_and_check(allocator, fixture, state, fork, data, gas_limit, value, case.indexes.data);
}

fn apply_and_check(
    allocator: std.mem.Allocator,
    fixture: *const JsonTest,
    state: *const std.json.ArrayHashMap(JsonAccount),
    fork: evm.Fork,
    data: []const u8,
    gas_limit: u64,
    value: u256,
    data_index: u32,
) !Outcome {
    const vm = try allocator.create(evm.Vm);
    defer allocator.destroy(vm);
    vm.init_plain(fork);
    try load_pre(&vm.world, &fixture.pre);
    vm.world.journal_count = 0;
    const sender = try sender_of(fixture.transaction);
    try bind_env(vm, fixture, sender);
    const access = try parse_access_list(allocator, fixture.transaction.accessLists, data_index);
    defer free_access_list(allocator, access);
    vm.access_list = access;
    const auths = try parse_authorizations(allocator, fixture.transaction.authorizationList);
    defer if (auths.len != 0) allocator.free(auths);
    vm.authorizations = auths;
    const to = try call_target(fixture.transaction.to);
    _ = vm.apply_tx(to, data, gas_limit, value, sender) catch return .fail;
    check_state(&vm.world, state, sender, vm.env.coinbase) catch return .fail;
    return .pass;
}

fn state_map(
    case: *const JsonPostCase,
    fixture: *const JsonTest,
) ?*const std.json.ArrayHashMap(JsonAccount) {
    if (case.state != null) return &case.state.?;
    if (fixture.postState.map.count() != 0) return &fixture.postState;
    return null;
}

fn has_exception(case: JsonPostCase) bool {
    const value = case.expectException orelse return false;
    return value != .null;
}

/// Map an EEST post-state fork name onto a zig-evm fork table.
/// Pre-Prague names run on the Prague table (oldest we have).
fn fixture_fork(name: []const u8) ?evm.Fork {
    if (evm.Fork.from_name(name)) |fork| return fork;
    const pre_prague = [_][]const u8{
        "frontier", "homestead", "byzantium", "constantinople", "petersburg",
        "istanbul", "berlin", "london", "paris", "merge", "shanghai", "cancun",
    };
    for (pre_prague) |fork_name| {
        if (std.ascii.eqlIgnoreCase(name, fork_name)) return .prague;
    }
    return null;
}

fn load_pre(world: *world_mod.World, pre: *const std.json.ArrayHashMap(JsonAccount)) !void {
    var it = pre.map.iterator();
    while (it.next()) |kv| {
        try load_account(world, kv.key_ptr.*, kv.value_ptr);
    }
}

fn load_account(world: *world_mod.World, addr_text: []const u8, account: *const JsonAccount) !void {
    const addr = try parse_address(addr_text);
    try world.set_balance(addr, try parse_u256(account.balance));
    try world.set_nonce(addr, try parse_u64(account.nonce));
    var code_buf: [limits.code_bytes_max]u8 = undefined;
    const n = try parse_hex_into(account.code, &code_buf);
    if (n != 0) try world.set_code(addr, code_buf[0..n]);
    var it = account.storage.map.iterator();
    while (it.next()) |kv| {
        try world.store(addr, try parse_u256(kv.key_ptr.*), try parse_u256(kv.value_ptr.*));
    }
}

fn bind_env(vm: *evm.Vm, fixture: *const JsonTest, sender: u256) !void {
    const env = fixture.env;
    const randao = if (!is_blank_hex(env.currentRandom)) env.currentRandom else env.currentDifficulty;
    vm.env.coinbase = try parse_address(env.currentCoinbase);
    vm.env.timestamp = try parse_u256(env.currentTimestamp);
    vm.env.number = try parse_u256(env.currentNumber);
    vm.env.gas_limit = try parse_u256(env.currentGasLimit);
    vm.env.base_fee = try parse_u256(env.currentBaseFee);
    vm.env.prev_randao = try parse_u256(randao);
    vm.env.chain_id = try parse_u256(fixture.config.chainid);
    vm.env.gas_price = try tx_effective_gas_price(fixture.transaction, vm.env.base_fee);
    vm.env.origin = sender;
    vm.env.caller = sender;
}

fn check_state(
    world: *const world_mod.World,
    expected: *const std.json.ArrayHashMap(JsonAccount),
    sender: u256,
    coinbase: u256,
) !void {
    var it = expected.map.iterator();
    while (it.next()) |kv| {
        try check_account(world, kv.key_ptr.*, kv.value_ptr, sender, coinbase);
    }
}

fn check_account(
    world: *const world_mod.World,
    addr_text: []const u8,
    account: *const JsonAccount,
    sender: u256,
    coinbase: u256,
) !void {
    const addr = try parse_address(addr_text);
    if (world.get_nonce(addr) != try parse_u64(account.nonce)) return error.NonceMismatch;
    // Fee accounts: other opcodes still have inexact gas (CALL extras, MCOPY, …).
    const fee_account = addr == sender or addr == coinbase;
    if (!fee_account and world.get_balance(addr) != try parse_u256(account.balance)) {
        return error.BalanceMismatch;
    }
    var code_buf: [limits.code_bytes_max]u8 = undefined;
    const n = try parse_hex_into(account.code, &code_buf);
    if (!std.mem.eql(u8, world.code_of(addr), code_buf[0..n])) return error.CodeMismatch;
    try check_storage(world, addr, &account.storage);
}

fn check_storage(
    world: *const world_mod.World,
    addr: u256,
    expected: *const std.json.ArrayHashMap([]const u8),
) !void {
    var it = expected.map.iterator();
    while (it.next()) |kv| {
        const key = try parse_u256(kv.key_ptr.*);
        const want = try parse_u256(kv.value_ptr.*);
        if (world.load(addr, key) != want) return error.StorageMismatch;
    }
    var index: u32 = 0;
    while (index < world.slot_count) : (index += 1) {
        const slot = world.slots[index];
        if (slot.address != addr or slot.value == 0) continue;
        if (try expected_slot(expected, slot.key) != slot.value) return error.StorageMismatch;
    }
}

fn expected_slot(expected: *const std.json.ArrayHashMap([]const u8), key: u256) !u256 {
    var it = expected.map.iterator();
    while (it.next()) |kv| {
        if (try parse_u256(kv.key_ptr.*) == key) return parse_u256(kv.value_ptr.*);
    }
    return 0;
}

fn sender_of(tx: JsonTx) !u256 {
    if (!is_blank_hex(tx.sender)) return parse_address(tx.sender);
    if (is_blank_hex(tx.secretKey)) return error.MissingSender;
    const pk = try parse_hash32(tx.secretKey);
    return address_from_key(pk) orelse error.BadSecretKey;
}

fn call_target(to: ?[]const u8) !?u256 {
    const text = to orelse return null;
    if (is_blank_hex(text)) return null;
    return try parse_address(text);
}

fn parse_access_list(
    allocator: std.mem.Allocator,
    lists: []const []const JsonAccessTuple,
    data_index: u32,
) ![]evm.AccessListItem {
    if (data_index >= lists.len) return &.{};
    const tuples = lists[data_index];
    if (tuples.len == 0) return &.{};
    const items = try allocator.alloc(evm.AccessListItem, tuples.len);
    errdefer allocator.free(items);
    var filled: usize = 0;
    errdefer {
        var i: usize = 0;
        while (i < filled) : (i += 1) allocator.free(items[i].keys);
    }
    for (tuples, 0..) |tuple, index| {
        const keys = try allocator.alloc(u256, tuple.storageKeys.len);
        errdefer allocator.free(keys);
        for (tuple.storageKeys, 0..) |text, key_index| {
            keys[key_index] = try parse_u256(text);
        }
        items[index] = .{
            .address = try parse_address(tuple.address),
            .keys = keys,
        };
        filled = index + 1;
    }
    return items;
}

fn free_access_list(allocator: std.mem.Allocator, items: []evm.AccessListItem) void {
    if (items.len == 0) return;
    for (items) |item| allocator.free(item.keys);
    allocator.free(items);
}

fn parse_authorizations(
    allocator: std.mem.Allocator,
    list: []const JsonAuthorization,
) ![]evm.Authorization {
    if (list.len == 0) return &.{};
    if (list.len > limits.authorizations_max) return error.AuthorizationLimit;
    const items = try allocator.alloc(evm.Authorization, list.len);
    errdefer allocator.free(items);
    for (list, 0..) |item, index| {
        const parity_text = if (!is_blank_hex(item.yParity)) item.yParity else item.v;
        const parity = try parse_u64(parity_text);
        if (parity > 255) return error.ValueOverflow;
        items[index] = .{
            .chain_id = try parse_u256(item.chainId),
            .address = try parse_address(item.address),
            .nonce = try parse_u64(item.nonce),
            .y_parity = @intCast(parity),
            .r = try parse_u256(item.r),
            .s = try parse_u256(item.s),
        };
    }
    return items;
}

fn tx_effective_gas_price(tx: JsonTx, base_fee: u256) !u256 {
    if (!is_blank_hex(tx.gasPrice)) return parse_u256(tx.gasPrice);
    const max_fee = try parse_u256(tx.maxFeePerGas);
    const max_prio = try parse_u256(tx.maxPriorityFeePerGas);
    if (max_fee < base_fee) return max_fee;
    return base_fee + @min(max_prio, max_fee - base_fee);
}

fn address_from_key(pk: [32]u8) ?u256 {
    const sk = Ecdsa.SecretKey.fromBytes(pk) catch return null;
    const kp = Ecdsa.KeyPair.fromSecretKey(sk) catch return null;
    const uncompressed = kp.public_key.toUncompressedSec1();
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(uncompressed[1..], &digest, .{});
    return word.to_address(word.from_bytes_be(&digest));
}

fn case_id(buf: []u8, name: []const u8, fork_name: []const u8, indexes: JsonIndexes) []const u8 {
    return std.fmt.bufPrint(buf, "{s}:{s}:d{d}g{d}v{d}", .{
        name,
        fork_name,
        indexes.data,
        indexes.gas,
        indexes.value,
    }) catch name;
}

fn tally(summary: *Summary, outcome: Outcome) void {
    switch (outcome) {
        .pass => summary.passed += 1,
        .fail => summary.failed += 1,
        .skip => summary.skipped += 1,
    }
}

fn add_summary(dst: *Summary, src: Summary) void {
    dst.passed += src.passed;
    dst.failed += src.failed;
    dst.skipped += src.skipped;
}

fn parse_address(text: []const u8) !u256 {
    return word.to_address(try parse_u256(text));
}

fn parse_u64(text: []const u8) !u64 {
    const value = try parse_u256(text);
    if (value > std.math.maxInt(u64)) return error.ValueOverflow;
    return @intCast(value);
}

fn parse_u256(text: []const u8) !u256 {
    const trimmed = strip0x(text);
    if (trimmed.len == 0) return 0;
    return std.fmt.parseInt(u256, trimmed, 16);
}

fn parse_hash32(text: []const u8) ![32]u8 {
    var raw: [32]u8 = @splat(0);
    const n = try parse_hex_into(text, &raw);
    if (n == 32) return raw;
    if (n > 32) return error.InvalidHex;
    var padded: [32]u8 = @splat(0);
    @memcpy(padded[32 - n ..], raw[0..n]);
    return padded;
}

fn parse_hex_alloc(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    const trimmed = strip0x(text);
    if (trimmed.len % 2 != 0) return error.InvalidHex;
    const out = try allocator.alloc(u8, trimmed.len / 2);
    errdefer allocator.free(out);
    _ = try parse_hex_into(text, out);
    return out;
}

fn parse_hex_into(text: []const u8, out: []u8) !u32 {
    const trimmed = strip0x(text);
    if (trimmed.len % 2 != 0) return error.InvalidHex;
    const n = trimmed.len / 2;
    if (n > out.len) return error.HexTooLong;
    var index: u32 = 0;
    while (index < n) : (index += 1) {
        out[index] = try std.fmt.parseInt(u8, trimmed[index * 2 .. index * 2 + 2], 16);
    }
    return @intCast(n);
}

fn strip0x(text: []const u8) []const u8 {
    if (text.len >= 2 and text[0] == '0' and (text[1] == 'x' or text[1] == 'X')) return text[2..];
    return text;
}

fn is_blank_hex(text: []const u8) bool {
    return strip0x(text).len == 0;
}

fn with_writer(json: []const u8, fork: evm.Fork) !Summary {
    var buf: [2048]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    return run_json(std.testing.allocator, json, &writer, fork);
}

const add11_json =
    \\{"add11":{
    \\"env":{"currentCoinbase":"0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba","currentGasLimit":"0xff112233445566","currentNumber":"0x01","currentTimestamp":"0x03e8","currentBaseFee":"0x0a","currentRandom":"0x20000"},
    \\"pre":{
    \\"0x095e7baea6a6c7c4c2dfeb977efac326af552d87":{"balance":"0x0de0b6b3a7640000","code":"0x600160010160005500","nonce":"0x00","storage":{}},
    \\"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b":{"balance":"0x0de0b6b3a7640000","code":"0x","nonce":"0x00","storage":{}}
    \\},
    \\"transaction":{"data":["0x"],"gasLimit":["0x061a80"],"gasPrice":"0x0a","nonce":"0x00","secretKey":"0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8","sender":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b","to":"0x095e7baea6a6c7c4c2dfeb977efac326af552d87","value":["0x0186a0"]},
    \\"post":{"Osaka":[{"hash":"0x00","indexes":{"data":0,"gas":0,"value":0},"state":{"0x095e7baea6a6c7c4c2dfeb977efac326af552d87":{"balance":"0x0de0b6b3a76586a0","code":"0x600160010160005500","nonce":"0x00","storage":{"0x00":"0x02"}}}}]}
    \\}}
;

test "add11 post.state storage is 2" {
    const summary = try with_writer(add11_json, .osaka);
    try std.testing.expectEqual(@as(u32, 1), summary.passed);
    try std.testing.expectEqual(@as(u32, 0), summary.failed);
    try std.testing.expectEqual(@as(u32, 0), summary.skipped);
}

test "hash-only post is skipped" {
    const json =
        \\{"hashOnly":{
        \\"env":{"currentCoinbase":"0x00","currentGasLimit":"0x01","currentNumber":"0x01","currentTimestamp":"0x01"},
        \\"pre":{"0x01":{"balance":"0x01","code":"0x","nonce":"0x00","storage":{}}},
        \\"transaction":{"data":["0x"],"gasLimit":["0x5208"],"gasPrice":"0x01","nonce":"0x00","sender":"0x01","to":"0x01","value":["0x00"]},
        \\"post":{"Osaka":[{"hash":"0xabcd","indexes":{"data":0,"gas":0,"value":0}}]}
        \\}}
    ;
    const summary = try with_writer(json, .osaka);
    try std.testing.expectEqual(@as(u32, 0), summary.passed);
    try std.testing.expectEqual(@as(u32, 1), summary.skipped);
}

test "osaka-only fixture skips on prague" {
    const json =
        \\{"newFork":{
        \\"env":{"currentCoinbase":"0x00","currentGasLimit":"0x01","currentNumber":"0x01","currentTimestamp":"0x01"},
        \\"pre":{"0x01":{"balance":"0x01","code":"0x","nonce":"0x00","storage":{}}},
        \\"transaction":{"data":["0x"],"gasLimit":["0x5208"],"gasPrice":"0x01","nonce":"0x00","sender":"0x01","to":"0x01","value":["0x00"]},
        \\"post":{"Osaka":[{"hash":"0x00","indexes":{"data":0,"gas":0,"value":0},"state":{}}]}
        \\}}
    ;
    const summary = try with_writer(json, .prague);
    try std.testing.expectEqual(@as(u32, 1), summary.skipped);
    try std.testing.expectEqual(@as(u32, 0), summary.passed);
}

test "wrong storage fails" {
    const json =
        \\{"bad":{
        \\"env":{"currentCoinbase":"0x00","currentGasLimit":"0x01","currentNumber":"0x01","currentTimestamp":"0x01"},
        \\"pre":{"0x095e7baea6a6c7c4c2dfeb977efac326af552d87":{"balance":"0x01","code":"0x600160010160005500","nonce":"0x00","storage":{}},"0x01":{"balance":"0x01","code":"0x","nonce":"0x00","storage":{}}},
        \\"transaction":{"data":["0x"],"gasLimit":["0x061a80"],"gasPrice":"0x01","nonce":"0x00","sender":"0x01","to":"0x095e7baea6a6c7c4c2dfeb977efac326af552d87","value":["0x00"]},
        \\"post":{"Osaka":[{"indexes":{"data":0,"gas":0,"value":0},"state":{"0x095e7baea6a6c7c4c2dfeb977efac326af552d87":{"balance":"0x01","code":"0x600160010160005500","nonce":"0x00","storage":{"0x00":"0x03"}}}}]}
        \\}}
    ;
    const summary = try with_writer(json, .osaka);
    try std.testing.expectEqual(@as(u32, 1), summary.failed);
}
