//! Foundry hevm cheatcodes at `address(uint160(uint256(keccak256("hevm cheat code"))))`.

const std = @import("std");
const limits = @import("limits.zig");
const precompile = @import("precompile.zig");
const state_mod = @import("state.zig");
const word = @import("u256.zig");
const world_mod = @import("world.zig");

pub const address: u256 = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;
pub const dummy_code = [_]u8{0x00};

const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;

pub fn is_cheatcode(who: u256) bool {
    return who == address;
}

pub const Result = struct {
    len: u32,
    revert: bool,
    restore_logs: bool = false,
    log_count: u32 = 0,
    log_data_used: u32 = 0,
};

pub const Prank = struct {
    active: bool = false,
    persistent: bool = false,
    depth: u32 = 0,
    sender: u256 = 0,
    origin: u256 = 0,
    has_origin: bool = false,
};

pub const ExpectKind = enum { none, any, selector, exact };

pub const ExpectRevert = struct {
    kind: ExpectKind = .none,
    selector: [4]u8 = @splat(0),
    data: [limits.cheat_expect_bytes_max]u8 = undefined,
    data_len: u32 = 0,
};

pub const Mock = struct {
    target: u256,
    value: u256,
    check_value: bool,
    data_off: u32,
    data_len: u32,
    ret_off: u32,
    ret_len: u32,
};

pub const Snapshot = struct {
    journal_mark: u32,
    log_count: u32,
    log_data_used: u32,
    env: state_mod.ExecutionContext,
    prank: Prank,
};

pub const State = struct {
    prank: Prank = .{},
    expect: ExpectRevert = .{},
    mocks: [limits.cheat_mocks_max]Mock = undefined,
    mock_count: u32 = 0,
    mock_data: [limits.cheat_mock_data_bytes_max]u8 = undefined,
    mock_data_used: u32 = 0,
    snapshots: [limits.cheat_snapshots_max]Snapshot = undefined,
    snapshot_count: u32 = 0,
    skipped: bool = false,
};

pub fn apply(
    cheats: *State,
    world: *world_mod.World,
    env: *state_mod.ExecutionContext,
    parent_depth: u32,
    calldata: []const u8,
    out: []u8,
    log_count: u32,
    log_data_used: u32,
) Result {
    if (calldata.len < 4) return revert_empty();
    if (is(calldata, "warp(uint256)")) return set_u256(&env.timestamp, calldata, 0);
    if (is(calldata, "roll(uint256)")) return set_u256(&env.number, calldata, 0);
    if (is(calldata, "fee(uint256)")) return set_u256(&env.base_fee, calldata, 0);
    if (is(calldata, "chainId(uint256)")) return set_u256(&env.chain_id, calldata, 0);
    if (is(calldata, "txGasPrice(uint256)")) return set_u256(&env.gas_price, calldata, 0);
    if (is(calldata, "difficulty(uint256)")) return set_u256(&env.prev_randao, calldata, 0);
    if (is(calldata, "prevrandao(uint256)")) return set_u256(&env.prev_randao, calldata, 0);
    if (is(calldata, "coinbase(address)")) {
        env.coinbase = word.to_address(arg_word(calldata, 0));
        return ok(0);
    }
    if (is(calldata, "prank(address)")) return prank(cheats, parent_depth, calldata, false, false);
    if (is(calldata, "prank(address,address)")) return prank(cheats, parent_depth, calldata, false, true);
    if (is(calldata, "startPrank(address)")) return prank(cheats, parent_depth, calldata, true, false);
    if (is(calldata, "startPrank(address,address)")) return prank(cheats, parent_depth, calldata, true, true);
    if (is(calldata, "stopPrank()")) return stop_prank(cheats);
    return apply_state(cheats, world, env, calldata, out, log_count, log_data_used);
}

fn apply_state(
    cheats: *State,
    world: *world_mod.World,
    env: *state_mod.ExecutionContext,
    calldata: []const u8,
    out: []u8,
    log_count: u32,
    log_data_used: u32,
) Result {
    if (is(calldata, "deal(address,uint256)")) return deal(world, calldata);
    if (is(calldata, "etch(address,bytes)")) return etch(world, calldata);
    if (is(calldata, "load(address,bytes32)")) return load(world, calldata, out);
    if (is(calldata, "store(address,bytes32,bytes32)")) return store(world, calldata);
    if (is(calldata, "getNonce(address)")) return get_nonce(world, calldata, out);
    if (is(calldata, "setNonce(address,uint64)")) return set_nonce(world, calldata);
    if (is(calldata, "resetNonce(address)")) return reset_nonce(world, calldata);
    if (is(calldata, "expectRevert()")) return expect(cheats, .any, calldata);
    if (is(calldata, "expectRevert(bytes4)")) return expect(cheats, .selector, calldata);
    if (is(calldata, "expectRevert(bytes)")) return expect(cheats, .exact, calldata);
    if (is(calldata, "assume(bool)")) return assume(calldata);
    if (is(calldata, "skip(bool)")) return skip(cheats, calldata);
    if (is(calldata, "skip(bool,string)")) return skip(cheats, calldata);
    if (is(calldata, "addr(uint256)")) return addr(calldata, out);
    if (is(calldata, "sign(uint256,bytes32)")) return sign(calldata, out);
    if (is(calldata, "snapshot()")) return snapshot(cheats, world, env, log_count, log_data_used, out);
    if (is(calldata, "snapshotState()")) return snapshot(cheats, world, env, log_count, log_data_used, out);
    if (is(calldata, "revertTo(uint256)")) return revert_to(cheats, world, env, calldata, out, false);
    if (is(calldata, "revertToAndDelete(uint256)")) return revert_to(cheats, world, env, calldata, out, true);
    if (is(calldata, "mockCall(address,bytes,bytes)")) return mock_call(cheats, calldata, false);
    if (is(calldata, "mockCall(address,uint256,bytes,bytes)")) return mock_call(cheats, calldata, true);
    if (is(calldata, "clearMockedCalls()")) return clear_mocks(cheats);
    if (is_noop(calldata)) return ok(0);
    return revert_empty();
}

fn is_noop(data: []const u8) bool {
    return is(data, "label(address,string)") or
        is(data, "expectEmit()") or
        is(data, "expectEmit(bool,bool,bool,bool)") or
        is(data, "expectEmit(bool,bool,bool,bool,address)") or
        is(data, "expectEmit(address)") or
        is(data, "expectCall(address,bytes)") or
        is(data, "expectCall(address,uint256,bytes)") or
        is(data, "pauseGasMetering()") or
        is(data, "resumeGasMetering()") or
        is(data, "record()") or
        is(data, "recordLogs()");
}

fn is(data: []const u8, comptime sig: []const u8) bool {
    const want = comptime sel4(sig);
    if (data.len < 4) return false;
    return std.mem.eql(u8, data[0..4], &want);
}

fn sel4(comptime sig: []const u8) [4]u8 {
    @setEvalBranchQuota(100_000);
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(sig, &hash, .{});
    return hash[0..4].*;
}

fn ok(len: u32) Result {
    return .{ .len = len, .revert = false };
}

fn revert_empty() Result {
    return .{ .len = 0, .revert = true };
}

fn set_u256(slot: *u256, data: []const u8, arg: u32) Result {
    slot.* = arg_word(data, arg);
    return ok(0);
}

fn prank(cheats: *State, depth: u32, data: []const u8, persistent: bool, with_origin: bool) Result {
    cheats.prank = .{
        .active = true,
        .persistent = persistent,
        .depth = depth,
        .sender = word.to_address(arg_word(data, 0)),
        .origin = if (with_origin) word.to_address(arg_word(data, 1)) else 0,
        .has_origin = with_origin,
    };
    return ok(0);
}

fn stop_prank(cheats: *State) Result {
    cheats.prank = .{};
    return ok(0);
}

fn deal(world: *world_mod.World, data: []const u8) Result {
    const who = word.to_address(arg_word(data, 0));
    world.set_balance(who, arg_word(data, 1)) catch return revert_empty();
    return ok(0);
}

fn etch(world: *world_mod.World, data: []const u8) Result {
    const who = word.to_address(arg_word(data, 0));
    if (is_cheatcode(who)) return ok(0);
    const code = dyn_bytes(data, 1) orelse return revert_empty();
    if (code.len > limits.code_bytes_max) return revert_empty();
    world.set_code(who, code) catch return revert_empty();
    return ok(0);
}

fn load(world: *world_mod.World, data: []const u8, out: []u8) Result {
    const who = word.to_address(arg_word(data, 0));
    const key = arg_word(data, 1);
    return write_word(out, world.load(who, key));
}

fn store(world: *world_mod.World, data: []const u8) Result {
    const who = word.to_address(arg_word(data, 0));
    world.store(who, arg_word(data, 1), arg_word(data, 2)) catch return revert_empty();
    return ok(0);
}

fn get_nonce(world: *world_mod.World, data: []const u8, out: []u8) Result {
    const who = word.to_address(arg_word(data, 0));
    return write_word(out, world.get_nonce(who));
}

fn set_nonce(world: *world_mod.World, data: []const u8) Result {
    const who = word.to_address(arg_word(data, 0));
    const nonce: u64 = @truncate(arg_word(data, 1));
    world.set_nonce(who, nonce) catch return revert_empty();
    return ok(0);
}

fn reset_nonce(world: *world_mod.World, data: []const u8) Result {
    const who = word.to_address(arg_word(data, 0));
    const nonce: u64 = if (world.code_of(who).len == 0) 0 else 1;
    world.set_nonce(who, nonce) catch return revert_empty();
    return ok(0);
}

fn expect(cheats: *State, kind: ExpectKind, data: []const u8) Result {
    cheats.expect.kind = kind;
    cheats.expect.data_len = 0;
    if (kind == .selector) {
        var buf: [32]u8 = undefined;
        word.to_bytes_be(arg_word(data, 0), &buf);
        cheats.expect.selector = buf[0..4].*;
    } else if (kind == .exact) {
        const raw = dyn_bytes(data, 0) orelse return revert_empty();
        if (raw.len > limits.cheat_expect_bytes_max) return revert_empty();
        if (raw.len > 0) @memcpy(cheats.expect.data[0..raw.len], raw);
        cheats.expect.data_len = @intCast(raw.len);
    }
    return ok(0);
}

fn assume(data: []const u8) Result {
    if (arg_word(data, 0) == 0) return revert_empty();
    return ok(0);
}

fn skip(cheats: *State, data: []const u8) Result {
    if (arg_word(data, 0) == 0) return ok(0);
    cheats.skipped = true;
    return revert_empty();
}

fn addr(data: []const u8, out: []u8) Result {
    var pk: [32]u8 = undefined;
    word.to_bytes_be(arg_word(data, 0), &pk);
    const who = address_from_key(pk) orelse return revert_empty();
    return write_word(out, who);
}

fn sign(data: []const u8, out: []u8) Result {
    var pk: [32]u8 = undefined;
    var digest: [32]u8 = undefined;
    word.to_bytes_be(arg_word(data, 0), &pk);
    word.to_bytes_be(arg_word(data, 1), &digest);
    const kp = keypair(pk) orelse return revert_empty();
    const sig = kp.signPrehashed(digest, null) catch return revert_empty();
    const r = word.from_bytes_be(&sig.r);
    const s = word.from_bytes_be(&sig.s);
    const want = address_from_key(pk) orelse return revert_empty();
    const v: u256 = if (match_rec(digest, 27, r, s, want)) 27 else 28;
    if (out.len < 96) return revert_empty();
    write_word_at(out, 0, v);
    @memcpy(out[32..64], &sig.r);
    @memcpy(out[64..96], &sig.s);
    return ok(96);
}

fn snapshot(
    cheats: *State,
    world: *world_mod.World,
    env: *state_mod.ExecutionContext,
    log_count: u32,
    log_data_used: u32,
    out: []u8,
) Result {
    if (cheats.snapshot_count >= limits.cheat_snapshots_max) return revert_empty();
    const id = cheats.snapshot_count;
    cheats.snapshots[id] = .{
        .journal_mark = world.mark(),
        .log_count = log_count,
        .log_data_used = log_data_used,
        .env = env.*,
        .prank = cheats.prank,
    };
    cheats.snapshot_count += 1;
    return write_word(out, id);
}

fn revert_to(
    cheats: *State,
    world: *world_mod.World,
    env: *state_mod.ExecutionContext,
    data: []const u8,
    out: []u8,
    delete: bool,
) Result {
    const id_word = arg_word(data, 0);
    if (id_word >= cheats.snapshot_count) return write_word(out, 0);
    const id: u32 = @intCast(id_word);
    const snap = cheats.snapshots[id];
    world.rollback(snap.journal_mark);
    env.* = snap.env;
    cheats.prank = snap.prank;
    if (delete) cheats.snapshot_count = id;
    var result = write_word(out, 1);
    result.restore_logs = true;
    result.log_count = snap.log_count;
    result.log_data_used = snap.log_data_used;
    return result;
}

fn mock_call(cheats: *State, data: []const u8, with_value: bool) Result {
    if (cheats.mock_count >= limits.cheat_mocks_max) return revert_empty();
    const target = word.to_address(arg_word(data, 0));
    const value = if (with_value) arg_word(data, 1) else 0;
    const data_index: u32 = if (with_value) 2 else 1;
    const call_data = dyn_bytes(data, data_index) orelse return revert_empty();
    const ret_data = dyn_bytes(data, data_index + 1) orelse return revert_empty();
    const data_off = append_mock(cheats, call_data) orelse return revert_empty();
    const ret_off = append_mock(cheats, ret_data) orelse return revert_empty();
    cheats.mocks[cheats.mock_count] = .{
        .target = target,
        .value = value,
        .check_value = with_value,
        .data_off = data_off,
        .data_len = @intCast(call_data.len),
        .ret_off = ret_off,
        .ret_len = @intCast(ret_data.len),
    };
    cheats.mock_count += 1;
    return ok(0);
}

fn clear_mocks(cheats: *State) Result {
    cheats.mock_count = 0;
    cheats.mock_data_used = 0;
    return ok(0);
}

fn append_mock(cheats: *State, bytes: []const u8) ?u32 {
    const len: u32 = @intCast(bytes.len);
    if (cheats.mock_data_used + len > limits.cheat_mock_data_bytes_max) return null;
    const off = cheats.mock_data_used;
    if (len > 0) @memcpy(cheats.mock_data[off .. off + len], bytes);
    cheats.mock_data_used += len;
    return off;
}

pub fn find_mock(cheats: *const State, target: u256, value: u256, call_data: []const u8) ?Mock {
    var index = cheats.mock_count;
    while (index > 0) {
        index -= 1;
        const mock = cheats.mocks[index];
        if (mock.target != target) continue;
        if (mock.check_value and mock.value != value) continue;
        const prefix = cheats.mock_data[mock.data_off .. mock.data_off + mock.data_len];
        if (call_data.len < prefix.len) continue;
        if (!std.mem.eql(u8, call_data[0..prefix.len], prefix)) continue;
        return mock;
    }
    return null;
}

pub fn mock_return(cheats: *const State, mock: Mock) []const u8 {
    return cheats.mock_data[mock.ret_off .. mock.ret_off + mock.ret_len];
}

pub fn revert_matches(expected: ExpectRevert, ret: []const u8) bool {
    return switch (expected.kind) {
        .none => false,
        .any => true,
        .selector => ret.len >= 4 and std.mem.eql(u8, ret[0..4], &expected.selector),
        .exact => ret.len == expected.data_len and
            (expected.data_len == 0 or std.mem.eql(u8, ret, expected.data[0..expected.data_len])),
    };
}

fn arg_word(data: []const u8, index: u32) u256 {
    const off: u32 = 4 + index * 32;
    var buf: [32]u8 = @splat(0);
    if (off >= data.len) return 0;
    const n = @min(32, data.len - off);
    @memcpy(buf[0..n], data[off .. off + n]);
    return word.from_bytes_be(&buf);
}

fn dyn_bytes(data: []const u8, index: u32) ?[]const u8 {
    const rel = arg_word(data, index);
    if (rel > std.math.maxInt(u32) - 4) return null;
    const abs = 4 + @as(u32, @intCast(rel));
    const len_word = arg_word_at(data, abs);
    if (len_word > std.math.maxInt(u32)) return null;
    const len: u32 = @intCast(len_word);
    const start = abs + 32;
    if (start > data.len) return null;
    if (start + len > data.len) return null;
    if (len == 0) return data[0..0];
    return data[start .. start + len];
}

fn arg_word_at(data: []const u8, off: u32) u256 {
    var buf: [32]u8 = @splat(0);
    if (off >= data.len) return 0;
    const n = @min(32, data.len - off);
    @memcpy(buf[0..n], data[off .. off + n]);
    return word.from_bytes_be(&buf);
}

fn write_word(out: []u8, value: u256) Result {
    if (out.len < 32) return revert_empty();
    word.to_bytes_be(value, out[0..32]);
    return ok(32);
}

fn write_word_at(out: []u8, off: u32, value: u256) void {
    word.to_bytes_be(value, out[off .. off + 32][0..32]);
}

fn keypair(pk: [32]u8) ?Ecdsa.KeyPair {
    const sk = Ecdsa.SecretKey.fromBytes(pk) catch return null;
    return Ecdsa.KeyPair.fromSecretKey(sk) catch null;
}

fn address_from_key(pk: [32]u8) ?u256 {
    const kp = keypair(pk) orelse return null;
    const uncompressed = kp.public_key.toUncompressedSec1();
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(uncompressed[1..], &digest, .{});
    return word.to_address(word.from_bytes_be(&digest));
}

fn match_rec(digest: [32]u8, v: u256, r: u256, s: u256, want: u256) bool {
    const rec = precompile.ecrecover(digest, v, r, s) orelse return false;
    return word.from_bytes_be(&rec) == want;
}

test "hevm address matches foundry" {
    try std.testing.expectEqual(
        @as(u256, 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D),
        address,
    );
}

test "warp selector" {
    try std.testing.expect(is(&sel4("warp(uint256)"), "warp(uint256)"));
}

test "deal updates balance" {
    var world: world_mod.World = undefined;
    world.init();
    var env = state_mod.ExecutionContext.default();
    var cheats = State{};
    var calldata: [68]u8 = @splat(0);
    const sel = sel4("deal(address,uint256)");
    @memcpy(calldata[0..4], &sel);
    calldata[4 + 31] = 0x42;
    calldata[4 + 32 + 31] = 0x07;
    var out: [32]u8 = undefined;
    const result = apply(&cheats, &world, &env, 0, &calldata, &out, 0, 0);
    try std.testing.expect(!result.revert);
    try std.testing.expectEqual(@as(u256, 7), world.get_balance(0x42));
}
