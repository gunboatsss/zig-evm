//! Execution-layer header and `keccak256(rlp(header))` block hash.

const std = @import("std");
const limits = @import("limits.zig");
const rlp = @import("rlp.zig");
const trie_mod = @import("trie.zig");
const word = @import("u256.zig");

/// keccak256(rlp([])) — empty uncle list.
pub const empty_ommers_hash = hex32("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347");
/// EIP-7685 empty requests: SHA-256 of the empty string.
pub const empty_requests_hash = hex32("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

pub const Header = struct {
    parent_hash: [32]u8 = @splat(0),
    ommers_hash: [32]u8 = empty_ommers_hash,
    coinbase: u256 = 0,
    state_root: [32]u8 = @splat(0),
    transactions_root: [32]u8 = @splat(0),
    receipts_root: [32]u8 = @splat(0),
    bloom: [256]u8 = @splat(0),
    difficulty: u256 = 0,
    number: u256 = 0,
    gas_limit: u256 = 0,
    gas_used: u256 = 0,
    timestamp: u256 = 0,
    extra: []const u8 = &.{},
    prev_randao: [32]u8 = @splat(0),
    nonce: [8]u8 = @splat(0),
    base_fee: u256 = 0,
    withdrawals_root: [32]u8 = @splat(0),
    blob_gas_used: u256 = 0,
    excess_blob_gas: u256 = 0,
    parent_beacon_root: [32]u8 = @splat(0),
    requests_hash: [32]u8 = empty_requests_hash,

    pub fn hash(self: Header) [32]u8 {
        var payload: [limits.header_rlp_bytes_max]u8 = undefined;
        const pay = self.encode_payload(&payload);
        var encoded: [limits.header_rlp_bytes_max]u8 = undefined;
        const n = rlp.list(encoded[0..], payload[0..pay]);
        var out: [32]u8 = undefined;
        rlp.keccak(encoded[0..n], &out);
        return out;
    }

    fn encode_payload(self: Header, out: *[limits.header_rlp_bytes_max]u8) u32 {
        var n: u32 = 0;
        n += rlp.bytes(out[n..], &self.parent_hash);
        n += rlp.bytes(out[n..], &self.ommers_hash);
        n += rlp.encode_address(out[n..], self.coinbase);
        n += rlp.bytes(out[n..], &self.state_root);
        n += rlp.bytes(out[n..], &self.transactions_root);
        n += rlp.bytes(out[n..], &self.receipts_root);
        n += rlp.bytes(out[n..], &self.bloom);
        n += rlp.uint(out[n..], self.difficulty);
        n += rlp.uint(out[n..], self.number);
        n += rlp.uint(out[n..], self.gas_limit);
        n += rlp.uint(out[n..], self.gas_used);
        n += rlp.uint(out[n..], self.timestamp);
        n += rlp.bytes(out[n..], self.extra);
        n += rlp.bytes(out[n..], &self.prev_randao);
        n += rlp.bytes(out[n..], &self.nonce);
        n += rlp.uint(out[n..], self.base_fee);
        n += rlp.bytes(out[n..], &self.withdrawals_root);
        n += rlp.uint(out[n..], self.blob_gas_used);
        n += rlp.uint(out[n..], self.excess_blob_gas);
        n += rlp.bytes(out[n..], &self.parent_beacon_root);
        n += rlp.bytes(out[n..], &self.requests_hash);
        std.debug.assert(n <= limits.header_rlp_bytes_max);
        return n;
    }
};

/// Dummy parent chain for isolated state tests: each hash is `keccak256(rlp(header))`.
pub fn fill_window(
    out: *[limits.block_hashes_max][32]u8,
    current_number: u256,
    coinbase: u256,
    gas_limit: u256,
    timestamp: u256,
    base_fee: u256,
    prev_randao: u256,
    state_root: [32]u8,
) u32 {
    const count: u32 = if (current_number == 0)
        0
    else if (current_number > limits.block_hashes_max)
        limits.block_hashes_max
    else
        @intCast(current_number);
    var parent: [32]u8 = @splat(0);
    var randao: [32]u8 = undefined;
    word.to_bytes_be(prev_randao, &randao);
    var i: u32 = 0;
    const first = current_number - count;
    while (i < count) : (i += 1) {
        const number = first + i;
        const header = Header{
            .parent_hash = parent,
            .coinbase = coinbase,
            .state_root = state_root,
            .number = number,
            .gas_limit = gas_limit,
            .timestamp = timestamp,
            .prev_randao = randao,
            .base_fee = base_fee,
            .withdrawals_root = trie_mod.empty_root,
        };
        parent = header.hash();
        out[i] = parent;
    }
    return count;
}

pub fn lookup(hashes: []const [32]u8, count: u32, current_number: u256, wanted: u256) u256 {
    if (wanted >= current_number) return 0;
    const dist = current_number - wanted;
    if (dist > 256 or dist > count) return 0;
    const index = count - @as(u32, @intCast(dist));
    std.debug.assert(index < count);
    return word.from_bytes_be(&hashes[index]);
}

fn hex32(text: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;
    return out;
}

test "empty ommers hash is keccak of empty list" {
    var encoded: [1]u8 = undefined;
    _ = rlp.list(&encoded, &[_]u8{});
    var hash: [32]u8 = undefined;
    rlp.keccak(&encoded, &hash);
    try std.testing.expectEqualSlices(u8, &empty_ommers_hash, &hash);
}

test "header hash is stable for a dummy genesis" {
    const h = Header{ .number = 0, .gas_limit = 30_000_000, .timestamp = 1 };
    const a = h.hash();
    const b = h.hash();
    try std.testing.expectEqualSlices(u8, &a, &b);
}

test "blockhash window: current and too-old are zero" {
    var hashes: [limits.block_hashes_max][32]u8 = undefined;
    const count = fill_window(&hashes, 3, 1, 30_000_000, 1000, 1, 0, @splat(0));
    try std.testing.expectEqual(@as(u32, 3), count);
    try std.testing.expectEqual(@as(u256, 0), lookup(&hashes, count, 3, 3));
    try std.testing.expect(lookup(&hashes, count, 3, 2) != 0);
    try std.testing.expect(lookup(&hashes, count, 3, 0) != 0);
}
