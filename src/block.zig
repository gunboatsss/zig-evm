//! Block commitments: tx/receipt/withdrawal tries, logs bloom, requests hash.

const std = @import("std");
const delegation = @import("delegation.zig");
const fork_mod = @import("fork.zig");
const gas_mod = @import("gas.zig");
const header_mod = @import("header.zig");
const limits = @import("limits.zig");
const rlp = @import("rlp.zig");
const trie_mod = @import("trie.zig");
const word = @import("u256.zig");

pub const TxKind = enum(u8) {
    legacy = 0,
    access_list = 1,
    fee_market = 2,
    blob = 3,
    set_code = 4,
};

pub const AccessListItem = struct {
    address: u256,
    keys: []const u256,
};

pub const BlockTx = struct {
    kind: TxKind = .legacy,
    nonce: u64 = 0,
    chain_id: u256 = 1,
    to: ?u256 = null,
    data: []const u8,
    gas_limit: u64,
    value: u256,
    sender: u256,
    gas_price: u256,
    max_fee_per_gas: u256 = 0,
    max_priority_fee_per_gas: u256 = 0,
    access_list: []const AccessListItem = &.{},
    authorizations: []const delegation.Authorization = &.{},
    blob_versioned_hashes: []const [32]u8 = &.{},
    max_fee_per_blob_gas: u256 = 0,
    y_parity: u8 = 0,
    v: u256 = 0,
    r: u256 = 0,
    s: u256 = 0,
};

pub const Withdrawal = struct {
    index: u64 = 0,
    validator_index: u64 = 0,
    address: u256,
    amount_gwei: u256,
};

pub const LogView = struct {
    address: u256,
    topics: []const u256,
    data: []const u8,
};

const deposit_contract: u256 = 0x00000000219ab540356cbb839cbe05303d7705fa;
const deposit_topic = hex32("649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5");
const deposit_event_len: u32 = 576;
const deposit_payload_len: u32 = 192;

pub const Receipts = struct {
    encoded: [limits.block_txs_max][]const u8,
    count: u32,
    bytes: [limits.receipt_pool_bytes_max]u8,
    used: u32,
    bloom: [256]u8,
    deposits: [limits.deposit_request_bytes_max]u8,
    deposit_len: u32,

    pub fn reset(self: *Receipts) void {
        self.count = 0;
        self.used = 0;
        self.bloom = @splat(0);
        self.deposit_len = 0;
    }

    pub fn push(
        self: *Receipts,
        kind: TxKind,
        succeeded: bool,
        cumulative_gas: u64,
        logs: []const LogView,
    ) !void {
        if (self.count >= limits.block_txs_max) return error.ReceiptLimit;
        var rec_bloom: [256]u8 = @splat(0);
        logs_bloom(&rec_bloom, logs);
        or_bloom(&self.bloom, rec_bloom);
        try self.collect_deposits(logs);
        var buf: [limits.receipt_rlp_bytes_max]u8 = undefined;
        const n = try encode_receipt(&buf, kind, succeeded, cumulative_gas, rec_bloom, logs);
        const off = self.used;
        if (off + n > limits.receipt_pool_bytes_max) return error.ReceiptLimit;
        @memcpy(self.bytes[off .. off + n], buf[0..n]);
        self.used = off + n;
        self.encoded[self.count] = self.bytes[off .. off + n];
        self.count += 1;
    }

    pub fn receipts_root(self: *const Receipts, trie: *trie_mod.Trie) ![32]u8 {
        return trie.indexed_root(self.encoded[0..self.count]);
    }

    fn collect_deposits(self: *Receipts, logs: []const LogView) !void {
        for (logs) |log| {
            if (log.address != deposit_contract) continue;
            if (log.topics.len == 0) continue;
            if (log.topics[0] != word.from_bytes_be(&deposit_topic)) continue;
            const payload = try extract_deposit(log.data);
            const next = self.deposit_len + deposit_payload_len;
            if (next > limits.deposit_request_bytes_max) return error.DepositLimit;
            @memcpy(self.deposits[self.deposit_len..next], &payload);
            self.deposit_len = next;
        }
    }
};

pub fn transactions_root(trie: *trie_mod.Trie, txs: []const BlockTx) ![32]u8 {
    trie.reset();
    var buf: [limits.tx_rlp_bytes_max]u8 = undefined;
    var i: u32 = 0;
    while (i < txs.len) : (i += 1) {
        const n = try encode_tx(&buf, txs[i]);
        try trie.insert_indexed(i, buf[0..n]);
    }
    return trie.root_hash();
}

pub fn withdrawals_root(trie: *trie_mod.Trie, withdrawals: []const Withdrawal) ![32]u8 {
    trie.reset();
    var buf: [96]u8 = undefined;
    var i: u32 = 0;
    while (i < withdrawals.len) : (i += 1) {
        const n = encode_withdrawal(&buf, withdrawals[i]);
        try trie.insert_indexed(i, buf[0..n]);
    }
    return trie.root_hash();
}

pub fn requests_hash(deposits: []const u8, withdrawals: []const u8, consolidations: []const u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    append_request(&hasher, 0x00, deposits);
    append_request(&hasher, 0x01, withdrawals);
    append_request(&hasher, 0x02, consolidations);
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

pub fn encode_tx(out: []u8, tx: BlockTx) !u32 {
    var inner: [limits.tx_rlp_bytes_max]u8 = undefined;
    const n = switch (tx.kind) {
        .legacy => try encode_legacy(&inner, tx),
        .access_list => try encode_access_tx(&inner, tx),
        .fee_market => try encode_fee_tx(&inner, tx),
        .blob => try encode_blob_tx(&inner, tx),
        .set_code => try encode_set_code_tx(&inner, tx),
    };
    if (tx.kind == .legacy) {
        if (n > out.len) return error.TxTooLarge;
        @memcpy(out[0..n], inner[0..n]);
        return n;
    }
    if (1 + n > out.len) return error.TxTooLarge;
    out[0] = @intFromEnum(tx.kind);
    @memcpy(out[1 .. 1 + n], inner[0..n]);
    return 1 + n;
}

fn encode_legacy(out: []u8, tx: BlockTx) !u32 {
    var payload: [limits.tx_rlp_bytes_max]u8 = undefined;
    var n: u32 = 0;
    n += rlp.uint(payload[n..], tx.nonce);
    n += rlp.uint(payload[n..], tx.gas_price);
    n += rlp.uint(payload[n..], tx.gas_limit);
    n += encode_to(payload[n..], tx.to);
    n += rlp.uint(payload[n..], tx.value);
    n += rlp.bytes(payload[n..], tx.data);
    n += rlp.uint(payload[n..], tx.v);
    n += rlp.uint(payload[n..], tx.r);
    n += rlp.uint(payload[n..], tx.s);
    return rlp.list(out, payload[0..n]);
}

fn encode_access_tx(out: []u8, tx: BlockTx) !u32 {
    var payload: [limits.tx_rlp_bytes_max]u8 = undefined;
    var n: u32 = 0;
    n += rlp.uint(payload[n..], tx.chain_id);
    n += rlp.uint(payload[n..], tx.nonce);
    n += rlp.uint(payload[n..], tx.gas_price);
    n += rlp.uint(payload[n..], tx.gas_limit);
    n += encode_to(payload[n..], tx.to);
    n += rlp.uint(payload[n..], tx.value);
    n += rlp.bytes(payload[n..], tx.data);
    n += try encode_access_list(payload[n..], tx.access_list);
    n += rlp.uint(payload[n..], tx.y_parity);
    n += rlp.uint(payload[n..], tx.r);
    n += rlp.uint(payload[n..], tx.s);
    return rlp.list(out, payload[0..n]);
}

fn encode_fee_tx(out: []u8, tx: BlockTx) !u32 {
    var payload: [limits.tx_rlp_bytes_max]u8 = undefined;
    var n: u32 = 0;
    n += rlp.uint(payload[n..], tx.chain_id);
    n += rlp.uint(payload[n..], tx.nonce);
    n += rlp.uint(payload[n..], tx.max_priority_fee_per_gas);
    n += rlp.uint(payload[n..], tx.max_fee_per_gas);
    n += rlp.uint(payload[n..], tx.gas_limit);
    n += encode_to(payload[n..], tx.to);
    n += rlp.uint(payload[n..], tx.value);
    n += rlp.bytes(payload[n..], tx.data);
    n += try encode_access_list(payload[n..], tx.access_list);
    n += rlp.uint(payload[n..], tx.y_parity);
    n += rlp.uint(payload[n..], tx.r);
    n += rlp.uint(payload[n..], tx.s);
    return rlp.list(out, payload[0..n]);
}

fn encode_blob_tx(out: []u8, tx: BlockTx) !u32 {
    var payload: [limits.tx_rlp_bytes_max]u8 = undefined;
    var n: u32 = 0;
    n += rlp.uint(payload[n..], tx.chain_id);
    n += rlp.uint(payload[n..], tx.nonce);
    n += rlp.uint(payload[n..], tx.max_priority_fee_per_gas);
    n += rlp.uint(payload[n..], tx.max_fee_per_gas);
    n += rlp.uint(payload[n..], tx.gas_limit);
    n += encode_to(payload[n..], tx.to);
    n += rlp.uint(payload[n..], tx.value);
    n += rlp.bytes(payload[n..], tx.data);
    n += try encode_access_list(payload[n..], tx.access_list);
    n += rlp.uint(payload[n..], tx.max_fee_per_blob_gas);
    n += encode_hashes(payload[n..], tx.blob_versioned_hashes);
    n += rlp.uint(payload[n..], tx.y_parity);
    n += rlp.uint(payload[n..], tx.r);
    n += rlp.uint(payload[n..], tx.s);
    return rlp.list(out, payload[0..n]);
}

fn encode_set_code_tx(out: []u8, tx: BlockTx) !u32 {
    var payload: [limits.tx_rlp_bytes_max]u8 = undefined;
    var n: u32 = 0;
    n += rlp.uint(payload[n..], tx.chain_id);
    n += rlp.uint(payload[n..], tx.nonce);
    n += rlp.uint(payload[n..], tx.max_priority_fee_per_gas);
    n += rlp.uint(payload[n..], tx.max_fee_per_gas);
    n += rlp.uint(payload[n..], tx.gas_limit);
    n += encode_to(payload[n..], tx.to);
    n += rlp.uint(payload[n..], tx.value);
    n += rlp.bytes(payload[n..], tx.data);
    n += try encode_access_list(payload[n..], tx.access_list);
    n += try encode_auths(payload[n..], tx.authorizations);
    n += rlp.uint(payload[n..], tx.y_parity);
    n += rlp.uint(payload[n..], tx.r);
    n += rlp.uint(payload[n..], tx.s);
    return rlp.list(out, payload[0..n]);
}

fn encode_to(out: []u8, to: ?u256) u32 {
    if (to) |addr| return rlp.encode_address(out, addr);
    return rlp.bytes(out, &[_]u8{});
}

fn encode_access_list(out: []u8, list: []const AccessListItem) !u32 {
    var payload: [limits.tx_rlp_bytes_max]u8 = undefined;
    var n: u32 = 0;
    for (list) |item| {
        n += try encode_access_item(payload[n..], item);
    }
    return rlp.list(out, payload[0..n]);
}

fn encode_access_item(out: []u8, item: AccessListItem) !u32 {
    var keys_payload: [limits.tx_rlp_bytes_max]u8 = undefined;
    var kn: u32 = 0;
    for (item.keys) |key| {
        var be: [32]u8 = undefined;
        word.to_bytes_be(key, &be);
        kn += rlp.bytes(keys_payload[kn..], &be);
    }
    var payload: [limits.tx_rlp_bytes_max]u8 = undefined;
    var n: u32 = 0;
    n += rlp.encode_address(payload[n..], item.address);
    n += rlp.list(payload[n..], keys_payload[0..kn]);
    return rlp.list(out, payload[0..n]);
}

fn encode_hashes(out: []u8, hashes: []const [32]u8) u32 {
    var payload: [limits.blob_versioned_hashes_max * 33]u8 = undefined;
    var n: u32 = 0;
    for (hashes) |hash| {
        n += rlp.bytes(payload[n..], &hash);
    }
    return rlp.list(out, payload[0..n]);
}

fn encode_auths(out: []u8, auths: []const delegation.Authorization) !u32 {
    var payload: [limits.tx_rlp_bytes_max]u8 = undefined;
    var n: u32 = 0;
    for (auths) |auth| {
        n += encode_auth(payload[n..], auth);
    }
    return rlp.list(out, payload[0..n]);
}

fn encode_auth(out: []u8, auth: delegation.Authorization) u32 {
    var payload: [128]u8 = undefined;
    var n: u32 = 0;
    n += rlp.uint(payload[n..], auth.chain_id);
    n += rlp.encode_address(payload[n..], auth.address);
    n += rlp.uint(payload[n..], auth.nonce);
    n += rlp.uint(payload[n..], auth.y_parity);
    n += rlp.uint(payload[n..], auth.r);
    n += rlp.uint(payload[n..], auth.s);
    return rlp.list(out, payload[0..n]);
}

pub fn encode_receipt(
    out: []u8,
    kind: TxKind,
    succeeded: bool,
    cumulative_gas: u64,
    bloom: [256]u8,
    logs: []const LogView,
) !u32 {
    var logs_buf: [limits.receipt_rlp_bytes_max]u8 = undefined;
    const logs_n = try encode_logs(&logs_buf, logs);
    var payload: [limits.receipt_rlp_bytes_max]u8 = undefined;
    var n: u32 = 0;
    n += rlp.uint(payload[n..], if (succeeded) 1 else 0);
    n += rlp.uint(payload[n..], cumulative_gas);
    n += rlp.bytes(payload[n..], &bloom);
    if (n + logs_n > payload.len) return error.ReceiptTooLarge;
    @memcpy(payload[n .. n + logs_n], logs_buf[0..logs_n]);
    n += logs_n;
    const wrapped = rlp.list(out[if (kind == .legacy) 0 else 1..], payload[0..n]);
    if (kind == .legacy) return wrapped;
    out[0] = @intFromEnum(kind);
    return 1 + wrapped;
}

fn encode_logs(out: []u8, logs: []const LogView) !u32 {
    var payload: [limits.receipt_rlp_bytes_max]u8 = undefined;
    var n: u32 = 0;
    for (logs) |log| {
        n += try encode_log(payload[n..], log);
    }
    return rlp.list(out, payload[0..n]);
}

fn encode_log(out: []u8, log: LogView) !u32 {
    var topics_payload: [limits.log_topics_max * 33]u8 = undefined;
    var tn: u32 = 0;
    for (log.topics) |topic| {
        var be: [32]u8 = undefined;
        word.to_bytes_be(topic, &be);
        tn += rlp.bytes(topics_payload[tn..], &be);
    }
    const hdr_room = rlp.list_header_room;
    std.debug.assert(out.len >= hdr_room);
    var n: u32 = hdr_room;
    n += rlp.encode_address(out[n..], log.address);
    n += rlp.list(out[n..], topics_payload[0..tn]);
    n += rlp.bytes(out[n..], log.data);
    return rlp.wrap_list(out, hdr_room, n);
}

pub fn encode_withdrawal(out: []u8, w: Withdrawal) u32 {
    var payload: [64]u8 = undefined;
    var n: u32 = 0;
    n += rlp.uint(payload[n..], w.index);
    n += rlp.uint(payload[n..], w.validator_index);
    n += rlp.encode_address(payload[n..], w.address);
    n += rlp.uint(payload[n..], w.amount_gwei);
    return rlp.list(out, payload[0..n]);
}

pub fn logs_bloom(bloom: *[256]u8, logs: []const LogView) void {
    for (logs) |log| {
        var addr: [20]u8 = undefined;
        var be: [32]u8 = undefined;
        word.to_bytes_be(log.address, &be);
        @memcpy(&addr, be[12..32]);
        add_to_bloom(bloom, &addr);
        for (log.topics) |topic| {
            word.to_bytes_be(topic, &be);
            add_to_bloom(bloom, &be);
        }
    }
}

pub fn add_to_bloom(bloom: *[256]u8, entry: []const u8) void {
    var hashed: [32]u8 = undefined;
    rlp.keccak(entry, &hashed);
    const pairs = [_]u32{ 0, 2, 4 };
    for (pairs) |idx| {
        const bit_to_set = (@as(u16, hashed[idx]) << 8 | hashed[idx + 1]) & 0x07ff;
        const bit_index: u32 = 0x07ff - bit_to_set;
        const byte_index = bit_index / 8;
        const bit_value: u8 = @as(u8, 1) << @intCast(7 - (bit_index % 8));
        bloom[byte_index] |= bit_value;
    }
}

fn or_bloom(dst: *[256]u8, src: [256]u8) void {
    var i: u32 = 0;
    while (i < 256) : (i += 1) dst[i] |= src[i];
}

fn append_request(hasher: *std.crypto.hash.sha2.Sha256, kind: u8, payload: []const u8) void {
    if (payload.len == 0) return;
    std.debug.assert(payload.len <= limits.system_request_bytes_max);
    var buf: [limits.system_request_bytes_max + 1]u8 = undefined;
    buf[0] = kind;
    @memcpy(buf[1 .. 1 + payload.len], payload);
    var inner: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(buf[0 .. 1 + payload.len], &inner, .{});
    hasher.update(&inner);
}

fn extract_deposit(data: []const u8) ![deposit_payload_len]u8 {
    if (data.len != deposit_event_len) return error.InvalidDeposit;
    if (be32(data, 0) != 160) return error.InvalidDeposit;
    if (be32(data, 32) != 256) return error.InvalidDeposit;
    if (be32(data, 64) != 320) return error.InvalidDeposit;
    if (be32(data, 96) != 384) return error.InvalidDeposit;
    if (be32(data, 128) != 512) return error.InvalidDeposit;
    if (be32(data, 160) != 48) return error.InvalidDeposit;
    if (be32(data, 256) != 32) return error.InvalidDeposit;
    if (be32(data, 320) != 8) return error.InvalidDeposit;
    if (be32(data, 384) != 96) return error.InvalidDeposit;
    if (be32(data, 512) != 8) return error.InvalidDeposit;
    var out: [deposit_payload_len]u8 = undefined;
    @memcpy(out[0..48], data[192..240]);
    @memcpy(out[48..80], data[288..320]);
    @memcpy(out[80..88], data[352..360]);
    @memcpy(out[88..184], data[416..512]);
    @memcpy(out[184..192], data[544..552]);
    return out;
}

fn be32(data: []const u8, off: u32) u32 {
    return std.mem.readInt(u32, data[off + 28 .. off + 32][0..4], .big);
}

pub fn header_parent_ok(
    parent: header_mod.Header,
    header: header_mod.Header,
    fork: fork_mod.Fork,
) bool {
    if (header.number != parent.number + 1) return false;
    if (header.timestamp <= parent.timestamp) return false;
    if (header.difficulty != 0) return false;
    if (!std.mem.allEqual(u8, &header.nonce, 0)) return false;
    if (!std.mem.eql(u8, &header.ommers_hash, &header_mod.empty_ommers_hash)) return false;
    if (header.extra.len > limits.extra_data_bytes_protocol_max) return false;
    const want = gas_mod.next_excess_blob_gas(
        parent.excess_blob_gas,
        parent.blob_gas_used,
        parent.base_fee,
        fork,
    );
    if (header.excess_blob_gas != want) return false;
    return true;
}

fn hex32(text: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;
    return out;
}

test "empty requests hash is sha256 of empty" {
    var want: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&[_]u8{}, &want, .{});
    try std.testing.expectEqualSlices(u8, &want, &header_mod.empty_requests_hash);
    try std.testing.expectEqualSlices(u8, &want, &requests_hash(&.{}, &.{}, &.{}));
}

test "empty logs bloom is zero" {
    var bloom: [256]u8 = @splat(0);
    logs_bloom(&bloom, &.{});
    try std.testing.expect(std.mem.allEqual(u8, &bloom, 0));
}

test "add to bloom sets three bits" {
    var bloom: [256]u8 = @splat(0);
    add_to_bloom(&bloom, &[_]u8{0x01});
    var bits: u32 = 0;
    for (bloom) |byte| bits += @popCount(byte);
    try std.testing.expectEqual(@as(u32, 3), bits);
}

test "legacy empty tx encodes as a list" {
    const tx = BlockTx{
        .data = &.{},
        .gas_limit = 21_000,
        .value = 0,
        .sender = 1,
        .gas_price = 1,
        .v = 27,
        .r = 1,
        .s = 1,
    };
    var buf: [limits.tx_rlp_bytes_max]u8 = undefined;
    const n = try encode_tx(&buf, tx);
    try std.testing.expect(n > 0);
    try std.testing.expect(buf[0] >= 0xc0);
}

test "type-2 tx starts with 0x02" {
    const tx = BlockTx{
        .kind = .fee_market,
        .data = &.{},
        .gas_limit = 21_000,
        .value = 0,
        .sender = 1,
        .gas_price = 1,
        .max_fee_per_gas = 1,
        .to = 0xaa,
        .r = 1,
        .s = 1,
    };
    var buf: [limits.tx_rlp_bytes_max]u8 = undefined;
    const n = try encode_tx(&buf, tx);
    try std.testing.expect(n > 1);
    try std.testing.expectEqual(@as(u8, 0x02), buf[0]);
}

test "withdrawal list root is empty for no withdrawals" {
    const trie = try std.testing.allocator.create(trie_mod.Trie);
    defer std.testing.allocator.destroy(trie);
    const root = try withdrawals_root(trie, &.{});
    try std.testing.expectEqualSlices(u8, &trie_mod.empty_root, &root);
}

test "header parent excess matches genesis to empty block" {
    const parent = header_mod.Header{ .number = 0, .gas_limit = 30_000_000, .timestamp = 1, .base_fee = 7 };
    const child = header_mod.Header{
        .number = 1,
        .gas_limit = 30_000_000,
        .timestamp = 2,
        .base_fee = 7,
        .excess_blob_gas = 0,
    };
    try std.testing.expect(header_parent_ok(parent, child, .osaka));
}
