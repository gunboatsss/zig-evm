//! EEST `blockchain_tests` JSON runner.
//!
//! Valid Osaka blocks first: skip `expectException` and uncles.
//! Transaction / receipt tries are copied from the fixture so
//! header hashing still matches when `stateRoot` and `gasUsed` are right.

const std = @import("std");
const evm = @import("evm.zig");
const header_mod = @import("header.zig");
const limits = @import("limits.zig");
const trie_mod = @import("trie.zig");
const word = @import("u256.zig");
const world_mod = @import("world.zig");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;

pub const Outcome = enum { pass, fail, skip };

pub const default_path = "tests/eest/blockchain_tests";

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

const JsonAccess = struct {
    address: []const u8 = "",
    storageKeys: []const []const u8 = &.{},
};

const JsonAuth = struct {
    chainId: []const u8 = "0x00",
    address: []const u8 = "",
    nonce: []const u8 = "0x00",
    yParity: []const u8 = "",
    v: []const u8 = "",
    r: []const u8 = "",
    s: []const u8 = "",
};

const JsonHeader = struct {
    parentHash: []const u8 = "0x00",
    uncleHash: []const u8 = "",
    ommersHash: []const u8 = "",
    coinbase: []const u8 = "",
    miner: []const u8 = "",
    stateRoot: []const u8 = "0x00",
    transactionsTrie: []const u8 = "",
    transactionsRoot: []const u8 = "",
    receiptTrie: []const u8 = "",
    receiptsRoot: []const u8 = "",
    bloom: []const u8 = "",
    logsBloom: []const u8 = "",
    difficulty: []const u8 = "0x00",
    number: []const u8 = "0x00",
    gasLimit: []const u8 = "0x00",
    gasUsed: []const u8 = "0x00",
    timestamp: []const u8 = "0x00",
    extraData: []const u8 = "0x",
    mixHash: []const u8 = "0x00",
    nonce: []const u8 = "0x00",
    baseFeePerGas: []const u8 = "0x00",
    withdrawalsRoot: []const u8 = "",
    blobGasUsed: []const u8 = "0x00",
    excessBlobGas: []const u8 = "0x00",
    parentBeaconBlockRoot: []const u8 = "",
    requestsHash: []const u8 = "",
    blockAccessListHash: []const u8 = "",
    hash: []const u8 = "",
};

const JsonTx = struct {
    type: []const u8 = "0x00",
    sender: []const u8 = "",
    secretKey: []const u8 = "",
    to: ?[]const u8 = null,
    data: []const u8 = "0x",
    gasLimit: []const u8 = "0x00",
    value: []const u8 = "0x00",
    gasPrice: []const u8 = "",
    maxFeePerGas: []const u8 = "",
    maxPriorityFeePerGas: []const u8 = "",
    maxFeePerBlobGas: []const u8 = "",
    accessList: []const JsonAccess = &.{},
    authorizationList: []const JsonAuth = &.{},
    blobVersionedHashes: []const []const u8 = &.{},
};

const JsonWithdrawal = struct {
    index: []const u8 = "0x00",
    validatorIndex: []const u8 = "0x00",
    address: []const u8 = "",
    amount: []const u8 = "0x00",
};

const JsonBlock = struct {
    blockHeader: ?JsonHeader = null,
    transactions: []const JsonTx = &.{},
    uncleHeaders: []const JsonHeader = &.{},
    withdrawals: ?[]const JsonWithdrawal = null,
    expectException: ?std.json.Value = null,
};

const JsonConfig = struct {
    chainid: []const u8 = "0x01",
};

const JsonFixture = struct {
    network: []const u8 = "",
    genesisBlockHeader: JsonHeader = .{},
    pre: std.json.ArrayHashMap(JsonAccount) = .{},
    blocks: []const JsonBlock = &.{},
    lastblockhash: []const u8 = "",
    postState: ?std.json.ArrayHashMap(JsonAccount) = null,
    postStateHash: []const u8 = "",
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
    var parsed = try std.json.parseFromSlice(std.json.ArrayHashMap(JsonFixture), allocator, json, .{
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
        if (!looks_like_chain_test(bytes)) {
            try writer.print("{s} skip not-blockchain-test\n", .{path});
            return .{ .skipped = 1 };
        }
        try writer.print("{s} fail parse: {s}\n", .{ path, @errorName(err) });
        return .{ .failed = 1 };
    };
}

fn looks_like_chain_test(json: []const u8) bool {
    return std.mem.indexOf(u8, json, "\"genesisBlockHeader\"") != null and
        std.mem.indexOf(u8, json, "\"pre\"") != null;
}

fn run_named(
    allocator: std.mem.Allocator,
    name: []const u8,
    fixture: *const JsonFixture,
    writer: *std.Io.Writer,
    fork: evm.Fork,
    summary: *Summary,
) !void {
    if (fixture.pre.map.count() == 0) return;
    if (skip_reason(name, fixture, fork)) |reason| {
        try writer.print("{s} skip {s}\n", .{ name, reason });
        try writer.flush();
        summary.skipped += 1;
        return;
    }
    const outcome = run_case(allocator, fixture, fork) catch |err| {
        try writer.print("{s} fail {s}\n", .{ name, @errorName(err) });
        try writer.flush();
        summary.failed += 1;
        return;
    };
    try writer.print("{s} {s}\n", .{ name, @tagName(outcome) });
    try writer.flush();
    tally(summary, outcome);
}

fn skip_reason(name: []const u8, fixture: *const JsonFixture, fork: evm.Fork) ?[]const u8 {
    _ = name;
    const mapped = fixture_fork(fixture.network) orelse return "unknown-fork";
    if (mapped != fork) return "fork";
    for (fixture.blocks) |block| {
        if (has_exception(block.expectException)) return "expect-exception";
        if (block.blockHeader == null) return "undecoded-block";
        if (block.uncleHeaders.len != 0) return "uncles";
        if (unsupported_header(block.blockHeader.?)) |why| return why;
    }
    if (unsupported_header(fixture.genesisBlockHeader)) |why| return why;
    return null;
}

fn unsupported_header(header: JsonHeader) ?[]const u8 {
    if (!is_blank_hex(header.blockAccessListHash)) return "block-access-list";
    return null;
}

fn has_exception(value: ?std.json.Value) bool {
    const inner = value orelse return false;
    return inner != .null;
}

fn run_case(allocator: std.mem.Allocator, fixture: *const JsonFixture, fork: evm.Fork) !Outcome {
    const vm = try allocator.create(evm.Vm);
    defer allocator.destroy(vm);
    vm.init_plain(fork);
    try load_pre(&vm.world, &fixture.pre);
    vm.world.journal_count = 0;
    vm.env.chain_id = try parse_u256(fixture.config.chainid);

    var extra: [limits.header_extra_bytes_max]u8 = undefined;
    const genesis = try decode_header(fixture.genesisBlockHeader, &extra);
    try check_state_root(allocator, &vm.world, genesis.state_root);
    const genesis_hash = genesis.hash();
    try check_header_hash(fixture.genesisBlockHeader.hash, genesis_hash);
    vm.push_block_hash(genesis_hash);

    var head = genesis_hash;
    for (fixture.blocks) |block| {
        head = try apply_fixture_block(allocator, vm, block.blockHeader.?, block.transactions, block.withdrawals);
    }
    try check_header_hash(fixture.lastblockhash, head);
    if (fixture.postState) |state| {
        check_state(&vm.world, &state) catch return .fail;
    }
    if (parse_root(fixture.postStateHash)) |root| {
        try check_state_root(allocator, &vm.world, root);
    }
    return .pass;
}

fn apply_fixture_block(
    allocator: std.mem.Allocator,
    vm: *evm.Vm,
    json_header: JsonHeader,
    json_txs: []const JsonTx,
    json_withdrawals: ?[]const JsonWithdrawal,
) ![32]u8 {
    var extra: [limits.header_extra_bytes_max]u8 = undefined;
    const header = try decode_header(json_header, &extra);
    const txs = try parse_txs(allocator, json_txs, header.base_fee);
    defer free_txs(allocator, txs);
    const withdrawals = try parse_withdrawals(allocator, json_withdrawals);
    defer if (withdrawals.len != 0) allocator.free(withdrawals);
    const gas_used = try vm.apply_block(header, txs, withdrawals);
    if (header.gas_used != 0 and @as(u256, gas_used) != header.gas_used) {
        return error.GasUsedMismatch;
    }
    try check_state_root(allocator, &vm.world, header.state_root);
    const hash = header.hash();
    try check_header_hash(json_header.hash, hash);
    vm.push_block_hash(hash);
    return hash;
}

fn parse_txs(allocator: std.mem.Allocator, json_txs: []const JsonTx, base_fee: u256) ![]evm.BlockTx {
    if (json_txs.len == 0) return &.{};
    const txs = try allocator.alloc(evm.BlockTx, json_txs.len);
    errdefer allocator.free(txs);
    var filled: usize = 0;
    errdefer {
        var i: usize = 0;
        while (i < filled) : (i += 1) free_tx(allocator, txs[i]);
    }
    for (json_txs, 0..) |json_tx, index| {
        txs[index] = try parse_tx(allocator, json_tx, base_fee);
        filled = index + 1;
    }
    return txs;
}

fn parse_tx(allocator: std.mem.Allocator, json_tx: JsonTx, base_fee: u256) !evm.BlockTx {
    const data = try parse_hex_alloc(allocator, json_tx.data);
    errdefer allocator.free(data);
    const access = try parse_access(allocator, json_tx.accessList);
    errdefer free_access(allocator, access);
    const auths = try parse_auths(allocator, json_tx.authorizationList);
    errdefer if (auths.len != 0) allocator.free(auths);
    const blobs = try parse_blob_hashes(allocator, json_tx.blobVersionedHashes);
    errdefer if (blobs.len != 0) allocator.free(blobs);
    return .{
        .to = try call_target(json_tx.to),
        .data = data,
        .gas_limit = try parse_u64(json_tx.gasLimit),
        .value = try parse_u256(json_tx.value),
        .sender = try sender_of(json_tx),
        .gas_price = try tx_gas_price(json_tx, base_fee),
        .access_list = access,
        .authorizations = auths,
        .blob_versioned_hashes = blobs,
        .max_fee_per_blob_gas = try parse_u256(json_tx.maxFeePerBlobGas),
    };
}

fn parse_withdrawals(allocator: std.mem.Allocator, json_w: ?[]const JsonWithdrawal) ![]evm.Withdrawal {
    const items = json_w orelse return &.{};
    if (items.len == 0) return &.{};
    if (items.len > limits.withdrawals_max) return error.WithdrawalLimit;
    const out = try allocator.alloc(evm.Withdrawal, items.len);
    errdefer allocator.free(out);
    for (items, 0..) |item, index| {
        out[index] = .{
            .address = try parse_address(item.address),
            .amount_gwei = try parse_u256(item.amount),
        };
    }
    return out;
}

fn parse_blob_hashes(allocator: std.mem.Allocator, hashes: []const []const u8) ![][32]u8 {
    if (hashes.len == 0) return &.{};
    if (hashes.len > limits.blob_versioned_hashes_max) return error.BlobLimit;
    const out = try allocator.alloc([32]u8, hashes.len);
    errdefer allocator.free(out);
    for (hashes, 0..) |text, index| {
        out[index] = try parse_fixed(text, 32);
    }
    return out;
}

fn free_tx(allocator: std.mem.Allocator, tx: evm.BlockTx) void {
    allocator.free(tx.data);
    free_access(allocator, tx.access_list);
    if (tx.authorizations.len != 0) allocator.free(@constCast(tx.authorizations));
    if (tx.blob_versioned_hashes.len != 0) allocator.free(@constCast(tx.blob_versioned_hashes));
}

fn free_txs(allocator: std.mem.Allocator, txs: []evm.BlockTx) void {
    for (txs) |tx| free_tx(allocator, tx);
    if (txs.len != 0) allocator.free(txs);
}

fn decode_header(json: JsonHeader, extra_buf: *[limits.header_extra_bytes_max]u8) !header_mod.Header {
    const extra_n = try parse_hex_into(json.extraData, extra_buf);
    return .{
        .parent_hash = try parse_fixed(json.parentHash, 32),
        .ommers_hash = try first_hash(json.uncleHash, json.ommersHash, header_mod.empty_ommers_hash),
        .coinbase = try parse_address(first_text(json.coinbase, json.miner)),
        .state_root = try parse_fixed(json.stateRoot, 32),
        .transactions_root = try first_hash(json.transactionsTrie, json.transactionsRoot, trie_mod.empty_root),
        .receipts_root = try first_hash(json.receiptTrie, json.receiptsRoot, trie_mod.empty_root),
        .bloom = try parse_bloom(json),
        .difficulty = try parse_u256(json.difficulty),
        .number = try parse_u256(json.number),
        .gas_limit = try parse_u256(json.gasLimit),
        .gas_used = try parse_u256(json.gasUsed),
        .timestamp = try parse_u256(json.timestamp),
        .extra = extra_buf[0..extra_n],
        .prev_randao = try parse_fixed(json.mixHash, 32),
        .nonce = try parse_fixed(json.nonce, 8),
        .base_fee = try parse_u256(json.baseFeePerGas),
        .withdrawals_root = try hash_or(json.withdrawalsRoot, trie_mod.empty_root),
        .blob_gas_used = try parse_u256(json.blobGasUsed),
        .excess_blob_gas = try parse_u256(json.excessBlobGas),
        .parent_beacon_root = try hash_or(json.parentBeaconBlockRoot, @splat(0)),
        .requests_hash = try hash_or(json.requestsHash, header_mod.empty_requests_hash),
    };
}

fn parse_bloom(json: JsonHeader) ![256]u8 {
    const text = first_text(json.bloom, json.logsBloom);
    if (is_blank_hex(text)) return @splat(0);
    return parse_fixed(text, 256);
}

fn check_state_root(allocator: std.mem.Allocator, world: *const world_mod.World, want: [32]u8) !void {
    if (std.mem.allEqual(u8, &want, 0)) return;
    const trie = try allocator.create(trie_mod.Trie);
    defer allocator.destroy(trie);
    trie.reset();
    const got = try trie.world_root(world);
    if (!std.mem.eql(u8, &got, &want)) return error.StateRootMismatch;
}

fn check_header_hash(text: []const u8, got: [32]u8) !void {
    const want = parse_root(text) orelse return;
    if (!std.mem.eql(u8, &want, &got)) return error.HeaderHashMismatch;
}

fn fixture_fork(name: []const u8) ?evm.Fork {
    if (evm.Fork.from_name(name)) |fork| return fork;
    const pre_prague = [_][]const u8{
        "frontier", "homestead", "byzantium", "constantinople", "petersburg",
        "istanbul", "berlin",    "london",    "paris",          "merge",
        "shanghai", "cancun",
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

fn check_state(world: *const world_mod.World, expected: *const std.json.ArrayHashMap(JsonAccount)) !void {
    var it = expected.map.iterator();
    while (it.next()) |kv| {
        try check_account(world, kv.key_ptr.*, kv.value_ptr);
    }
}

fn check_account(world: *const world_mod.World, addr_text: []const u8, account: *const JsonAccount) !void {
    const addr = try parse_address(addr_text);
    if (world.get_nonce(addr) != try parse_u64(account.nonce)) return error.NonceMismatch;
    if (world.get_balance(addr) != try parse_u256(account.balance)) return error.BalanceMismatch;
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
    const pk = try parse_fixed(tx.secretKey, 32);
    return address_from_key(pk) orelse error.BadSecretKey;
}

fn call_target(to: ?[]const u8) !?u256 {
    const text = to orelse return null;
    if (is_blank_hex(text)) return null;
    return try parse_address(text);
}

fn parse_access(allocator: std.mem.Allocator, tuples: []const JsonAccess) ![]evm.AccessListItem {
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
        items[index] = .{ .address = try parse_address(tuple.address), .keys = keys };
        filled = index + 1;
    }
    return items;
}

fn free_access(allocator: std.mem.Allocator, items: []const evm.AccessListItem) void {
    if (items.len == 0) return;
    for (items) |item| allocator.free(@constCast(item.keys));
    allocator.free(@constCast(items));
}

fn parse_auths(allocator: std.mem.Allocator, list: []const JsonAuth) ![]evm.Authorization {
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

fn tx_gas_price(tx: JsonTx, base_fee: u256) !u256 {
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

fn first_text(a: []const u8, b: []const u8) []const u8 {
    if (!is_blank_hex(a)) return a;
    return b;
}

fn hash_or(text: []const u8, fallback: [32]u8) ![32]u8 {
    if (is_blank_hex(text)) return fallback;
    return parse_fixed(text, 32);
}

fn first_hash(a: []const u8, b: []const u8, fallback: [32]u8) ![32]u8 {
    if (!is_blank_hex(a)) return parse_fixed(a, 32);
    if (!is_blank_hex(b)) return parse_fixed(b, 32);
    return fallback;
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

fn parse_fixed(text: []const u8, comptime n: u32) ![n]u8 {
    var raw: [n]u8 = @splat(0);
    const got = try parse_hex_into(text, &raw);
    if (got == n) return raw;
    if (got > n) return error.InvalidHex;
    var padded: [n]u8 = @splat(0);
    if (got != 0) @memcpy(padded[n - got ..], raw[0..got]);
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

fn parse_root(text: []const u8) ?[32]u8 {
    const hex = strip0x(text);
    if (hex.len != 64) return null;
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch return null;
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
    \\"network":"Osaka",
    \\"genesisBlockHeader":{"parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","uncleHash":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","coinbase":"0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba","stateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","gasLimit":"0x2fefd8","gasUsed":"0x00","number":"0x00","timestamp":"0x00","extraData":"0x","mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x0000000000000000","baseFeePerGas":"0x0a","withdrawalsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"},
    \\"pre":{
    \\"0x095e7baea6a6c7c4c2dfeb977efac326af552d87":{"balance":"0x0de0b6b3a7640000","code":"0x600160010160005500","nonce":"0x00","storage":{}},
    \\"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b":{"balance":"0x0de0b6b3a7640000","code":"0x","nonce":"0x00","storage":{}}
    \\},
    \\"blocks":[{"blockHeader":{"parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","uncleHash":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","coinbase":"0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba","stateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","gasLimit":"0x2fefd8","gasUsed":"0x00","number":"0x01","timestamp":"0x03e8","extraData":"0x","mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x0000000000000000","baseFeePerGas":"0x0a","withdrawalsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"},"transactions":[{"sender":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b","to":"0x095e7baea6a6c7c4c2dfeb977efac326af552d87","data":"0x","gasLimit":"0x061a80","gasPrice":"0x0a","value":"0x0186a0","secretKey":"0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8"}]}],
    \\"postState":{"0x095e7baea6a6c7c4c2dfeb977efac326af552d87":{"balance":"0x0de0b6b3a76586a0","code":"0x600160010160005500","nonce":"0x00","storage":{"0x00":"0x02"}}},
    \\"config":{"chainid":"0x01"}
    \\}}
;

test "add11 blockchain post.state storage is 2" {
    const summary = try with_writer(add11_json, .osaka);
    try std.testing.expectEqual(@as(u32, 1), summary.passed);
    try std.testing.expectEqual(@as(u32, 0), summary.failed);
}

test "osaka-only blockchain fixture skips on prague" {
    const summary = try with_writer(add11_json, .prague);
    try std.testing.expectEqual(@as(u32, 1), summary.skipped);
    try std.testing.expectEqual(@as(u32, 0), summary.passed);
}

test "expectException blockchain tests are skipped" {
    const json =
        \\{"bad":{"network":"Osaka","genesisBlockHeader":{"number":"0x00","gasLimit":"0x01","timestamp":"0x01","stateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000"},"pre":{"0x01":{"balance":"0x01","code":"0x","nonce":"0x00","storage":{}}},"blocks":[{"expectException":"BlockException.RLP"}],"config":{"chainid":"0x01"}}}
    ;
    const summary = try with_writer(json, .osaka);
    try std.testing.expectEqual(@as(u32, 1), summary.skipped);
}
