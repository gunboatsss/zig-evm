//! Check-time Merkle Patricia trie. Snapshot `World`, sort keccak keys, fold.

const std = @import("std");
const limits = @import("limits.zig");
const rlp = @import("rlp.zig");
const word = @import("u256.zig");
const world_mod = @import("world.zig");

/// keccak256(rlp("")) — empty trie root.
pub const empty_root = hex32("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");
/// keccak256("").
pub const empty_code_hash = hex32("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

const Leaf = struct {
    path: [64]u8,
    value_off: u32,
    value_len: u32,
};

const Kind = enum { leaf, ext, branch };

const Node = struct {
    kind: Kind,
    path: [64]u8,
    path_len: u32,
    value_off: u32,
    value_len: u32,
    children: [16]u32,
    ref: [32]u8,
    ref_len: u32,
};

pub const Trie = struct {
    leaves: [limits.trie_leaves_max]Leaf,
    leaf_count: u32,
    nodes: [limits.trie_nodes_max]Node,
    node_count: u32,
    values: [limits.trie_value_bytes_max]u8,
    value_used: u32,
    root: u32,

    pub fn reset(self: *Trie) void {
        self.leaf_count = 0;
        self.node_count = 1;
        self.value_used = 0;
        self.root = 0;
    }

    pub fn world_root(self: *Trie, world: *const world_mod.World) ![32]u8 {
        var account_i: u32 = 0;
        var state_n: u32 = 0;
        var state_keys: [limits.accounts_max][32]u8 = undefined;
        var state_vals: [limits.accounts_max]struct { off: u32, len: u32 } = undefined;
        var account_blob: [limits.trie_account_bytes_max]u8 = undefined;

        while (account_i < world.account_count) : (account_i += 1) {
            const account = world.accounts[account_i];
            if (!world.is_alive(account.address)) continue;
            const storage = try self.storage_root(world, account.address);
            const code = world.code_of(account.address);
            var code_hash: [32]u8 = empty_code_hash;
            if (code.len != 0) rlp.keccak(code, &code_hash);
            const acc_len = encode_account(&account_blob, account.nonce, account.balance, storage, code_hash);
            var addr_be: [32]u8 = undefined;
            word.to_bytes_be(account.address, &addr_be);
            // Yellow Paper: state keys are keccak256 of the 20-byte address.
            rlp.keccak(addr_be[12..32], &state_keys[state_n]);
            const off = try self.copy_value(account_blob[0..acc_len]);
            state_vals[state_n] = .{ .off = off, .len = acc_len };
            state_n += 1;
        }

        self.clear_tree();
        var i: u32 = 0;
        while (i < state_n) : (i += 1) {
            const v = state_vals[i];
            try self.push_leaf_off(state_keys[i], v.off, v.len);
        }
        return self.root_hash();
    }

    fn storage_root(self: *Trie, world: *const world_mod.World, address: u256) ![32]u8 {
        self.clear_tree();
        var index: u32 = 0;
        var slot_blob: [48]u8 = undefined;
        while (index < world.slot_count) : (index += 1) {
            const slot = world.slots[index];
            if (slot.address != address or slot.value == 0) continue;
            var key_be: [32]u8 = undefined;
            word.to_bytes_be(slot.key, &key_be);
            var hashed: [32]u8 = undefined;
            rlp.keccak(&key_be, &hashed);
            const n = rlp.uint(&slot_blob, slot.value);
            try self.push_leaf(hashed, slot_blob[0..n]);
        }
        return self.root_hash();
    }

    fn clear_tree(self: *Trie) void {
        self.leaf_count = 0;
        self.node_count = 1;
        self.root = 0;
    }

    fn push_leaf_off(self: *Trie, key: [32]u8, off: u32, len: u32) !void {
        if (self.leaf_count >= limits.trie_leaves_max) return error.TrieFull;
        var path: [64]u8 = undefined;
        to_nibbles(&key, &path);
        self.leaves[self.leaf_count] = .{
            .path = path,
            .value_off = off,
            .value_len = len,
        };
        self.leaf_count += 1;
    }

    fn push_leaf(self: *Trie, key: [32]u8, value: []const u8) !void {
        const off = try self.copy_value(value);
        try self.push_leaf_off(key, off, @intCast(value.len));
    }

    fn copy_value(self: *Trie, value: []const u8) !u32 {
        const off = self.value_used;
        if (off + value.len > limits.trie_value_bytes_max) return error.TrieFull;
        if (value.len != 0) @memcpy(self.values[off .. off + value.len], value);
        self.value_used = off + @as(u32, @intCast(value.len));
        return off;
    }

    fn root_hash(self: *Trie) error{TrieFull}![32]u8 {
        if (self.leaf_count == 0) return empty_root;
        sort_leaves(self.leaves[0..self.leaf_count]);
        dedup_leaves(&self.leaf_count, self.leaves[0..self.leaf_count]);
        self.root = try self.build(0, self.leaf_count, 0);
        return hash_ref(self.nodes[self.root]);
    }

    fn build(self: *Trie, lo: u32, hi: u32, key_off: u32) error{TrieFull}!u32 {
        std.debug.assert(key_off <= 64);
        std.debug.assert(lo < hi);
        if (lo + 1 == hi) {
            const leaf = self.leaves[lo];
            return self.new_leaf(leaf.path[key_off..64], leaf.value_off, leaf.value_len);
        }
        const shared = shared_prefix(self.leaves[lo].path, self.leaves[hi - 1].path, key_off);
        if (shared != 0) {
            const child = try self.build(lo, hi, key_off + shared);
            return self.new_ext(self.leaves[lo].path[key_off .. key_off + shared], child);
        }
        return self.new_branch(lo, hi, key_off);
    }

    fn new_branch(self: *Trie, lo: u32, hi: u32, key_off: u32) error{TrieFull}!u32 {
        var children: [16]u32 = @splat(0);
        var cursor = lo;
        var nibble: u32 = 0;
        while (nibble < 16) : (nibble += 1) {
            const start = cursor;
            while (cursor < hi and self.leaves[cursor].path[key_off] == nibble) cursor += 1;
            if (start == cursor) continue;
            children[nibble] = try self.build(start, cursor, key_off + 1);
        }
        std.debug.assert(cursor == hi);
        const idx = try self.alloc_node();
        self.nodes[idx] = .{
            .kind = .branch,
            .path = undefined,
            .path_len = 0,
            .value_off = 0,
            .value_len = 0,
            .children = children,
            .ref = undefined,
            .ref_len = 0,
        };
        self.seal(idx);
        return idx;
    }

    fn new_leaf(self: *Trie, path: []const u8, value_off: u32, value_len: u32) error{TrieFull}!u32 {
        const idx = try self.alloc_node();
        var stored: [64]u8 = undefined;
        std.debug.assert(path.len <= 64);
        if (path.len != 0) @memcpy(stored[0..path.len], path);
        self.nodes[idx] = .{
            .kind = .leaf,
            .path = stored,
            .path_len = @intCast(path.len),
            .value_off = value_off,
            .value_len = value_len,
            .children = @splat(0),
            .ref = undefined,
            .ref_len = 0,
        };
        self.seal(idx);
        return idx;
    }

    fn new_ext(self: *Trie, path: []const u8, child: u32) error{TrieFull}!u32 {
        const idx = try self.alloc_node();
        var stored: [64]u8 = undefined;
        std.debug.assert(path.len <= 64);
        if (path.len != 0) @memcpy(stored[0..path.len], path);
        var children: [16]u32 = @splat(0);
        children[0] = child;
        self.nodes[idx] = .{
            .kind = .ext,
            .path = stored,
            .path_len = @intCast(path.len),
            .value_off = 0,
            .value_len = 0,
            .children = children,
            .ref = undefined,
            .ref_len = 0,
        };
        self.seal(idx);
        return idx;
    }

    fn alloc_node(self: *Trie) error{TrieFull}!u32 {
        if (self.node_count >= limits.trie_nodes_max) return error.TrieFull;
        const idx = self.node_count;
        self.node_count += 1;
        return idx;
    }

    fn seal(self: *Trie, idx: u32) void {
        var payload: [limits.trie_node_bytes_max]u8 = undefined;
        const pay = self.encode_payload(idx, &payload);
        var encoded: [limits.trie_node_bytes_max]u8 = undefined;
        const n = rlp.list(encoded[0..], payload[0..pay]);
        if (n < 32) {
            self.nodes[idx].ref_len = n;
            @memcpy(self.nodes[idx].ref[0..n], encoded[0..n]);
        } else {
            self.nodes[idx].ref_len = 32;
            rlp.keccak(encoded[0..n], &self.nodes[idx].ref);
        }
    }

    fn encode_payload(self: *const Trie, idx: u32, out: *[limits.trie_node_bytes_max]u8) u32 {
        const node = self.nodes[idx];
        var n: u32 = 0;
        switch (node.kind) {
            .leaf => {
                var hp: [33]u8 = undefined;
                const hp_len = hex_prefix(node.path[0..node.path_len], true, &hp);
                n += rlp.bytes(out[n..], hp[0..hp_len]);
                n += rlp.bytes(out[n..], self.values[node.value_off .. node.value_off + node.value_len]);
            },
            .ext => {
                var hp: [33]u8 = undefined;
                const hp_len = hex_prefix(node.path[0..node.path_len], false, &hp);
                n += rlp.bytes(out[n..], hp[0..hp_len]);
                n += self.write_ref(out[n..], node.children[0]);
            },
            .branch => {
                var child_i: u32 = 0;
                while (child_i < 16) : (child_i += 1) {
                    n += self.write_ref(out[n..], node.children[child_i]);
                }
                out[n] = 0x80;
                n += 1;
            },
        }
        return n;
    }

    fn write_ref(self: *const Trie, out: []u8, child: u32) u32 {
        if (child == limits.trie_empty_child) {
            out[0] = 0x80;
            return 1;
        }
        const node = self.nodes[child];
        if (node.ref_len < 32) {
            @memcpy(out[0..node.ref_len], node.ref[0..node.ref_len]);
            return node.ref_len;
        }
        return rlp.bytes(out, node.ref[0..32]);
    }
};

fn hash_ref(node: Node) [32]u8 {
    if (node.ref_len == 32) return node.ref;
    var hash: [32]u8 = undefined;
    rlp.keccak(node.ref[0..node.ref_len], &hash);
    return hash;
}

fn to_nibbles(key: *const [32]u8, out: *[64]u8) void {
    var i: u32 = 0;
    while (i < 32) : (i += 1) {
        out[i * 2] = key[i] >> 4;
        out[i * 2 + 1] = key[i] & 0x0f;
    }
}

fn hex_prefix(nibbles: []const u8, terminator: bool, out: *[33]u8) u32 {
    const odd = nibbles.len % 2 == 1;
    var flags: u8 = 0;
    if (terminator) flags += 2;
    if (odd) flags += 1;
    if (odd) {
        out[0] = (flags << 4) | nibbles[0];
        return 1 + pack_nibbles(nibbles[1..], out[1..]);
    }
    out[0] = flags << 4;
    return 1 + pack_nibbles(nibbles, out[1..]);
}

fn pack_nibbles(nibbles: []const u8, out: []u8) u32 {
    var i: u32 = 0;
    var o: u32 = 0;
    while (i + 1 < nibbles.len) : (i += 2) {
        out[o] = (nibbles[i] << 4) | nibbles[i + 1];
        o += 1;
    }
    return o;
}

fn shared_prefix(a: [64]u8, b: [64]u8, off: u32) u32 {
    var n: u32 = 0;
    while (off + n < 64 and a[off + n] == b[off + n]) n += 1;
    return n;
}

fn sort_leaves(items: []Leaf) void {
    var i: u32 = 1;
    while (i < items.len) : (i += 1) {
        var j = i;
        while (j > 0 and path_less(items[j].path, items[j - 1].path)) {
            const tmp = items[j];
            items[j] = items[j - 1];
            items[j - 1] = tmp;
            j -= 1;
        }
    }
}

fn path_less(a: [64]u8, b: [64]u8) bool {
    var i: u32 = 0;
    while (i < 64) : (i += 1) {
        if (a[i] < b[i]) return true;
        if (a[i] > b[i]) return false;
    }
    return false;
}

fn dedup_leaves(count: *u32, items: []Leaf) void {
    if (count.* < 2) return;
    var w: u32 = 1;
    var r: u32 = 1;
    while (r < count.*) : (r += 1) {
        if (std.mem.eql(u8, &items[r].path, &items[w - 1].path)) {
            items[w - 1] = items[r];
            continue;
        }
        if (w != r) items[w] = items[r];
        w += 1;
    }
    count.* = w;
}

fn encode_account(
    out: *[limits.trie_account_bytes_max]u8,
    nonce: u64,
    balance: u256,
    storage_root: [32]u8,
    code_hash: [32]u8,
) u32 {
    var payload: [limits.trie_account_bytes_max]u8 = undefined;
    var n: u32 = 0;
    n += rlp.uint(payload[n..], nonce);
    n += rlp.uint(payload[n..], balance);
    n += rlp.bytes(payload[n..], &storage_root);
    n += rlp.bytes(payload[n..], &code_hash);
    return rlp.list(out, payload[0..n]);
}

fn hex32(text: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;
    return out;
}

test "empty trie root" {
    var encoded: [1]u8 = undefined;
    _ = rlp.bytes(&encoded, &[_]u8{});
    var hash: [32]u8 = undefined;
    rlp.keccak(&encoded, &hash);
    try std.testing.expectEqualSlices(u8, &empty_root, &hash);
}

test "empty world root is empty trie" {
    var world: world_mod.World = undefined;
    world.init();
    const trie = try std.testing.allocator.create(Trie);
    defer std.testing.allocator.destroy(trie);
    trie.reset();
    const root = try trie.world_root(&world);
    try std.testing.expectEqualSlices(u8, &empty_root, &root);
}

test "nonce-1 eoa has a nonempty state root" {
    var world: world_mod.World = undefined;
    world.init();
    try world.set_nonce(1, 1);
    const trie = try std.testing.allocator.create(Trie);
    defer std.testing.allocator.destroy(trie);
    trie.reset();
    const root = try trie.world_root(&world);
    try std.testing.expect(!std.mem.eql(u8, &root, &empty_root));
}
