//! Account, storage, and revert journal. No allocation after `World.init`.

const std = @import("std");
const limits = @import("limits.zig");

pub const Account = struct {
    address: u256,
    balance: u256,
    nonce: u64,
    code_off: u32,
    code_len: u32,
};

pub const StorageSlot = struct {
    address: u256,
    key: u256,
    value: u256,
};

const JournalOp = enum(u8) {
    balance,
    nonce,
    code,
    storage,
    transient,
    created,
};

const JournalEntry = struct {
    op: JournalOp,
    address: u256,
    key: u256,
    prev_u256: u256,
    prev_u32_a: u32,
    prev_u32_b: u32,
};

pub const World = struct {
    accounts: [limits.accounts_max]Account,
    account_count: u32,
    slots: [limits.storage_slots_max]StorageSlot,
    slot_count: u32,
    transient: [limits.storage_slots_max]StorageSlot,
    transient_count: u32,
    code: [limits.code_pool_bytes_max]u8,
    code_used: u32,
    journal: [limits.journal_entries_max]JournalEntry,
    journal_count: u32,

    pub fn init(self: *World) void {
        self.account_count = 0;
        self.slot_count = 0;
        self.transient_count = 0;
        self.code_used = 0;
        self.journal_count = 0;
    }

    pub fn mark(self: *const World) u32 {
        return self.journal_count;
    }

    pub fn rollback(self: *World, journal_mark: u32) void {
        std.debug.assert(journal_mark <= self.journal_count);
        var index = self.journal_count;
        while (index > journal_mark) {
            index -= 1;
            self.undo(self.journal[index]);
        }
        self.journal_count = journal_mark;
    }

    pub fn get_account(self: *const World, address: u256) ?Account {
        const index = self.find_account(address) orelse return null;
        return self.accounts[index];
    }

    pub fn get_balance(self: *const World, address: u256) u256 {
        const account = self.get_account(address) orelse return 0;
        return account.balance;
    }

    pub fn get_nonce(self: *const World, address: u256) u64 {
        const account = self.get_account(address) orelse return 0;
        return account.nonce;
    }

    pub fn code_of(self: *const World, address: u256) []const u8 {
        const account = self.get_account(address) orelse return &[_]u8{};
        return self.code[account.code_off .. account.code_off + account.code_len];
    }

    pub fn is_alive(self: *const World, address: u256) bool {
        const account = self.get_account(address) orelse return false;
        return account.nonce > 0 or account.balance > 0 or account.code_len > 0;
    }

    pub fn touch(self: *World, address: u256) !void {
        _ = try self.ensure_account(address);
    }

    pub fn set_balance(self: *World, address: u256, value: u256) !void {
        const index = try self.ensure_account(address);
        try self.push_journal(.{
            .op = .balance,
            .address = address,
            .key = 0,
            .prev_u256 = self.accounts[index].balance,
            .prev_u32_a = 0,
            .prev_u32_b = 0,
        });
        self.accounts[index].balance = value;
    }

    pub fn set_nonce(self: *World, address: u256, nonce: u64) !void {
        const index = try self.ensure_account(address);
        try self.push_journal(.{
            .op = .nonce,
            .address = address,
            .key = 0,
            .prev_u256 = self.accounts[index].nonce,
            .prev_u32_a = 0,
            .prev_u32_b = 0,
        });
        self.accounts[index].nonce = nonce;
    }

    pub fn increment_nonce(self: *World, address: u256) !void {
        const nonce = self.get_nonce(address);
        if (nonce == std.math.maxInt(u64)) return error.NonceOverflow;
        try self.set_nonce(address, nonce + 1);
    }

    pub fn set_code(self: *World, address: u256, code: []const u8) !void {
        std.debug.assert(code.len <= limits.forge_code_bytes_max);
        const index = try self.ensure_account(address);
        try self.push_journal(.{
            .op = .code,
            .address = address,
            .key = 0,
            .prev_u256 = 0,
            .prev_u32_a = self.accounts[index].code_off,
            .prev_u32_b = self.accounts[index].code_len,
        });
        const off = self.code_used;
        const len: u32 = @intCast(code.len);
        if (off + len > limits.code_pool_bytes_max) return error.CodePoolFull;
        @memcpy(self.code[off .. off + len], code);
        self.code_used = off + len;
        self.accounts[index].code_off = off;
        self.accounts[index].code_len = len;
    }

    pub fn move_ether(self: *World, from: u256, to: u256, value: u256) !void {
        if (value == 0) return;
        const sender = self.get_balance(from);
        if (sender < value) return error.InsufficientFunds;
        try self.set_balance(from, sender - value);
        const dest = self.get_balance(to);
        try self.set_balance(to, dest + value);
    }

    pub fn destroy_account(self: *World, address: u256) !void {
        try self.set_balance(address, 0);
        try self.set_nonce(address, 0);
        try self.set_code(address, &[_]u8{});
        var index: u32 = 0;
        while (index < self.slot_count) : (index += 1) {
            const slot = self.slots[index];
            if (slot.address == address and slot.value != 0) {
                try self.store(address, slot.key, 0);
            }
        }
    }

    pub fn load(self: *const World, address: u256, key: u256) u256 {
        return load_slot(&self.slots, self.slot_count, address, key);
    }

    pub fn store(self: *World, address: u256, key: u256, value: u256) !void {
        try self.write_slot(&self.slots, &self.slot_count, .storage, address, key, value);
    }

    pub fn tload(self: *const World, address: u256, key: u256) u256 {
        return load_slot(&self.transient, self.transient_count, address, key);
    }

    pub fn tstore(self: *World, address: u256, key: u256, value: u256) !void {
        try self.write_slot(&self.transient, &self.transient_count, .transient, address, key, value);
    }

    fn write_slot(
        self: *World,
        slots: *[limits.storage_slots_max]StorageSlot,
        count: *u32,
        op: JournalOp,
        address: u256,
        key: u256,
        value: u256,
    ) !void {
        const prev = load_slot(slots, count.*, address, key);
        try self.push_journal(.{
            .op = op,
            .address = address,
            .key = key,
            .prev_u256 = prev,
            .prev_u32_a = 0,
            .prev_u32_b = 0,
        });
        var index: u32 = 0;
        while (index < count.*) : (index += 1) {
            if (slots[index].address == address and slots[index].key == key) {
                slots[index].value = value;
                return;
            }
        }
        if (count.* >= limits.storage_slots_max) return error.StorageFull;
        slots[count.*] = .{ .address = address, .key = key, .value = value };
        count.* += 1;
    }

    fn load_slot(slots: []const StorageSlot, count: u32, address: u256, key: u256) u256 {
        var index: u32 = 0;
        while (index < count) : (index += 1) {
            if (slots[index].address == address and slots[index].key == key) return slots[index].value;
        }
        return 0;
    }

    fn find_account(self: *const World, address: u256) ?u32 {
        var index: u32 = 0;
        while (index < self.account_count) : (index += 1) {
            if (self.accounts[index].address == address) return index;
        }
        return null;
    }

    fn ensure_account(self: *World, address: u256) !u32 {
        if (self.find_account(address)) |index| return index;
        if (self.account_count >= limits.accounts_max) return error.AccountLimit;
        try self.push_journal(.{
            .op = .created,
            .address = address,
            .key = 0,
            .prev_u256 = 0,
            .prev_u32_a = 0,
            .prev_u32_b = 0,
        });
        const index = self.account_count;
        self.accounts[index] = .{
            .address = address,
            .balance = 0,
            .nonce = 0,
            .code_off = 0,
            .code_len = 0,
        };
        self.account_count += 1;
        return index;
    }

    pub const SlotDiff = struct {
        address: u256,
        key: u256,
        before: u256,
        after: u256,
        transient: bool,
    };

    /// First journal write supplies `before`; `after` is the live slot value.
    pub fn collect_slot_diffs(self: *const World, out: []SlotDiff) u32 {
        var n: u32 = 0;
        var i: u32 = 0;
        while (i < self.journal_count) : (i += 1) {
            const entry = self.journal[i];
            if (entry.op != .storage and entry.op != .transient) continue;
            const transient = entry.op == .transient;
            if (find_diff(out[0..n], entry.address, entry.key, transient) != null) continue;
            if (n >= out.len) break;
            const after = if (transient)
                self.tload(entry.address, entry.key)
            else
                self.load(entry.address, entry.key);
            out[n] = .{
                .address = entry.address,
                .key = entry.key,
                .before = entry.prev_u256,
                .after = after,
                .transient = transient,
            };
            n += 1;
        }
        return n;
    }

    fn push_journal(self: *World, entry: JournalEntry) !void {
        if (self.journal_count >= limits.journal_entries_max) return error.JournalFull;
        self.journal[self.journal_count] = entry;
        self.journal_count += 1;
    }

    fn undo(self: *World, entry: JournalEntry) void {
        switch (entry.op) {
            .created => {
                std.debug.assert(self.account_count > 0);
                std.debug.assert(self.accounts[self.account_count - 1].address == entry.address);
                self.account_count -= 1;
            },
            .balance => {
                const index = self.find_account(entry.address) orelse return;
                self.accounts[index].balance = entry.prev_u256;
            },
            .nonce => {
                const index = self.find_account(entry.address) orelse return;
                self.accounts[index].nonce = @intCast(entry.prev_u256);
            },
            .code => {
                const index = self.find_account(entry.address) orelse return;
                self.accounts[index].code_off = entry.prev_u32_a;
                self.accounts[index].code_len = entry.prev_u32_b;
            },
            .storage => undo_slot(&self.slots, &self.slot_count, entry),
            .transient => undo_slot(&self.transient, &self.transient_count, entry),
        }
    }
};

fn find_diff(diffs: []const World.SlotDiff, address: u256, key: u256, transient: bool) ?u32 {
    var index: u32 = 0;
    while (index < diffs.len) : (index += 1) {
        if (diffs[index].address == address and diffs[index].key == key and diffs[index].transient == transient) {
            return index;
        }
    }
    return null;
}

fn undo_slot(slots: *[limits.storage_slots_max]StorageSlot, count: *u32, entry: JournalEntry) void {
    var index: u32 = 0;
    while (index < count.*) : (index += 1) {
        if (slots[index].address == entry.address and slots[index].key == entry.key) {
            slots[index].value = entry.prev_u256;
            return;
        }
    }
}

test "world store load rollback" {
    var world: World = undefined;
    world.init();
    try world.store(1, 7, 42);
    try std.testing.expectEqual(@as(u256, 42), world.load(1, 7));
    const snap = world.mark();
    try world.store(1, 7, 99);
    try std.testing.expectEqual(@as(u256, 99), world.load(1, 7));
    world.rollback(snap);
    try std.testing.expectEqual(@as(u256, 42), world.load(1, 7));
    var diffs: [8]World.SlotDiff = undefined;
    const n = world.collect_slot_diffs(&diffs);
    try std.testing.expectEqual(@as(u32, 1), n);
    try std.testing.expectEqual(@as(u256, 0), diffs[0].before);
    try std.testing.expectEqual(@as(u256, 42), diffs[0].after);
}

test "world ether move" {
    var world: World = undefined;
    world.init();
    try world.set_balance(1, 50);
    try world.move_ether(1, 2, 20);
    try std.testing.expectEqual(@as(u256, 30), world.get_balance(1));
    try std.testing.expectEqual(@as(u256, 20), world.get_balance(2));
}
