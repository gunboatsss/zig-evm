const std = @import("std");
const limits = @import("limits.zig");

pub const Storage = struct {
    keys: [limits.storage_slots_max]u256,
    values: [limits.storage_slots_max]u256,
    count: u32,

    pub fn init() Storage {
        return .{
            .keys = undefined,
            .values = undefined,
            .count = 0,
        };
    }

    pub fn load(self: *Storage, key: u256) u256 {
        var index: u32 = 0;
        while (index < self.count) : (index += 1) {
            if (self.keys[index] == key) return self.values[index];
        }
        return 0;
    }

    pub fn store(self: *Storage, key: u256, value: u256) !void {
        var index: u32 = 0;
        while (index < self.count) : (index += 1) {
            if (self.keys[index] == key) {
                self.values[index] = value;
                return;
            }
        }
        if (self.count >= limits.storage_slots_max) return error.StorageFull;
        self.keys[self.count] = key;
        self.values[self.count] = value;
        self.count += 1;
        std.debug.assert(self.count <= limits.storage_slots_max);
    }
};

pub const ExecutionContext = struct {
    address: u256,
    caller: u256,
    call_value: u256,
    origin: u256,
    gas_price: u256,
    coinbase: u256,
    timestamp: u256,
    number: u256,
    prev_randao: u256,
    gas_limit: u256,
    chain_id: u256,
    base_fee: u256,
    blob_base_fee: u256,
    slot_number: u256,

    pub fn default() ExecutionContext {
        return .{
            .address = 0,
            .caller = 0,
            .call_value = 0,
            .origin = 0,
            .gas_price = 0,
            .coinbase = 0,
            .timestamp = 1_700_000_000,
            .number = 1,
            .prev_randao = 0,
            .gas_limit = 30_000_000,
            .chain_id = 1,
            .base_fee = 1_000_000_000,
            .blob_base_fee = 1,
            .slot_number = 0,
        };
    }
};
