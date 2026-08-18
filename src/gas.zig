const std = @import("std");

pub const Gas = struct {
    limit: u64,
    used: u64,

    pub fn init(limit: u64) Gas {
        return .{ .limit = limit, .used = 0 };
    }

    pub fn remaining(self: *const Gas) u64 {
        std.debug.assert(self.used <= self.limit);
        return self.limit - self.used;
    }

    pub fn consume(self: *Gas, amount: u64) !void {
        std.debug.assert(amount >= 0);
        const sum = @addWithOverflow(self.used, amount);
        if (sum[1] == 1) return error.OutOfGas;
        if (sum[0] > self.limit) return error.OutOfGas;
        self.used = sum[0];
        std.debug.assert(self.used <= self.limit);
    }

    pub fn consume_memory(self: *Gas, active_bytes: u32, new_bytes: u32) !void {
        std.debug.assert(new_bytes >= active_bytes);
        const old_words = (active_bytes + 31) / 32;
        const new_words = (new_bytes + 31) / 32;
        if (new_words <= old_words) return;
        const delta_words = new_words - old_words;
        const linear = @as(u64, delta_words) * 3;
        const quadratic = (@as(u64, new_words) * @as(u64, new_words)) / 512;
        try self.consume(linear + quadratic);
    }

    pub fn consume_copy(self: *Gas, length: u32) !void {
        const words = (length + 31) / 32;
        try self.consume(@as(u64, words) * 3);
    }

    pub fn refund(self: *Gas, amount: u64) void {
        std.debug.assert(amount <= self.used);
        self.used -= amount;
        std.debug.assert(self.used <= self.limit);
    }
};

pub const gas_cold_account: u64 = 2600;
pub const gas_warm_access: u64 = 100;
pub const gas_call_value: u64 = 9000;
pub const gas_call_stipend: u64 = 2300;
pub const gas_new_account: u64 = 25000;
pub const gas_create_base: u64 = 32000;
pub const gas_code_deposit: u64 = 200;
pub const gas_init_code_word: u64 = 2;
pub const gas_ecrecover: u64 = 3000;
pub const gas_sha256_base: u64 = 60;
pub const gas_sha256_word: u64 = 12;
pub const gas_identity_base: u64 = 15;
pub const gas_identity_word: u64 = 3;
pub const gas_log_data: u64 = 8;

pub const MessageCallGas = struct {
    cost: u64,
    sub_call: u64,
};

/// EIP-150: at most 63/64 of remaining gas may be forwarded.
pub fn max_message_call_gas(gas: u64) u64 {
    return gas - (gas / 64);
}

/// EELS `calculate_message_call_gas`.
pub fn calculate_message_call_gas(
    value: u256,
    requested: u64,
    gas_left: u64,
    memory_cost: u64,
    extra_gas: u64,
) MessageCallGas {
    const stipend: u64 = if (value == 0) 0 else gas_call_stipend;
    if (gas_left < extra_gas + memory_cost) {
        return .{ .cost = requested + extra_gas, .sub_call = requested + stipend };
    }
    const forwarded = @min(requested, max_message_call_gas(gas_left - memory_cost - extra_gas));
    return .{ .cost = forwarded + extra_gas, .sub_call = forwarded + stipend };
}

test "gas consume" {
    var gas = Gas.init(1000);
    try gas.consume(100);
    try std.testing.expectEqual(@as(u64, 900), gas.remaining());
}
