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
        try self.consume(memory_expansion_gas(active_bytes, new_bytes));
    }

    pub fn consume_copy(self: *Gas, length: u32) !void {
        try self.consume(try copy_words_gas(@as(u256, length)));
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
pub const gas_selfdestruct: u64 = 5000;
pub const gas_selfdestruct_new_account: u64 = 25000;
pub const gas_code_deposit: u64 = 200;
pub const gas_init_code_word: u64 = 2;
/// EIP-160: extra EXP cost per byte of the exponent.
pub const gas_exp_byte: u64 = 50;
pub const gas_ecrecover: u64 = 3000;
pub const gas_sha256_base: u64 = 60;
pub const gas_sha256_word: u64 = 12;
pub const gas_identity_base: u64 = 15;
pub const gas_identity_word: u64 = 3;
/// EIP-2565 minimum (Prague and earlier).
pub const gas_modexp_min_prague: u64 = 200;
/// EIP-7883 minimum (Osaka).
pub const gas_modexp_min_osaka: u64 = 500;
/// EIP-7951 `P256VERIFY`.
pub const gas_p256verify: u64 = 6900;
pub const gas_log_data: u64 = 8;
pub const gas_tx: u64 = 21_000;
pub const gas_tx_data_zero: u64 = 4;
pub const gas_tx_data_nonzero: u64 = 16;
pub const gas_tx_data_floor_token: u64 = 10;
pub const gas_tx_access_list_address: u64 = 2400;
pub const gas_tx_access_list_storage_key: u64 = 1900;
/// EIP-7702 `PER_EMPTY_ACCOUNT_COST`. Charged once per authorization.
pub const gas_auth_per_empty: u64 = 25_000;
/// EIP-7702 `PER_AUTH_BASE_COST`. Refunded when the authority already exists.
pub const gas_auth_base: u64 = 12_500;
pub const gas_cold_sload: u64 = 2100;
pub const gas_sstore_set: u64 = 20_000;
/// `COLD_STORAGE_WRITE - COLD_STORAGE_ACCESS` (EIP-2200/2929).
pub const gas_sstore_reset: u64 = 2_900;
pub const gas_refund_sstore_clear: i64 = 4_800;

pub const TxFees = struct {
    effective: u256,
    priority: u256,
};

pub fn fees_from_prices(gas_price: u256, base_fee: u256) TxFees {
    const priority: u256 = if (gas_price > base_fee) gas_price - base_fee else 0;
    return .{ .effective = gas_price, .priority = priority };
}

pub fn intrinsic_gas(data: []const u8, is_create: bool) u64 {
    var gas: u64 = gas_tx;
    if (is_create) {
        gas += gas_create_base;
        gas += gas_init_code_word * @as(u64, (data.len + 31) / 32);
    }
    for (data) |byte| {
        gas += if (byte == 0) gas_tx_data_zero else gas_tx_data_nonzero;
    }
    return gas;
}

/// EIP-7623 floor: `21000 + 10 * (zero_bytes + 4 * nonzero_bytes)`.
pub fn calldata_floor_gas(data: []const u8) u64 {
    var tokens: u64 = 0;
    for (data) |byte| {
        tokens += if (byte == 0) 1 else 4;
    }
    return gas_tx + tokens * gas_tx_data_floor_token;
}

pub fn memory_gas_cost(size: u32) u64 {
    const words: u64 = (size + 31) / 32;
    return words * 3 + (words * words) / 512;
}

pub fn memory_expansion_gas(old_size: u32, new_size: u32) u64 {
    std.debug.assert(new_size >= old_size);
    return memory_gas_cost(new_size) - memory_gas_cost(old_size);
}

/// Copy cost `3 * ceil32(length) / 32`. Huge lengths are OutOfGas.
pub fn copy_words_gas(length: u256) !u64 {
    if (length == 0) return 0;
    if (length > std.math.maxInt(u64) - 31) return error.OutOfGas;
    const len: u64 = @intCast(length);
    const words = (len + 31) / 32;
    const product = @mulWithOverflow(words, 3);
    if (product[1] == 1) return error.OutOfGas;
    return product[0];
}

pub fn access_list_gas(address_count: u64, key_count: u64) u64 {
    return address_count * gas_tx_access_list_address + key_count * gas_tx_access_list_storage_key;
}

/// Execution gas after EIP-3529 refund (capped at 1/5 of used) and EIP-7623 floor.
pub fn settled_gas_used(gas_limit: u64, remaining: u64, refund_counter: i64, floor: u64) u64 {
    std.debug.assert(remaining <= gas_limit);
    var used = gas_limit - remaining;
    const positive: u64 = if (refund_counter > 0) @intCast(refund_counter) else 0;
    used -= @min(positive, used / 5);
    return @max(used, floor);
}

pub const SstoreCharge = struct {
    cost: u64,
    refund_delta: i64,
};

/// EIP-2200/2929/3529 `SSTORE` (EELS Osaka `sstore`).
pub fn sstore_gas(original: u256, current: u256, new_value: u256, cold: bool) SstoreCharge {
    var cost: u64 = 0;
    if (cold) cost += gas_cold_sload;
    if (original == current and current != new_value) {
        cost += if (original == 0) gas_sstore_set else gas_sstore_reset;
    } else {
        cost += gas_warm_access;
    }
    var refund_delta: i64 = 0;
    if (current != new_value) {
        if (original != 0 and current != 0 and new_value == 0) refund_delta += gas_refund_sstore_clear;
        if (original != 0 and current == 0) refund_delta -= gas_refund_sstore_clear;
        if (original == new_value) {
            refund_delta += if (original == 0)
                @as(i64, @intCast(gas_sstore_set - gas_warm_access))
            else
                @as(i64, @intCast(gas_sstore_reset - gas_warm_access));
        }
    }
    return .{ .cost = cost, .refund_delta = refund_delta };
}

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

test "intrinsic gas empty call" {
    try std.testing.expectEqual(@as(u64, 21_000), intrinsic_gas(&[_]u8{}, false));
}

test "intrinsic gas create adds 32000" {
    try std.testing.expectEqual(@as(u64, 53_000), intrinsic_gas(&[_]u8{}, true));
}

test "calldata floor empty is 21000" {
    try std.testing.expectEqual(@as(u64, 21_000), calldata_floor_gas(&[_]u8{}));
}

test "sstore gas cold set from zero" {
    const charge = sstore_gas(0, 0, 1, true);
    try std.testing.expectEqual(@as(u64, 22_100), charge.cost);
    try std.testing.expectEqual(@as(i64, 0), charge.refund_delta);
}

test "sstore gas cold clear" {
    const charge = sstore_gas(1, 1, 0, true);
    try std.testing.expectEqual(@as(u64, 5_000), charge.cost);
    try std.testing.expectEqual(@as(i64, 4_800), charge.refund_delta);
}

test "settled gas used refunds at most one fifth" {
    try std.testing.expectEqual(@as(u64, 21_206), settled_gas_used(100_000, 73_994, 4_800, 21_000));
}

test "memory expansion gas is cost difference" {
    try std.testing.expectEqual(@as(u64, 3), memory_expansion_gas(0, 32));
    const first = memory_gas_cost(32);
    const second = memory_gas_cost(64);
    try std.testing.expectEqual(second - first, memory_expansion_gas(32, 64));
}

test "copy words gas zero is zero" {
    try std.testing.expectEqual(@as(u64, 0), try copy_words_gas(0));
    try std.testing.expectEqual(@as(u64, 3), try copy_words_gas(1));
}
