//! MODEXP precompile at `0x05` (EIP-198 / EIP-2565 / EIP-7823 / EIP-7883).

const std = @import("std");
const gas_mod = @import("gas.zig");
const limits = @import("limits.zig");
const word = @import("u256.zig");
const fork_mod = @import("fork.zig");

const Limb = std.math.big.Limb;
const Mutable = std.math.big.int.Mutable;
const Managed = std.math.big.int.Managed;
const Fork = fork_mod.Fork;

const max_len: u32 = limits.modexp_len_bytes_max;
const max_limbs = std.math.big.int.calcTwosCompLimbCount(max_len * 8);

pub fn gas_cost(input: []const u8, fork: Fork) error{OutOfGas}!u64 {
    const base_len = read_u256(input, 0);
    const exp_len = read_u256(input, 32);
    const mod_len = read_u256(input, 64);
    if (fork.at_least(.osaka) and (base_len > max_len or exp_len > max_len or mod_len > max_len))
        return error.OutOfGas;
    const floor: u64 = if (fork.at_least(.osaka)) gas_mod.gas_modexp_min_osaka else gas_mod.gas_modexp_min_prague;
    // Pre-Osaka complexity is `words²` with words=0, so gas is always the floor
    // even when `exp_len` is huge. Osaka uses a 16-word floor instead, so the
    // iteration count still matters (`zero-length-base-mod` is 4064, not 500).
    if (base_len == 0 and mod_len == 0 and !fork.at_least(.osaka)) return floor;
    if (base_len > std.math.maxInt(u32) or exp_len > std.math.maxInt(u32) or mod_len > std.math.maxInt(u32))
        return std.math.maxInt(u64);
    const header = Header{
        .base_len = @intCast(base_len),
        .exp_len = @intCast(exp_len),
        .mod_len = @intCast(mod_len),
    };
    const head = exponent_head(input, header);
    return price(header.base_len, header.mod_len, header.exp_len, head, fork);
}

pub fn execute(input: []const u8, out: []u8, fork: Fork) error{ OutOfGas, OutputTooLarge }!u32 {
    const base_len = read_u256(input, 0);
    const exp_len = read_u256(input, 32);
    const mod_len = read_u256(input, 64);
    if (fork.at_least(.osaka) and (base_len > max_len or exp_len > max_len or mod_len > max_len))
        return error.OutOfGas;
    if (base_len == 0 and mod_len == 0) return 0;
    if (base_len > max_len or exp_len > max_len or mod_len > max_len) return error.OutOfGas;
    const header = Header{
        .base_len = @intCast(base_len),
        .exp_len = @intCast(exp_len),
        .mod_len = @intCast(mod_len),
    };
    if (header.mod_len > out.len) return error.OutputTooLarge;

    var base_buf: [max_len]u8 = undefined;
    var exp_buf: [max_len]u8 = undefined;
    var mod_buf: [max_len]u8 = undefined;
    buffer_read(input, 96, header.base_len, base_buf[0..header.base_len]);
    buffer_read(input, 96 + header.base_len, header.exp_len, exp_buf[0..header.exp_len]);
    buffer_read(
        input,
        96 + header.base_len + header.exp_len,
        header.mod_len,
        mod_buf[0..header.mod_len],
    );

    if (is_zero(mod_buf[0..header.mod_len])) {
        @memset(out[0..header.mod_len], 0);
        return header.mod_len;
    }

    var scratch: [limits.modexp_scratch_bytes_max]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    powmod(
        fba.allocator(),
        base_buf[0..header.base_len],
        exp_buf[0..header.exp_len],
        mod_buf[0..header.mod_len],
        out[0..header.mod_len],
    ) catch return error.OutOfGas;
    return header.mod_len;
}

const Header = struct {
    base_len: u32,
    exp_len: u32,
    mod_len: u32,
};

fn read_u256(input: []const u8, offset: u32) u256 {
    var buf: [32]u8 = @splat(0);
    buffer_read(input, offset, 32, &buf);
    return word.from_bytes_be(&buf);
}

fn buffer_read(input: []const u8, start: u64, size: u32, out: []u8) void {
    std.debug.assert(out.len == size);
    @memset(out, 0);
    if (size == 0 or start >= input.len) return;
    const src: usize = @intCast(start);
    const n = @min(@as(usize, size), input.len - src);
    if (n > 0) @memcpy(out[0..n], input[src..][0..n]);
}

fn exponent_head(input: []const u8, header: Header) u256 {
    const n: u32 = @min(32, header.exp_len);
    var buf: [32]u8 = @splat(0);
    buffer_read(input, 96 + header.base_len, n, buf[32 - n ..][0..n]);
    return word.from_bytes_be(&buf);
}

fn price(base_len: u32, mod_len: u32, exp_len: u32, exp_head: u256, fork: Fork) u64 {
    const osaka = fork.at_least(.osaka);
    const max_length: u64 = @max(base_len, mod_len);
    const words = (max_length + 7) / 8;
    const complexity: u64 = if (!osaka)
        words *% words
    else if (max_length > 32)
        2 *% words *% words
    else
        16;
    const iters = iteration_count(exp_len, exp_head, osaka);
    const product: u128 = @as(u128, complexity) * iters;
    const raw: u128 = if (osaka) product else product / 3;
    const cost: u64 = if (raw > std.math.maxInt(u64)) std.math.maxInt(u64) else @intCast(raw);
    const floor: u64 = if (osaka) gas_mod.gas_modexp_min_osaka else gas_mod.gas_modexp_min_prague;
    return @max(floor, cost);
}

fn iteration_count(exp_len: u32, exp_head: u256, osaka: bool) u64 {
    var count: u64 = 0;
    if (exp_len <= 32 and exp_head == 0) {
        count = 0;
    } else if (exp_len <= 32) {
        count = bit_length(exp_head) - 1;
    } else {
        const bits = bit_length(exp_head);
        const bits_part: u64 = if (bits == 0) 0 else bits - 1;
        const scale: u64 = if (osaka) 16 else 8;
        count = scale * (exp_len - 32) + bits_part;
    }
    return @max(count, 1);
}

fn bit_length(value: u256) u64 {
    if (value == 0) return 0;
    return 256 - @clz(value);
}

fn is_zero(bytes: []const u8) bool {
    for (bytes) |b| {
        if (b != 0) return false;
    }
    return true;
}

fn powmod(
    allocator: std.mem.Allocator,
    base_bytes: []const u8,
    exp_bytes: []const u8,
    mod_bytes: []const u8,
    out: []u8,
) !void {
    var base = try int_from_bytes(allocator, base_bytes);
    defer base.deinit();
    var modulus = try int_from_bytes(allocator, mod_bytes);
    defer modulus.deinit();
    var result = try Managed.initSet(allocator, 1);
    defer result.deinit();
    var tmp = try Managed.init(allocator);
    defer tmp.deinit();
    var quot = try Managed.init(allocator);
    defer quot.deinit();
    var rem = try Managed.init(allocator);
    defer rem.deinit();

    try quot.divTrunc(&rem, &base, &modulus);
    try base.copy(rem.toConst());

    var started = false;
    for (exp_bytes) |byte| {
        var bit: u32 = 0;
        while (bit < 8) : (bit += 1) {
            const shift: u3 = @intCast(7 - bit);
            if (started) {
                try tmp.mul(&result, &result);
                try quot.divTrunc(&rem, &tmp, &modulus);
                try result.copy(rem.toConst());
            }
            if ((byte >> shift) & 1 == 1) {
                started = true;
                try tmp.mul(&result, &base);
                try quot.divTrunc(&rem, &tmp, &modulus);
                try result.copy(rem.toConst());
            }
        }
    }
    if (!started) {
        try quot.divTrunc(&rem, &result, &modulus);
        try result.copy(rem.toConst());
    }
    write_be_bytes(result.toConst(), out);
}

fn int_from_bytes(allocator: std.mem.Allocator, bytes: []const u8) !Managed {
    var n = try Managed.init(allocator);
    errdefer n.deinit();
    if (bytes.len == 0) {
        try n.set(0);
        return n;
    }
    var limbs: [max_limbs]Limb = undefined;
    var mut = Mutable{ .limbs = &limbs, .len = 1, .positive = true };
    mut.readTwosComplement(bytes, bytes.len * 8, .big, .unsigned);
    try n.copy(mut.toConst());
    return n;
}

fn write_be_bytes(value: std.math.big.int.Const, out: []u8) void {
    @memset(out, 0);
    if (value.eqlZero()) return;
    value.writeTwosComplement(out, .big);
}

test "modexp gas empty input is the fork minimum" {
    try std.testing.expectEqual(gas_mod.gas_modexp_min_osaka, try gas_cost(&[_]u8{}, .osaka));
    try std.testing.expectEqual(gas_mod.gas_modexp_min_prague, try gas_cost(&[_]u8{}, .prague));
}

test "modexp 3**2 mod 5" {
    var input: [99]u8 = @splat(0);
    input[31] = 1;
    input[63] = 1;
    input[95] = 1;
    input[96] = 3;
    input[97] = 2;
    input[98] = 5;
    var out: [32]u8 = undefined;
    const n = try execute(&input, &out, .osaka);
    try std.testing.expectEqual(@as(u32, 1), n);
    try std.testing.expectEqual(@as(u8, 4), out[0]);
}

test "osaka rejects length above 1024" {
    var input: [96]u8 = @splat(0);
    input[30] = 0x04;
    input[31] = 0x01;
    try std.testing.expectError(error.OutOfGas, gas_cost(&input, .osaka));
}

test "prague huge exp length with zero base and mod is the minimum" {
    var input: [64]u8 = @splat(0);
    input[32 + 20] = 0x04;
    try std.testing.expectEqual(gas_mod.gas_modexp_min_prague, try gas_cost(&input, .prague));
    var out: [32]u8 = undefined;
    try std.testing.expectEqual(@as(u32, 0), try execute(&input, &out, .prague));
    try std.testing.expectError(error.OutOfGas, gas_cost(&input, .osaka));
}

test "osaka zero-length base and mod still uses iteration gas" {
    var input: [128]u8 = @splat(0);
    input[63] = 32;
    input[96] = 0x66;
    input[97] = 0x0b;
    input[98] = 0xfd;
    try std.testing.expectEqual(@as(u64, 4064), try gas_cost(&input, .osaka));
    var out: [32]u8 = undefined;
    try std.testing.expectEqual(@as(u32, 0), try execute(&input, &out, .osaka));
}
