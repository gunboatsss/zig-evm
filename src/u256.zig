//! EVM word helpers on Zig's native `u256`.
//!
//! Ordinary wrapping arithmetic (`+%`, `*%`, `-%`) is used at the call site.
//! This module covers Yellow Paper rules the language does not: divide-by-zero
//! returns 0, shifts of 256+ bits saturate, and ADDMOD/MULMOD use a wider
//! intermediate so the sum/product does not wrap before the modulus.

const std = @import("std");

pub fn from_bytes_be(bytes: *const [32]u8) u256 {
    return std.mem.readInt(u256, bytes, .big);
}

pub fn to_bytes_be(value: u256, out: *[32]u8) void {
    std.mem.writeInt(u256, out, value, .big);
}

pub fn div(a: u256, b: u256) u256 {
    if (b == 0) return 0;
    return a / b;
}

pub fn mod(a: u256, b: u256) u256 {
    if (b == 0) return 0;
    return a % b;
}

pub fn sdiv(a: u256, b: u256) u256 {
    if (b == 0) return 0;
    const sa: i256 = @bitCast(a);
    const sb: i256 = @bitCast(b);
    // minInt(i256) / -1 overflows two's complement; the EVM returns the dividend.
    if (sa == std.math.minInt(i256) and sb == -1) return a;
    return @bitCast(@divTrunc(sa, sb));
}

pub fn smod(a: u256, b: u256) u256 {
    if (b == 0) return 0;
    const sa: i256 = @bitCast(a);
    const sb: i256 = @bitCast(b);
    return @bitCast(@rem(sa, sb));
}

pub fn addmod(a: u256, b: u256, modulus: u256) u256 {
    if (modulus == 0) return 0;
    const sum: u257 = @as(u257, a) + @as(u257, b);
    return @intCast(sum % @as(u257, modulus));
}

pub fn mulmod(a: u256, b: u256, modulus: u256) u256 {
    if (modulus == 0) return 0;
    const product: u512 = @as(u512, a) * @as(u512, b);
    return @intCast(product % @as(u512, modulus));
}

pub fn exp(base: u256, exponent: u256) u256 {
    var result: u256 = 1;
    var b = base;
    var e = exponent;
    while (e != 0) {
        if (e & 1 == 1) result *%= b;
        b *%= b;
        e >>= 1;
    }
    return result;
}

pub fn signextend(byte_index: u256, value: u256) u256 {
    if (byte_index >= 31) return value;
    const bit_index: u8 = @intCast(byte_index * 8 + 7);
    const sign_mask: u256 = @as(u256, 1) << bit_index;
    const value_mask: u256 = (sign_mask << 1) - 1;
    if (value & sign_mask == 0) return value & value_mask;
    return value | ~value_mask;
}

pub fn byte(word: u256, index: u256) u256 {
    if (index >= 32) return 0;
    const shift: u8 = @intCast((31 - index) * 8);
    return (word >> shift) & 0xff;
}

pub fn shl(value: u256, shift: u256) u256 {
    if (shift >= 256) return 0;
    return value << @intCast(shift);
}

pub fn shr(value: u256, shift: u256) u256 {
    if (shift >= 256) return 0;
    return value >> @intCast(shift);
}

pub fn sar(value: u256, shift: u256) u256 {
    const signed: i256 = @bitCast(value);
    if (shift >= 256) {
        if (signed < 0) return std.math.maxInt(u256);
        return 0;
    }
    return @bitCast(signed >> @intCast(shift));
}

pub fn clz(value: u256) u256 {
    return @as(u256, @clz(value));
}

pub fn slt(a: u256, b: u256) bool {
    const sa: i256 = @bitCast(a);
    const sb: i256 = @bitCast(b);
    return sa < sb;
}

pub const address_mask: u256 = (@as(u256, 1) << 160) - 1;

pub fn to_address(word: u256) u256 {
    return word & address_mask;
}

pub fn to_u32(word: u256) !u32 {
    if (word > std.math.maxInt(u32)) return error.ValueOverflow;
    return @intCast(word);
}

pub fn to_u64_saturating(word: u256) u64 {
    if (word > std.math.maxInt(u64)) return std.math.maxInt(u64);
    return @intCast(word);
}

pub fn exponent_byte_size(exponent: u256) u64 {
    if (exponent == 0) return 0;
    return (256 - @clz(exponent) + 7) / 8;
}

test "native add and mul wrap" {
    try std.testing.expectEqual(@as(u256, 50), @as(u256, 42) +% 8);
    try std.testing.expectEqual(@as(u256, 336), @as(u256, 42) *% 8);
}

test "div by zero returns zero" {
    try std.testing.expectEqual(@as(u256, 0), div(10, 0));
}

test "clz of zero is 256" {
    try std.testing.expectEqual(@as(u256, 256), clz(0));
}

test "clz of one is 255" {
    try std.testing.expectEqual(@as(u256, 255), clz(1));
}

test "bytes round trip" {
    const value: u256 = 0xdeadbeef;
    var bytes: [32]u8 = undefined;
    to_bytes_be(value, &bytes);
    try std.testing.expectEqual(value, from_bytes_be(&bytes));
    try std.testing.expectEqual(@as(u8, 0xde), bytes[28]);
}
