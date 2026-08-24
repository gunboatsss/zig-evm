//! BLAKE2F precompile at `0x09` (EIP-152). 213-byte input, 64-byte output.

const std = @import("std");
const limits = @import("limits.zig");

const input_len: u32 = limits.blake2f_input_bytes;
const output_len: u32 = limits.blake2f_output_bytes;

pub fn gas_cost(input: []const u8) u64 {
    if (input.len != input_len) return 0;
    return std.mem.readInt(u32, input[0..4], .big);
}

pub fn execute(input: []const u8, out: []u8) error{ OutputTooLarge, PrecompileFailed }!u32 {
    if (input.len != input_len) return error.PrecompileFailed;
    const flag = input[212];
    if (flag > 1) return error.PrecompileFailed;
    if (out.len < output_len) return error.OutputTooLarge;

    const rounds = std.mem.readInt(u32, input[0..4], .big);
    var h: [8]u64 = undefined;
    var m: [16]u64 = undefined;
    var i: u32 = 0;
    while (i < 8) : (i += 1) {
        h[i] = std.mem.readInt(u64, input[4 + i * 8 ..][0..8], .little);
    }
    i = 0;
    while (i < 16) : (i += 1) {
        m[i] = std.mem.readInt(u64, input[68 + i * 8 ..][0..8], .little);
    }
    const t0 = std.mem.readInt(u64, input[196..204], .little);
    const t1 = std.mem.readInt(u64, input[204..212], .little);
    compress(&h, m, t0, t1, flag == 1, rounds);
    i = 0;
    while (i < 8) : (i += 1) {
        std.mem.writeInt(u64, out[i * 8 ..][0..8], h[i], .little);
    }
    return output_len;
}

fn compress(h: *[8]u64, m: [16]u64, t0: u64, t1: u64, last: bool, rounds: u32) void {
    var v: [16]u64 = undefined;
    var i: u32 = 0;
    while (i < 8) : (i += 1) {
        v[i] = h[i];
        v[i + 8] = iv[i];
    }
    v[12] ^= t0;
    v[13] ^= t1;
    if (last) v[14] = ~v[14];
    i = 0;
    while (i < rounds) : (i += 1) {
        const s = &sigma[i % 10];
        mix(&v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        mix(&v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        mix(&v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        mix(&v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        mix(&v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        mix(&v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        mix(&v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        mix(&v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    i = 0;
    while (i < 8) : (i += 1) h[i] ^= v[i] ^ v[i + 8];
}

fn mix(v: *[16]u64, a: u32, b: u32, c: u32, d: u32, x: u64, y: u64) void {
    v[a] = v[a] +% v[b] +% x;
    v[d] = std.math.rotr(u64, v[d] ^ v[a], 32);
    v[c] = v[c] +% v[d];
    v[b] = std.math.rotr(u64, v[b] ^ v[c], 24);
    v[a] = v[a] +% v[b] +% y;
    v[d] = std.math.rotr(u64, v[d] ^ v[a], 16);
    v[c] = v[c] +% v[d];
    v[b] = std.math.rotr(u64, v[b] ^ v[c], 63);
}

const iv = [_]u64{
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
};

const sigma = [10][16]u8{
    .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    .{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    .{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    .{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    .{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    .{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    .{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    .{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    .{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    .{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};

test "blake2f eip-152 zero rounds" {
    var input: [213]u8 = @splat(0);
    const h = hex64("48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b");
    @memcpy(input[4..68], &h);
    input[68] = 'a';
    input[69] = 'b';
    input[70] = 'c';
    std.mem.writeInt(u64, input[196..204], 3, .little);
    input[212] = 1;
    var out: [64]u8 = undefined;
    const n = try execute(&input, &out);
    try std.testing.expectEqual(@as(u32, 64), n);
    const want = hex64("08c9bcf367e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d282e6ad7f520e511f6c3e2b8c68059b9442be0454267ce079217e1319cde05b");
    try std.testing.expectEqualSlices(u8, &want, &out);
}

test "blake2f rejects short input" {
    var out: [64]u8 = undefined;
    try std.testing.expectError(error.PrecompileFailed, execute(&[_]u8{ 1, 2, 3 }, &out));
}

test "blake2f rejects final flag above one" {
    var input: [213]u8 = @splat(0);
    input[212] = 2;
    var out: [64]u8 = undefined;
    try std.testing.expectError(error.PrecompileFailed, execute(&input, &out));
}

test "blake2f gas is rounds when input is 213 bytes" {
    var input: [213]u8 = @splat(0);
    std.mem.writeInt(u32, input[0..4], 12, .big);
    try std.testing.expectEqual(@as(u64, 12), gas_cost(&input));
    try std.testing.expectEqual(@as(u64, 0), gas_cost(&[_]u8{ 1, 2, 3 }));
}

fn hex64(text: *const [128]u8) [64]u8 {
    var out: [64]u8 = undefined;
    var index: u32 = 0;
    while (index < 64) : (index += 1) {
        out[index] = std.fmt.parseInt(u8, text[index * 2 .. index * 2 + 2], 16) catch unreachable;
    }
    return out;
}
