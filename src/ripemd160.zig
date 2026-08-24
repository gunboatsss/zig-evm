//! RIPEMD-160 precompile at `0x03`. Output is 32 bytes, left-padded.

const std = @import("std");

pub fn execute(input: []const u8, out: []u8) error{OutputTooLarge}!u32 {
    if (out.len < 32) return error.OutputTooLarge;
    var digest: [20]u8 = undefined;
    hash(input, &digest);
    @memset(out[0..12], 0);
    @memcpy(out[12..32], &digest);
    return 32;
}

fn hash(data: []const u8, out: *[20]u8) void {
    var state = [_]u32{
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0,
    };
    var offset: u32 = 0;
    const total: u32 = @intCast(data.len);
    while (offset + 64 <= total) : (offset += 64) {
        compress(&state, data[offset..][0..64]);
    }
    var block: [128]u8 = @splat(0);
    const rest: u32 = total - offset;
    if (rest > 0) @memcpy(block[0..rest], data[offset..]);
    block[rest] = 0x80;
    const bits: u64 = @as(u64, total) * 8;
    if (rest < 56) {
        std.mem.writeInt(u64, block[56..64], bits, .little);
        compress(&state, block[0..64]);
    } else {
        std.mem.writeInt(u64, block[120..128], bits, .little);
        compress(&state, block[0..64]);
        compress(&state, block[64..128]);
    }
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        std.mem.writeInt(u32, out[i * 4 ..][0..4], state[i], .little);
    }
}

fn f(j: u32, x: u32, y: u32, z: u32) u32 {
    return switch (j / 16) {
        0 => x ^ y ^ z,
        1 => (x & y) | (~x & z),
        2 => (x | ~y) ^ z,
        3 => (x & z) | (y & ~z),
        else => x ^ (y | ~z),
    };
}

fn compress(state: *[5]u32, block: *const [64]u8) void {
    var w: [16]u32 = undefined;
    var i: u32 = 0;
    while (i < 16) : (i += 1) {
        w[i] = std.mem.readInt(u32, block[i * 4 ..][0..4], .little);
    }
    var al = state[0];
    var bl = state[1];
    var cl = state[2];
    var dl = state[3];
    var el = state[4];
    var ar = state[0];
    var br = state[1];
    var cr = state[2];
    var dr = state[3];
    var er = state[4];
    i = 0;
    while (i < 80) : (i += 1) {
        var t = al +% f(i, bl, cl, dl) +% w[idx_l[i]] +% k_l[i / 16];
        t = std.math.rotl(u32, t, s_l[i]) +% el;
        al = el;
        el = dl;
        dl = std.math.rotl(u32, cl, 10);
        cl = bl;
        bl = t;
        t = ar +% f(79 - i, br, cr, dr) +% w[idx_r[i]] +% k_r[i / 16];
        t = std.math.rotl(u32, t, s_r[i]) +% er;
        ar = er;
        er = dr;
        dr = std.math.rotl(u32, cr, 10);
        cr = br;
        br = t;
    }
    const t = state[1] +% cl +% dr;
    state[1] = state[2] +% dl +% er;
    state[2] = state[3] +% el +% ar;
    state[3] = state[4] +% al +% br;
    state[4] = state[0] +% bl +% cr;
    state[0] = t;
}

const k_l = [_]u32{ 0, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E };
const k_r = [_]u32{ 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0 };

const idx_l = [_]u32{
    0, 1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    7, 4,  13, 1,  10, 6,  15, 3,  12, 0, 9,  5,  2,  14, 11, 8,
    3, 10, 14, 4,  9,  15, 8,  1,  2,  7, 0,  6,  13, 11, 5,  12,
    1, 9,  11, 10, 0,  8,  12, 4,  13, 3, 7,  15, 14, 5,  6,  2,
    4, 0,  5,  9,  7,  12, 2,  10, 14, 1, 3,  8,  11, 6,  15, 13,
};

const idx_r = [_]u32{
    5,  14, 7,  0, 9, 2,  11, 4,  13, 6,  15, 8,  1,  10, 3,  12,
    6,  11, 3,  7, 0, 13, 5,  10, 14, 15, 8,  12, 4,  9,  1,  2,
    15, 5,  1,  3, 7, 14, 6,  9,  11, 8,  12, 2,  10, 0,  4,  13,
    8,  6,  4,  1, 3, 11, 15, 0,  5,  12, 2,  13, 9,  7,  10, 14,
    12, 15, 10, 4, 1, 5,  8,  7,  6,  2,  13, 14, 0,  3,  9,  11,
};

const s_l = [_]u5{
    11, 14, 15, 12, 5,  8,  7,  9,  11, 13, 14, 15, 6,  7,  9,  8,
    7,  6,  8,  13, 11, 9,  7,  15, 7,  12, 15, 9,  11, 7,  13, 12,
    11, 13, 6,  7,  14, 9,  13, 15, 14, 8,  13, 6,  5,  12, 7,  5,
    11, 12, 14, 15, 14, 15, 9,  8,  9,  14, 5,  6,  8,  6,  5,  12,
    9,  15, 5,  11, 6,  8,  13, 12, 5,  12, 13, 14, 11, 8,  5,  6,
};

const s_r = [_]u5{
    8,  9,  9,  11, 13, 15, 15, 5,  7,  7,  8,  11, 14, 14, 12, 6,
    9,  13, 15, 7,  12, 8,  9,  11, 7,  7,  12, 7,  6,  15, 13, 11,
    9,  7,  15, 11, 8,  6,  6,  14, 12, 13, 5,  14, 13, 13, 7,  5,
    15, 5,  8,  11, 14, 14, 6,  14, 6,  9,  12, 9,  12, 5,  15, 8,
    8,  5,  12, 9,  12, 5,  14, 6,  8,  13, 6,  5,  15, 13, 11, 11,
};

test "ripemd160 empty" {
    var out: [32]u8 = undefined;
    const n = try execute(&[_]u8{}, &out);
    try std.testing.expectEqual(@as(u32, 32), n);
    try std.testing.expectEqualSlices(u8, &hex20("9c1185a5c5e9fc54612808977ee8f548b2258d31"), out[12..32]);
}

test "ripemd160 abc" {
    var out: [32]u8 = undefined;
    _ = try execute("abc", &out);
    try std.testing.expectEqualSlices(u8, &hex20("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"), out[12..32]);
}

fn hex20(text: *const [40]u8) [20]u8 {
    var out: [20]u8 = undefined;
    var index: u32 = 0;
    while (index < 20) : (index += 1) {
        out[index] = std.fmt.parseInt(u8, text[index * 2 .. index * 2 + 2], 16) catch unreachable;
    }
    return out;
}
