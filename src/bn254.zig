//! alt_bn128 precompiles `0x06` ECADD, `0x07` ECMUL, `0x08` ECPAIRING.

const std = @import("std");
const gas_mod = @import("gas.zig");
const word = @import("u256.zig");

const p: u256 = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
const n: u256 = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
const ate_loop: u128 = 0x19d797039be763ba8;
const final_exp_hex = "2f4b6dc97020fddadf107d20bc842d43bf6369b1ff6a1c71015f3f7be2e1e30a73bb94fec0daf15466b2383a5d3ec3d15ad524d8f70c54efee1bd8c3b21377e563a09a1b705887e72eceaddea3790364a61f676baaf977870e88d5c6c8fef0781361e443ae77f5b63a2a2264487f2940a8b1ddb3d15062cd0fb2015dfc6668449aed3cc48a82d0d602d268c7daab6a41294c0cc4ebe5664568dfc50e1648a45a4a1e3a5195846a3ed011a337a02088ec80e0ebae8755cfe107acf3aafb40494e406f804216bb10cf430b0f37856b42db8dc5514724ee93dfb10826f0dd4a0364b9580291d2cd65664814fde37ca80bb4ea44eacc5e641bbadf423f9a2cbf813b8d145da90029baee7ddadda71c7f3811c4105262945bba1668c3be69a3c230974d83561841d766f9c9d570bb7fbe04c7e8a6c3c760c0de81def35692da361102b6b9b2b918837fa97896e84abb40a4efb7e54523a486964b64ca86f120";

const Fp2 = struct { c0: u256, c1: u256 };
const G1 = struct { inf: bool, x: u256, y: u256 };
const G2 = struct { inf: bool, x: Fp2, y: Fp2 };
const Fq12 = [12]u256;

pub fn gas_add(_: []const u8) u64 {
    return gas_mod.gas_bn254_add;
}

pub fn gas_mul(_: []const u8) u64 {
    return gas_mod.gas_bn254_mul;
}

pub fn gas_pairing(input: []const u8) u64 {
    const k = input.len / 192;
    return gas_mod.gas_bn254_pairing_base + @as(u64, k) * gas_mod.gas_bn254_pairing_pair;
}

pub fn execute_add(input: []const u8, out: []u8) error{ OutputTooLarge, PrecompileFailed }!u32 {
    if (out.len < 64) return error.OutputTooLarge;
    const a = try decode_g1(input, 0);
    const b = try decode_g1(input, 64);
    write_g1(g1_add(a, b), out);
    return 64;
}

pub fn execute_mul(input: []const u8, out: []u8) error{ OutputTooLarge, PrecompileFailed }!u32 {
    if (out.len < 64) return error.OutputTooLarge;
    const a = try decode_g1(input, 0);
    const s = load_word(input, 64);
    write_g1(g1_mul(a, s), out);
    return 64;
}

pub fn execute_pairing(input: []const u8, out: []u8) error{ OutputTooLarge, PrecompileFailed }!u32 {
    if (out.len < 32) return error.OutputTooLarge;
    if (input.len % 192 != 0) return error.PrecompileFailed;
    var acc = fq12_one();
    var off: usize = 0;
    while (off < input.len) : (off += 192) {
        const p1 = try decode_g1(input[off..], 0);
        const q = try decode_g2(input[off + 64 ..]);
        if (!g1_mul(p1, n).inf) return error.PrecompileFailed;
        if (!g2_mul(q, n).inf) return error.PrecompileFailed;
        acc = fq12_mul(acc, pairing(q, p1));
    }
    @memset(out[0..32], 0);
    if (fq12_eq(acc, fq12_one())) out[31] = 1;
    return 32;
}

fn load_word(data: []const u8, off: usize) u256 {
    var buf: [32]u8 = @splat(0);
    if (off < data.len) {
        const n_copy = @min(32, data.len - off);
        @memcpy(buf[0..n_copy], data[off .. off + n_copy]);
    }
    return word.from_bytes_be(&buf);
}

fn decode_fp(data: []const u8, off: usize) !u256 {
    const v = load_word(data, off);
    if (v >= p) return error.PrecompileFailed;
    return v;
}

fn decode_g1(data: []const u8, off: usize) !G1 {
    const x = try decode_fp(data, off);
    const y = try decode_fp(data, off + 32);
    if (x == 0 and y == 0) return .{ .inf = true, .x = 0, .y = 0 };
    const pt = G1{ .inf = false, .x = x, .y = y };
    if (!g1_on_curve(pt)) return error.PrecompileFailed;
    return pt;
}

fn decode_g2(data: []const u8) !G2 {
    const x0 = try decode_fp(data, 0);
    const x1 = try decode_fp(data, 32);
    const y0 = try decode_fp(data, 64);
    const y1 = try decode_fp(data, 96);
    // EELS: FQ2((x1, x0)) so c0=x1, c1=x0.
    const x = Fp2{ .c0 = x1, .c1 = x0 };
    const y = Fp2{ .c0 = y1, .c1 = y0 };
    if (x0 == 0 and x1 == 0 and y0 == 0 and y1 == 0) {
        return .{ .inf = true, .x = x, .y = y };
    }
    const pt = G2{ .inf = false, .x = x, .y = y };
    if (!g2_on_curve(pt)) return error.PrecompileFailed;
    return pt;
}

fn write_g1(pt: G1, out: []u8) void {
    if (pt.inf) {
        @memset(out[0..64], 0);
        return;
    }
    word.to_bytes_be(pt.x, out[0..32]);
    word.to_bytes_be(pt.y, out[32..64]);
}

fn fp_add(a: u256, b: u256) u256 {
    const s = a + b;
    return if (s >= p) s - p else s;
}

fn fp_sub(a: u256, b: u256) u256 {
    return if (a >= b) a - b else a + p - b;
}

fn fp_mul(a: u256, b: u256) u256 {
    return @intCast(@as(u512, a) * @as(u512, b) % p);
}

fn fp_neg(a: u256) u256 {
    return if (a == 0) 0 else p - a;
}

fn fp_inv(a: u256) u256 {
    std.debug.assert(a != 0);
    return fp_pow(a, p - 2);
}

fn fp_pow(base: u256, exp: u256) u256 {
    var result: u256 = 1;
    var b = base;
    var e = exp;
    while (e != 0) {
        if (e & 1 == 1) result = fp_mul(result, b);
        b = fp_mul(b, b);
        e >>= 1;
    }
    return result;
}

fn fp2_add(a: Fp2, b: Fp2) Fp2 {
    return .{ .c0 = fp_add(a.c0, b.c0), .c1 = fp_add(a.c1, b.c1) };
}

fn fp2_sub(a: Fp2, b: Fp2) Fp2 {
    return .{ .c0 = fp_sub(a.c0, b.c0), .c1 = fp_sub(a.c1, b.c1) };
}

fn fp2_neg(a: Fp2) Fp2 {
    return .{ .c0 = fp_neg(a.c0), .c1 = fp_neg(a.c1) };
}

fn fp2_mul(a: Fp2, b: Fp2) Fp2 {
    return .{
        .c0 = fp_sub(fp_mul(a.c0, b.c0), fp_mul(a.c1, b.c1)),
        .c1 = fp_add(fp_mul(a.c0, b.c1), fp_mul(a.c1, b.c0)),
    };
}

fn fp2_inv(a: Fp2) Fp2 {
    const norm = fp_add(fp_mul(a.c0, a.c0), fp_mul(a.c1, a.c1));
    const invn = fp_inv(norm);
    return .{ .c0 = fp_mul(a.c0, invn), .c1 = fp_mul(fp_neg(a.c1), invn) };
}

fn fp2_div(a: Fp2, b: Fp2) Fp2 {
    return fp2_mul(a, fp2_inv(b));
}

fn fp2_eq(a: Fp2, b: Fp2) bool {
    return a.c0 == b.c0 and a.c1 == b.c1;
}

fn b2() Fp2 {
    return fp2_div(.{ .c0 = 3, .c1 = 0 }, .{ .c0 = 9, .c1 = 1 });
}

fn g1_on_curve(pt: G1) bool {
    if (pt.inf) return true;
    const yy = fp_mul(pt.y, pt.y);
    const xxx = fp_mul(fp_mul(pt.x, pt.x), pt.x);
    return yy == fp_add(xxx, 3);
}

fn g2_on_curve(pt: G2) bool {
    if (pt.inf) return true;
    const yy = fp2_mul(pt.y, pt.y);
    const xxx = fp2_mul(fp2_mul(pt.x, pt.x), pt.x);
    return fp2_eq(yy, fp2_add(xxx, b2()));
}

fn g1_double(pt: G1) G1 {
    if (pt.inf or pt.y == 0) return .{ .inf = true, .x = 0, .y = 0 };
    const m = fp_mul(fp_mul(3, fp_mul(pt.x, pt.x)), fp_inv(fp_mul(2, pt.y)));
    const x3 = fp_sub(fp_mul(m, m), fp_mul(2, pt.x));
    const y3 = fp_sub(fp_mul(m, fp_sub(pt.x, x3)), pt.y);
    return .{ .inf = false, .x = x3, .y = y3 };
}

fn g1_add(a: G1, b: G1) G1 {
    if (a.inf) return b;
    if (b.inf) return a;
    if (a.x == b.x) {
        if (a.y == b.y) return g1_double(a);
        return .{ .inf = true, .x = 0, .y = 0 };
    }
    const m = fp_mul(fp_sub(b.y, a.y), fp_inv(fp_sub(b.x, a.x)));
    const x3 = fp_sub(fp_sub(fp_mul(m, m), a.x), b.x);
    const y3 = fp_sub(fp_mul(m, fp_sub(a.x, x3)), a.y);
    return .{ .inf = false, .x = x3, .y = y3 };
}

fn g1_mul(pt: G1, scalar: u256) G1 {
    var result = G1{ .inf = true, .x = 0, .y = 0 };
    var acc = pt;
    var s = scalar;
    while (s != 0) {
        if (s & 1 == 1) result = g1_add(result, acc);
        acc = g1_double(acc);
        s >>= 1;
    }
    return result;
}

fn g2_double(pt: G2) G2 {
    if (pt.inf or (pt.y.c0 == 0 and pt.y.c1 == 0)) {
        return .{ .inf = true, .x = pt.x, .y = pt.y };
    }
    const xx = fp2_mul(pt.x, pt.x);
    const m = fp2_div(.{ .c0 = fp_mul(3, xx.c0), .c1 = fp_mul(3, xx.c1) }, fp2_add(pt.y, pt.y));
    const x3 = fp2_sub(fp2_mul(m, m), fp2_add(pt.x, pt.x));
    const y3 = fp2_sub(fp2_mul(m, fp2_sub(pt.x, x3)), pt.y);
    return .{ .inf = false, .x = x3, .y = y3 };
}

fn g2_add(a: G2, b: G2) G2 {
    if (a.inf) return b;
    if (b.inf) return a;
    if (fp2_eq(a.x, b.x)) {
        if (fp2_eq(a.y, b.y)) return g2_double(a);
        return .{ .inf = true, .x = a.x, .y = a.y };
    }
    const m = fp2_div(fp2_sub(b.y, a.y), fp2_sub(b.x, a.x));
    const x3 = fp2_sub(fp2_sub(fp2_mul(m, m), a.x), b.x);
    const y3 = fp2_sub(fp2_mul(m, fp2_sub(a.x, x3)), a.y);
    return .{ .inf = false, .x = x3, .y = y3 };
}

fn g2_mul(pt: G2, scalar: u256) G2 {
    var result = G2{ .inf = true, .x = pt.x, .y = pt.y };
    var acc = pt;
    var s = scalar;
    while (s != 0) {
        if (s & 1 == 1) result = g2_add(result, acc);
        acc = g2_double(acc);
        s >>= 1;
    }
    return result;
}

fn fq12_one() Fq12 {
    var r: Fq12 = @splat(0);
    r[0] = 1;
    return r;
}

fn fq12_eq(a: Fq12, b: Fq12) bool {
    return std.mem.eql(u256, &a, &b);
}

fn fq12_add(a: Fq12, b: Fq12) Fq12 {
    var r: Fq12 = undefined;
    var i: u32 = 0;
    while (i < 12) : (i += 1) r[i] = fp_add(a[i], b[i]);
    return r;
}

fn fq12_sub(a: Fq12, b: Fq12) Fq12 {
    var r: Fq12 = undefined;
    var i: u32 = 0;
    while (i < 12) : (i += 1) r[i] = fp_sub(a[i], b[i]);
    return r;
}

fn fq12_mul(a: Fq12, b: Fq12) Fq12 {
    var t: [23]u256 = @splat(0);
    var i: u32 = 0;
    while (i < 12) : (i += 1) {
        var j: u32 = 0;
        while (j < 12) : (j += 1) {
            t[i + j] = fp_add(t[i + j], fp_mul(a[i], b[j]));
        }
    }
    var d: i32 = 22;
    while (d >= 12) : (d -= 1) {
        const c = t[@intCast(d)];
        if (c == 0) continue;
        t[@intCast(d)] = 0;
        t[@intCast(d - 6)] = fp_add(t[@intCast(d - 6)], fp_mul(18, c));
        t[@intCast(d - 12)] = fp_sub(t[@intCast(d - 12)], fp_mul(82, c));
    }
    var r: Fq12 = undefined;
    i = 0;
    while (i < 12) : (i += 1) r[i] = t[i];
    return r;
}

fn fq12_from_fp(x: u256) Fq12 {
    var z: Fq12 = @splat(0);
    z[0] = x;
    return z;
}

fn fq12_pow_u256(base: Fq12, exp: u256) Fq12 {
    var result = fq12_one();
    var b = base;
    var e = exp;
    while (e != 0) {
        if (e & 1 == 1) result = fq12_mul(result, b);
        b = fq12_mul(b, b);
        e >>= 1;
    }
    return result;
}

fn fq12_pow_final(base: Fq12) Fq12 {
    const exp = comptime blk: {
        @setEvalBranchQuota(100_000);
        break :blk std.fmt.parseInt(u4096, final_exp_hex, 16) catch unreachable;
    };
    var result = fq12_one();
    var b = base;
    var e: u4096 = exp;
    while (e != 0) {
        if (e & 1 == 1) result = fq12_mul(result, b);
        b = fq12_mul(b, b);
        e >>= 1;
    }
    return result;
}

const Fq12Pt = struct { x: Fq12, y: Fq12 };

fn w() Fq12 {
    var r: Fq12 = @splat(0);
    r[1] = 1;
    return r;
}

fn twist(pt: G2) Fq12Pt {
    const xc0 = fp_sub(pt.x.c0, fp_mul(pt.x.c1, 9));
    const xc1 = pt.x.c1;
    const yc0 = fp_sub(pt.y.c0, fp_mul(pt.y.c1, 9));
    const yc1 = pt.y.c1;
    var nx: Fq12 = @splat(0);
    nx[0] = xc0;
    nx[6] = xc1;
    var ny: Fq12 = @splat(0);
    ny[0] = yc0;
    ny[6] = yc1;
    const ww = w();
    const w2 = fq12_mul(ww, ww);
    const w3 = fq12_mul(w2, ww);
    return .{ .x = fq12_mul(nx, w2), .y = fq12_mul(ny, w3) };
}

fn linefunc(p1: Fq12Pt, p2: Fq12Pt, t: Fq12Pt) Fq12 {
    if (!fq12_eq(p1.x, p2.x)) {
        const m = fq12_mul(fq12_sub(p2.y, p1.y), fq12_inv(fq12_sub(p2.x, p1.x)));
        return fq12_sub(fq12_mul(m, fq12_sub(t.x, p1.x)), fq12_sub(t.y, p1.y));
    }
    if (fq12_eq(p1.y, p2.y)) {
        const xx = fq12_mul(p1.x, p1.x);
        const num = fq12_mul(fq12_from_fp(3), xx);
        const den = fq12_add(p1.y, p1.y);
        const m = fq12_mul(num, fq12_inv(den));
        return fq12_sub(fq12_mul(m, fq12_sub(t.x, p1.x)), fq12_sub(t.y, p1.y));
    }
    return fq12_sub(t.x, p1.x);
}

fn fq12_inv(a: Fq12) Fq12 {
    var lm: [13]u256 = @splat(0);
    var hm: [13]u256 = @splat(0);
    var low: [13]u256 = @splat(0);
    var high: [13]u256 = @splat(0);
    lm[0] = 1;
    var i: u32 = 0;
    while (i < 12) : (i += 1) low[i] = a[i];
    high[0] = 82;
    high[6] = fp_neg(18);
    high[12] = 1;
    while (poly_deg(&low) > 0) {
        const r = poly_div(&high, &low);
        var nm = hm;
        var nw = high;
        i = 0;
        while (i < 13) : (i += 1) {
            var j: u32 = 0;
            while (j + i < 13) : (j += 1) {
                nm[i + j] = fp_sub(nm[i + j], fp_mul(lm[i], r[j]));
                nw[i + j] = fp_sub(nw[i + j], fp_mul(low[i], r[j]));
            }
        }
        hm = lm;
        high = low;
        lm = nm;
        low = nw;
    }
    std.debug.assert(low[0] != 0);
    const scale = fp_inv(low[0]);
    var out: Fq12 = undefined;
    i = 0;
    while (i < 12) : (i += 1) out[i] = fp_mul(lm[i], scale);
    return out;
}

fn poly_deg(c: *const [13]u256) i32 {
    var i: i32 = 12;
    while (i >= 0) : (i -= 1) {
        if (c.*[@intCast(i)] != 0) return i;
    }
    return -1;
}

fn poly_div(high: *const [13]u256, low: *const [13]u256) [13]u256 {
    var rem = high.*;
    var q: [13]u256 = @splat(0);
    const dlow = poly_deg(low);
    std.debug.assert(dlow >= 0);
    var d = poly_deg(&rem);
    while (d >= dlow) {
        const idx: u32 = @intCast(d - dlow);
        const coef = fp_mul(rem[@intCast(d)], fp_inv(low.*[@intCast(dlow)]));
        q[idx] = fp_add(q[idx], coef);
        var j: u32 = 0;
        while (j <= @as(u32, @intCast(dlow))) : (j += 1) {
            rem[idx + j] = fp_sub(rem[idx + j], fp_mul(coef, low.*[j]));
        }
        d = poly_deg(&rem);
    }
    return q;
}

fn fq12_pt_double(pt: Fq12Pt) Fq12Pt {
    const xx = fq12_mul(pt.x, pt.x);
    const m = fq12_mul(fq12_mul(fq12_from_fp(3), xx), fq12_inv(fq12_add(pt.y, pt.y)));
    const x3 = fq12_sub(fq12_mul(m, m), fq12_add(pt.x, pt.x));
    const y3 = fq12_sub(fq12_mul(m, fq12_sub(pt.x, x3)), pt.y);
    return .{ .x = x3, .y = y3 };
}

fn fq12_pt_add(a: Fq12Pt, b: Fq12Pt) Fq12Pt {
    const m = fq12_mul(fq12_sub(b.y, a.y), fq12_inv(fq12_sub(b.x, a.x)));
    const x3 = fq12_sub(fq12_sub(fq12_mul(m, m), a.x), b.x);
    const y3 = fq12_sub(fq12_mul(m, fq12_sub(a.x, x3)), a.y);
    return .{ .x = x3, .y = y3 };
}

fn miller_loop(q: Fq12Pt, p_pt: Fq12Pt) Fq12 {
    var r = q;
    var f = fq12_one();
    var i: i32 = 64;
    while (i >= 0) : (i -= 1) {
        f = fq12_mul(fq12_mul(f, f), linefunc(r, r, p_pt));
        r = fq12_pt_double(r);
        if ((ate_loop >> @intCast(i)) & 1 == 1) {
            f = fq12_mul(f, linefunc(r, q, p_pt));
            r = fq12_pt_add(r, q);
        }
    }
    const q1 = Fq12Pt{
        .x = fq12_pow_u256(q.x, p),
        .y = fq12_pow_u256(q.y, p),
    };
    const nq2 = Fq12Pt{
        .x = fq12_pow_u256(q1.x, p),
        .y = fq12_sub(fq12_from_fp(0), fq12_pow_u256(q1.y, p)),
    };
    f = fq12_mul(f, linefunc(r, q1, p_pt));
    r = fq12_pt_add(r, q1);
    f = fq12_mul(f, linefunc(r, nq2, p_pt));
    return fq12_pow_final(f);
}

fn pairing(q: G2, p1: G1) Fq12 {
    if (q.inf or p1.inf) return fq12_one();
    const p12 = Fq12Pt{ .x = fq12_from_fp(p1.x), .y = fq12_from_fp(p1.y) };
    return miller_loop(twist(q), p12);
}

test "bn254 add generator to itself" {
    var input: [128]u8 = @splat(0);
    input[31] = 1;
    input[63] = 2;
    input[95] = 1;
    input[127] = 2;
    var out: [64]u8 = undefined;
    const n_out = try execute_add(&input, &out);
    try std.testing.expectEqual(@as(u32, 64), n_out);
    try std.testing.expectEqual(@as(u256, 0x030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3), word.from_bytes_be(out[0..32]));
    try std.testing.expectEqual(@as(u256, 0x15ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4), word.from_bytes_be(out[32..64]));
}

test "bn254 add empty is infinity" {
    var out: [64]u8 = undefined;
    const n_out = try execute_add(&[_]u8{}, &out);
    try std.testing.expectEqual(@as(u32, 64), n_out);
    try std.testing.expect(std.mem.allEqual(u8, &out, 0));
}

test "bn254 mul two is double" {
    var input: [96]u8 = @splat(0);
    input[31] = 1;
    input[63] = 2;
    input[95] = 2;
    var out: [64]u8 = undefined;
    _ = try execute_mul(&input, &out);
    try std.testing.expectEqual(@as(u256, 0x030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3), word.from_bytes_be(out[0..32]));
}

test "bn254 invalid point fails" {
    var input: [64]u8 = @splat(0);
    input[31] = 1;
    input[63] = 1;
    var out: [64]u8 = undefined;
    try std.testing.expectError(error.PrecompileFailed, execute_add(&input, &out));
}

test "bn254 pairing empty returns one" {
    var out: [32]u8 = undefined;
    const n_out = try execute_pairing(&[_]u8{}, &out);
    try std.testing.expectEqual(@as(u32, 32), n_out);
    try std.testing.expectEqual(@as(u8, 1), out[31]);
}

test "bn254 pairing e(G,G2)*e(-G,G2) is one" {
    var input: [384]u8 = @splat(0);
    fill_g1_g2(&input, false);
    fill_g1_g2(input[192..], true);
    var out: [32]u8 = undefined;
    const n_out = try execute_pairing(&input, &out);
    try std.testing.expectEqual(@as(u32, 32), n_out);
    try std.testing.expectEqual(@as(u8, 1), out[31]);
}

fn fill_g1_g2(out: []u8, neg: bool) void {
    @memset(out, 0);
    out[31] = 1;
    if (neg) {
        word.to_bytes_be(p - 2, out[32..64]);
    } else {
        out[63] = 2;
    }
    const x0: u256 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    const x1: u256 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    const y0: u256 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    const y1: u256 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    word.to_bytes_be(x0, out[64..96]);
    word.to_bytes_be(x1, out[96..128]);
    word.to_bytes_be(y0, out[128..160]);
    word.to_bytes_be(y1, out[160..192]);
}
