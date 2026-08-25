//! alt_bn128 precompiles `0x06` ECADD, `0x07` ECMUL, `0x08` ECPAIRING.

const std = @import("std");
const gas_mod = @import("gas.zig");
const word = @import("u256.zig");

const p: u256 = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
const n: u256 = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
const ate_loop: u128 = 0x19d797039be763ba8;
/// BN seed `x`. `[6x²]P = ψ(P)` iff `P` is in G2 (HGP 2022).
const six_x_squared: u256 = 0x6f4d8248eeb859fbf83e9682e87cfd46;
const bn_x: u64 = 0x44e992b44a6909f1;

const Fp2 = struct { c0: u256, c1: u256 };
const psi_x = Fp2{
    .c0 = 0x2fb347984f7911f74c0bec3cf559b143b78cc310c2c3330c99e39557176f553d,
    .c1 = 0x16c9e55061ebae204ba4cc8bd75a079432ae2a1d0b7c9dce1665d51c640fcba2,
};
const psi_y = Fp2{
    .c0 = 0x63cf305489af5dcdc5ec698b6e2f9b9dbaae0eda9c95998dc54014671a0135a,
    .c1 = 0x7c03cbcac41049a0704b5a7ec796f2b21807dc98fa25bd282d37f632623b0e3,
};
const G1 = struct { inf: bool, x: u256, y: u256 };
const G2 = struct { inf: bool, x: Fp2, y: Fp2 };
const Fq12 = [12]u256;

comptime {
    std.debug.assert(n != 0);
    std.debug.assert(six_x_squared != 0);
}

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
        // G1 cofactor is 1: on-curve (decode) is the subgroup check.
        if (!g2_in_subgroup(q)) return error.PrecompileFailed;
        if (p1.inf or q.inf) continue;
        acc = fq12_mul(acc, miller_loop(q, p1));
    }
    if (!fq12_eq(acc, fq12_one())) acc = fq12_pow_final(acc);
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
    var t: i512 = 0;
    var newt: i512 = 1;
    var r: i512 = p;
    var newr: i512 = a;
    while (newr != 0) {
        const q = @divTrunc(r, newr);
        const tmp_t = newt;
        newt = t - q * newt;
        t = tmp_t;
        const tmp_r = newr;
        newr = r - q * newr;
        r = tmp_r;
    }
    if (t < 0) t += p;
    return @intCast(t);
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
    const t0 = fp_mul(a.c0, b.c0);
    const t1 = fp_mul(a.c1, b.c1);
    const t2 = fp_mul(fp_add(a.c0, a.c1), fp_add(b.c0, b.c1));
    return .{
        .c0 = fp_sub(t0, t1),
        .c1 = fp_sub(t2, fp_add(t0, t1)),
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

fn fp2_mul_xi(a: Fp2) Fp2 {
    return .{
        .c0 = fp_sub(fp_mul(9, a.c0), a.c1),
        .c1 = fp_add(a.c0, fp_mul(9, a.c1)),
    };
}

const Fp6 = struct { c0: Fp2, c1: Fp2, c2: Fp2 };

fn fp6_add(a: Fp6, b: Fp6) Fp6 {
    return .{ .c0 = fp2_add(a.c0, b.c0), .c1 = fp2_add(a.c1, b.c1), .c2 = fp2_add(a.c2, b.c2) };
}

fn fp6_sub(a: Fp6, b: Fp6) Fp6 {
    return .{ .c0 = fp2_sub(a.c0, b.c0), .c1 = fp2_sub(a.c1, b.c1), .c2 = fp2_sub(a.c2, b.c2) };
}

fn fp6_neg(a: Fp6) Fp6 {
    return .{ .c0 = fp2_neg(a.c0), .c1 = fp2_neg(a.c1), .c2 = fp2_neg(a.c2) };
}

fn fp6_mul(a: Fp6, b: Fp6) Fp6 {
    const t0 = fp2_mul(a.c0, b.c0);
    const t1 = fp2_mul(a.c1, b.c1);
    const t2 = fp2_mul(a.c2, b.c2);
    return .{
        .c0 = fp2_add(t0, fp2_mul_xi(fp2_sub(fp2_sub(fp2_mul(fp2_add(a.c1, a.c2), fp2_add(b.c1, b.c2)), t1), t2))),
        .c1 = fp2_add(fp2_sub(fp2_sub(fp2_mul(fp2_add(a.c0, a.c1), fp2_add(b.c0, b.c1)), t0), t1), fp2_mul_xi(t2)),
        .c2 = fp2_add(fp2_sub(fp2_sub(fp2_mul(fp2_add(a.c0, a.c2), fp2_add(b.c0, b.c2)), t0), t2), t1),
    };
}

fn fp6_mul_v(a: Fp6) Fp6 {
    return .{ .c0 = fp2_mul_xi(a.c2), .c1 = a.c0, .c2 = a.c1 };
}

fn fp6_scale_fp2(a: Fp6, b: Fp2) Fp6 {
    return .{ .c0 = fp2_mul(a.c0, b), .c1 = fp2_mul(a.c1, b), .c2 = fp2_mul(a.c2, b) };
}

fn fp6_mul_by_01(z: Fp6, c0: Fp2, c1: Fp2) Fp6 {
    const a = fp2_mul(z.c0, c0);
    const b = fp2_mul(z.c1, c1);
    return .{
        .c0 = fp2_add(a, fp2_mul_xi(fp2_sub(fp2_mul(c1, fp2_add(z.c1, z.c2)), b))),
        .c1 = fp2_sub(fp2_sub(fp2_mul(fp2_add(z.c0, z.c1), fp2_add(c0, c1)), a), b),
        .c2 = fp2_add(fp2_sub(fp2_mul(fp2_add(z.c0, z.c2), c0), a), b),
    };
}

fn fp6_inv(a: Fp6) Fp6 {
    const t0 = fp2_mul(a.c0, a.c0);
    const t1 = fp2_mul(a.c1, a.c1);
    const t2 = fp2_mul(a.c2, a.c2);
    const t3 = fp2_mul(a.c0, a.c1);
    const t4 = fp2_mul(a.c0, a.c2);
    const t5 = fp2_mul(a.c1, a.c2);
    const c0 = fp2_sub(t0, fp2_mul_xi(t5));
    const c1 = fp2_sub(fp2_mul_xi(t2), t3);
    const c2 = fp2_sub(t1, t4);
    const t6 = fp2_add(fp2_mul(a.c0, c0), fp2_mul_xi(fp2_add(fp2_mul(a.c2, c1), fp2_mul(a.c1, c2))));
    const inv = fp2_inv(t6);
    return .{
        .c0 = fp2_mul(c0, inv),
        .c1 = fp2_mul(c1, inv),
        .c2 = fp2_mul(c2, inv),
    };
}

fn fp2_from_w6(lo: u256, hi: u256) Fp2 {
    return .{ .c0 = fp_add(lo, fp_mul(9, hi)), .c1 = hi };
}

fn fp2_to_w6(a: Fp2) struct { lo: u256, hi: u256 } {
    return .{ .lo = fp_sub(a.c0, fp_mul(9, a.c1)), .hi = a.c1 };
}

fn fq12_even(a: Fq12) Fp6 {
    return .{
        .c0 = fp2_from_w6(a[0], a[6]),
        .c1 = fp2_from_w6(a[2], a[8]),
        .c2 = fp2_from_w6(a[4], a[10]),
    };
}

fn fq12_odd(a: Fq12) Fp6 {
    return .{
        .c0 = fp2_from_w6(a[1], a[7]),
        .c1 = fp2_from_w6(a[3], a[9]),
        .c2 = fp2_from_w6(a[5], a[11]),
    };
}

fn fq12_from_fp6_pair(even: Fp6, odd: Fp6) Fq12 {
    const e0 = fp2_to_w6(even.c0);
    const e1 = fp2_to_w6(even.c1);
    const e2 = fp2_to_w6(even.c2);
    const o0 = fp2_to_w6(odd.c0);
    const o1 = fp2_to_w6(odd.c1);
    const o2 = fp2_to_w6(odd.c2);
    var r: Fq12 = undefined;
    r[0] = e0.lo;
    r[6] = e0.hi;
    r[2] = e1.lo;
    r[8] = e1.hi;
    r[4] = e2.lo;
    r[10] = e2.hi;
    r[1] = o0.lo;
    r[7] = o0.hi;
    r[3] = o1.lo;
    r[9] = o1.hi;
    r[5] = o2.lo;
    r[11] = o2.hi;
    return r;
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

fn g2_eq(a: G2, b: G2) bool {
    if (a.inf or b.inf) return a.inf and b.inf;
    return fp2_eq(a.x, b.x) and fp2_eq(a.y, b.y);
}

fn g2_neg(pt: G2) G2 {
    if (pt.inf) return pt;
    return .{ .inf = false, .x = pt.x, .y = fp2_neg(pt.y) };
}

fn fp2_conjugate(a: Fp2) Fp2 {
    return .{ .c0 = a.c0, .c1 = fp_neg(a.c1) };
}

fn g2_psi(pt: G2) G2 {
    if (pt.inf) return pt;
    return .{
        .inf = false,
        .x = fp2_mul(psi_x, fp2_conjugate(pt.x)),
        .y = fp2_mul(psi_y, fp2_conjugate(pt.y)),
    };
}

fn g2_in_subgroup(pt: G2) bool {
    if (pt.inf) return true;
    return g2_eq(g2_psi(pt), g2_mul(pt, six_x_squared));
}

fn fq12_one() Fq12 {
    var r: Fq12 = @splat(0);
    r[0] = 1;
    return r;
}

fn fq12_eq(a: Fq12, b: Fq12) bool {
    return std.mem.eql(u256, &a, &b);
}

fn fq12_mul(a: Fq12, b: Fq12) Fq12 {
    const a0 = fq12_even(a);
    const a1 = fq12_odd(a);
    const b0 = fq12_even(b);
    const b1 = fq12_odd(b);
    const t0 = fp6_mul(a0, b0);
    const t1 = fp6_mul(a1, b1);
    const s = fp6_mul(fp6_add(a0, a1), fp6_add(b0, b1));
    return fq12_from_fp6_pair(fp6_add(t0, fp6_mul_v(t1)), fp6_sub(fp6_sub(s, t0), t1));
}

/// Sparse miller line `(c0 + c3 w + c4 w³)` times `f` (gnark MulBy034).
fn fq12_mul_034(f: Fq12, c0: u256, c3: Fp2, c4: Fp2) Fq12 {
    const z0 = fq12_even(f);
    const z1 = fq12_odd(f);
    const c0e = Fp2{ .c0 = c0, .c1 = 0 };
    const a = fp6_scale_fp2(z0, c0e);
    const b = fp6_mul_by_01(z1, c3, c4);
    const d = fp6_mul_by_01(fp6_add(z0, z1), fp2_add(c0e, c3), c4);
    return fq12_from_fp6_pair(fp6_add(a, fp6_mul_v(b)), fp6_sub(fp6_sub(d, a), b));
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

fn fq12_conjugate(a: Fq12) Fq12 {
    var r = a;
    var i: u32 = 1;
    while (i < 12) : (i += 2) r[i] = fp_neg(r[i]);
    return r;
}

fn fq12_square(a: Fq12) Fq12 {
    return fq12_mul(a, a);
}

fn fq12_expt(a: Fq12) Fq12 {
    var r = fq12_one();
    var i: i32 = 62;
    while (i >= 0) : (i -= 1) {
        r = fq12_square(r);
        if ((bn_x >> @intCast(i)) & 1 == 1) r = fq12_mul(r, a);
    }
    return r;
}

fn fq12_frobenius_square(a: Fq12) Fq12 {
    return fq12_frobenius(fq12_frobenius(a));
}

fn fq12_frobenius_cube(a: Fq12) Fq12 {
    return fq12_frobenius(fq12_frobenius_square(a));
}

/// `(p¹²-1)/r` via easy part + Duquesne–Ghammam hard part (gnark). Extra
/// cofactor is coprime to `r`, so the pairing-check (`== 1`) is unchanged.
fn fq12_pow_final(base: Fq12) Fq12 {
    const t0_easy = fq12_mul(fq12_conjugate(base), fq12_inv(base));
    const result = fq12_mul(fq12_frobenius_square(t0_easy), t0_easy);
    if (fq12_eq(result, fq12_one())) return result;

    var t: [5]Fq12 = undefined;
    t[0] = fq12_square(fq12_conjugate(fq12_expt(result)));
    t[1] = fq12_mul(t[0], fq12_square(t[0]));
    t[2] = fq12_conjugate(fq12_expt(t[1]));
    t[3] = fq12_conjugate(t[1]);
    t[1] = fq12_mul(t[2], t[3]);
    t[3] = fq12_square(t[2]);
    t[4] = fq12_mul(t[1], fq12_expt(t[3]));
    t[3] = fq12_mul(t[0], t[4]);
    t[0] = fq12_mul(result, fq12_mul(t[2], t[4]));
    t[0] = fq12_mul(fq12_frobenius(t[3]), t[0]);
    t[0] = fq12_mul(fq12_frobenius_square(t[4]), t[0]);
    t[2] = fq12_frobenius_cube(fq12_mul(fq12_conjugate(result), t[3]));
    return fq12_mul(t[2], t[0]);
}

fn fq12_set_fp2_at_w(r: *Fq12, a: Fp2, w_pow: u32) void {
    const coeffs = fp2_to_w6(a);
    r[w_pow] = coeffs.lo;
    r[w_pow + 6] = coeffs.hi;
}

/// Line of the twisted G2 chord/tangent, evaluated at G1 `p`.
/// Twist `(x w², y w³)` makes the slope `m w`, so the line is
/// `-y_p + (m x_p) w + (y - m x) w³` (vertical: `x_p - x w²`).
fn miller_mul_line(f: Fq12, r: G2, s: G2, p_pt: G1) Fq12 {
    if (!fp2_eq(r.x, s.x) or fp2_eq(r.y, s.y)) {
        const m = if (fp2_eq(r.x, s.x)) blk: {
            const xx = fp2_mul(r.x, r.x);
            break :blk fp2_div(.{ .c0 = fp_mul(3, xx.c0), .c1 = fp_mul(3, xx.c1) }, fp2_add(r.y, r.y));
        } else fp2_div(fp2_sub(s.y, r.y), fp2_sub(s.x, r.x));
        return fq12_mul_034(
            f,
            fp_neg(p_pt.y),
            fp2_mul(m, .{ .c0 = p_pt.x, .c1 = 0 }),
            fp2_sub(r.y, fp2_mul(m, r.x)),
        );
    }
    var ell: Fq12 = @splat(0);
    ell[0] = p_pt.x;
    fq12_set_fp2_at_w(&ell, fp2_neg(r.x), 2);
    return fq12_mul(f, ell);
}

fn fq12_inv(a: Fq12) Fq12 {
    const a0 = fq12_even(a);
    const a1 = fq12_odd(a);
    const t0 = fp6_sub(fp6_mul(a0, a0), fp6_mul_v(fp6_mul(a1, a1)));
    const t1 = fp6_inv(t0);
    return fq12_from_fp6_pair(fp6_mul(a0, t1), fp6_neg(fp6_mul(a1, t1)));
}

fn fq12_frobenius(a: Fq12) Fq12 {
    var r: Fq12 = @splat(0);
    r[0] = a[0];
    r[1] = fp_add(fp_mul(a[1], 0x1d8c8daef3eee1e81b2522ec5eb28ded6895e1cdfde6a43f5daa971f3fa65955), fp_mul(a[7], 0x217e400dc9351e774e34e2ac06ead4000d14d1e242b29c567e9c385ce480a71a));
    r[7] = fp_add(fp_mul(a[1], 0x246996f3b4fae7e6a6327cfe12150b8e747992778eeec7e5ca5cf05f80f362ac), fp_mul(a[7], 0x12d7c0c3ed42be419d2b22ca22ceca702eeb88c36a8b264dde75f4f798d6a3f2));
    r[2] = fp_add(fp_mul(a[2], 0x242b719062f6737b8481d22c6934ce844d72f250fd28d102c0d147b2f4d521a7), fp_mul(a[8], 0x359809094bd5c8e1b9c22d81246ffc2e794e17643ac198484b8d9094aa82536));
    r[8] = fp_add(fp_mul(a[2], 0x16c9e55061ebae204ba4cc8bd75a079432ae2a1d0b7c9dce1665d51c640fcba2), fp_mul(a[8], 0xc38dce27e3b2cae33ce738a184c89d94a0e78406b48f98a7b4f4463e3a7dba0));
    r[3] = fp_add(fp_mul(a[3], 0x21436d48fcb50cc60dd4ef1e69a0c1f0dd2949fa6df7b44cbb259ef7cb58d5ed), fp_mul(a[9], 0x18857a58f3b5bb3038a4311a86919d9c7c6c15f88a4f4f0831364cf35f78f771));
    r[9] = fp_add(fp_mul(a[3], 0x7c03cbcac41049a0704b5a7ec796f2b21807dc98fa25bd282d37f632623b0e3), fp_mul(a[9], 0xf20e129e47c9363aa7b569817e0966cba582096fa7a164080faed1f0d24275a));
    r[4] = fp_add(fp_mul(a[4], 0x2c84bbad27c3671562b7adefd44038ab3c0bbad96fc008e7d6998c82f7fc048b), fp_mul(a[10], 0xc33b1c70e4fd11b6d1eab6fcd18b99ad4afd096a8697e0c9c36d8ca3339a7b5));
    r[10] = fp_add(fp_mul(a[4], 0x2c145edbe7fd8aee9f3a80b03b0b1c923685d2ea1bdec763c13b4711cd2b8126), fp_mul(a[10], 0x3df92c5b96e3914559897c6ad411fb25b75afb7f8b1c1a56586ff93e080f8bc));
    r[5] = fp_add(fp_mul(a[5], 0x1b007294a55accce13fe08bea73305ff6bdac77c5371c546d428780a6e3dcfa8), fp_mul(a[11], 0x215d42e7ac7bd17cefe88dd8e6965b3adae92c974f501fe811493d72543a3977));
    r[11] = fp_add(fp_mul(a[5], 0x12acf2ca76fd0675a27fb246c7729f7db080cb99678e2ac024c6b8ee6e0c2c4b), fp_mul(a[11], 0x1563dbde3bd6d35ba4523cf7da4e525e2ba6a3151500054667f8140c6a3f2d9f));
    r[0] = fp_add(r[0], fp_mul(a[6], 0x12));
    r[6] = fp_mul(a[6], 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46);
    return r;
}

fn miller_loop(q: G2, p_pt: G1) Fq12 {
    var r = q;
    var f = fq12_one();
    // py_ecc `log_ate_loop_count = 63` (MSB of `ate_loop` is skipped).
    var i: i32 = 63;
    while (i >= 0) : (i -= 1) {
        f = miller_mul_line(fq12_square(f), r, r, p_pt);
        r = g2_double(r);
        if ((ate_loop >> @intCast(i)) & 1 == 1) {
            f = miller_mul_line(f, r, q, p_pt);
            r = g2_add(r, q);
        }
    }
    const q1 = g2_psi(q);
    const nq2 = g2_neg(g2_psi(q1));
    f = miller_mul_line(f, r, q1, p_pt);
    r = g2_add(r, q1);
    f = miller_mul_line(f, r, nq2, p_pt);
    return f;
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

test "bn254 pairing e(G,G2) is not one" {
    var input: [192]u8 = @splat(0);
    fill_g1_g2(&input, false);
    var out: [32]u8 = undefined;
    _ = try execute_pairing(&input, &out);
    try std.testing.expectEqual(@as(u8, 0), out[31]);
}

test "bn254 pairing e(2G,G2)*e(-G,G2)*e(-G,G2) is one" {
    var input: [576]u8 = @splat(0);
    fill_g1_g2(input[0..192], false);
    // 2G
    word.to_bytes_be(0x030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3, input[0..32]);
    word.to_bytes_be(0x15ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4, input[32..64]);
    fill_g1_g2(input[192..384], true);
    fill_g1_g2(input[384..576], true);
    var out: [32]u8 = undefined;
    _ = try execute_pairing(&input, &out);
    try std.testing.expectEqual(@as(u8, 1), out[31]);
}

test "bn254 pairing eest positive base vector is one" {
    const hex = "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002203e205db4f19b37b60121b83a7333706db86431c6d835849957ed8c3928ad7927dc7234fd11d3e8c36c59277c3e6f149d5cd3cfa9a62aee49f8130962b4b3b9195e8aa5b7827463722b8c153931579d3505566b4edf48d498e185f0509de15204bb53b8977e5f92a0bc372742c4830944a59b4fe6b1c0466e2a6dad122b5d2e104316c97997c17267a1bb67365523b4388e1306d66ea6e4d8f4a4a4b65f5c7d06e286b49c56f6293b2cea30764f0d5eabe5817905468a41f09b77588f692e8b081070efe3d4913dde35bba2513c426d065dee815c478700cef07180fb6146182432428b1490a4f25053d4c20c8723a73de6f0681bd3a8fca41008a6c3c288252d50f18403272e96c10135f96db0f8d0aec25033ebdffb88d2e7956c9bb198ec072462211ebc0a2f042f993d5bd76caf4adb5e99610dcf7c1d992595e6976aa3";
    var input: [384]u8 = undefined;
    _ = std.fmt.hexToBytes(&input, hex) catch unreachable;
    var out: [32]u8 = undefined;
    _ = try execute_pairing(&input, &out);
    try std.testing.expectEqual(@as(u8, 1), out[31]);
}

test "bn254 fp inv" {
    try std.testing.expectEqual(@as(u256, 1), fp_mul(7, fp_inv(7)));
}

test "bn254 g2 generator is in the r-torsion" {
    var buf: [192]u8 = @splat(0);
    fill_g1_g2(&buf, false);
    const q = try decode_g2(buf[64..]);
    try std.testing.expect(g2_in_subgroup(q));
}

test "bn254 fq12 inv * a is one" {
    var a: Fq12 = @splat(0);
    a[0] = 3;
    a[1] = 5;
    a[4] = 9;
    a[7] = 7;
    try std.testing.expect(fq12_eq(fq12_mul(a, fq12_inv(a)), fq12_one()));
}

test "bn254 fq12 frobenius matches pow p" {
    var a: Fq12 = @splat(0);
    a[0] = 3;
    a[1] = 5;
    a[6] = 11;
    a[7] = 7;
    try std.testing.expect(fq12_eq(fq12_frobenius(a), fq12_pow_u256(a, p)));
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
