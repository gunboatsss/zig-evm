//! EIP-2537 BLS12-381 precompiles `0x0b`–`0x11`, via vendored blst.

const std = @import("std");
const gas_mod = @import("gas.zig");

const c = @import("blst_c");

const g1_len: usize = 128;
const g2_len: usize = 256;
const fp_len: usize = 64;
const scalar_len: usize = 32;
const g1_pair_len: usize = 160;
const g2_pair_len: usize = 288;
const pairing_pair_len: usize = 384;

const g1_discount = [_]u64{
    1000, 949, 848, 797, 764, 750, 738, 728, 719, 712, 705, 698, 692, 687, 682, 677,
    673,  669, 665, 661, 658, 654, 651, 648, 645, 642, 640, 637, 635, 632, 630, 627,
    625,  623, 621, 619, 617, 615, 613, 611, 609, 608, 606, 604, 603, 601, 599, 598,
    596,  595, 593, 592, 591, 589, 588, 586, 585, 584, 582, 581, 580, 579, 577, 576,
    575,  574, 573, 572, 570, 569, 568, 567, 566, 565, 564, 563, 562, 561, 560, 559,
    558,  557, 556, 555, 554, 553, 552, 551, 550, 549, 548, 547, 547, 546, 545, 544,
    543,  542, 541, 540, 540, 539, 538, 537, 536, 536, 535, 534, 533, 532, 532, 531,
    530,  529, 528, 528, 527, 526, 525, 525, 524, 523, 522, 522, 521, 520, 520, 519,
};

const g2_discount = [_]u64{
    1000, 1000, 923, 884, 855, 832, 812, 796, 782, 770, 759, 749, 740, 732, 724, 717,
    711,  704,  699, 693, 688, 683, 679, 674, 670, 666, 663, 659, 655, 652, 649, 646,
    643,  640,  637, 634, 632, 629, 627, 624, 622, 620, 618, 615, 613, 611, 609, 607,
    606,  604,  602, 600, 598, 597, 595, 593, 592, 590, 589, 587, 586, 584, 583, 582,
    580,  579,  578, 576, 575, 574, 573, 571, 570, 569, 568, 567, 566, 565, 563, 562,
    561,  560,  559, 558, 557, 556, 555, 554, 553, 552, 552, 551, 550, 549, 548, 547,
    546,  545,  545, 544, 543, 542, 541, 541, 540, 539, 538, 537, 537, 536, 535, 535,
    534,  533,  532, 532, 531, 530, 530, 529, 528, 528, 527, 526, 526, 525, 524, 524,
};

const fp_mod: u512 = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

const G1 = struct {
    inf: bool,
    p: c.blst_p1_affine,
};

const G2 = struct {
    inf: bool,
    p: c.blst_p2_affine,
};

pub fn gas_g1_add(input: []const u8) u64 {
    _ = input;
    return gas_mod.gas_bls_g1add;
}

pub fn gas_g2_add(input: []const u8) u64 {
    _ = input;
    return gas_mod.gas_bls_g2add;
}

pub fn gas_g1_map(input: []const u8) u64 {
    _ = input;
    return gas_mod.gas_bls_g1map;
}

pub fn gas_g2_map(input: []const u8) u64 {
    _ = input;
    return gas_mod.gas_bls_g2map;
}

pub fn gas_g1_msm(input: []const u8) u64 {
    return msm_gas(input.len, g1_pair_len, gas_mod.gas_bls_g1mul, &g1_discount);
}

pub fn gas_g2_msm(input: []const u8) u64 {
    return msm_gas(input.len, g2_pair_len, gas_mod.gas_bls_g2mul, &g2_discount);
}

pub fn gas_pairing(input: []const u8) u64 {
    if (input.len == 0 or input.len % pairing_pair_len != 0) return 0;
    const k = input.len / pairing_pair_len;
    return gas_mod.gas_bls_pairing_base + @as(u64, k) * gas_mod.gas_bls_pairing_pair;
}

fn msm_gas(len: usize, pair_len: usize, mul: u64, discount: []const u64) u64 {
    if (len == 0 or len % pair_len != 0) return 0;
    const k = len / pair_len;
    const d = if (k <= discount.len) discount[k - 1] else discount[discount.len - 1];
    return @as(u64, k) * mul * d / 1000;
}

pub fn execute_g1_add(input: []const u8, out: []u8) error{ OutputTooLarge, PrecompileFailed }!u32 {
    if (input.len != 256) return error.PrecompileFailed;
    if (out.len < g1_len) return error.OutputTooLarge;
    const a = try decode_g1(input[0..g1_len], false);
    const b = try decode_g1(input[g1_len..], false);
    encode_g1(g1_add(a, b), out[0..g1_len]);
    return @intCast(g1_len);
}

pub fn execute_g2_add(input: []const u8, out: []u8) error{ OutputTooLarge, PrecompileFailed }!u32 {
    if (input.len != 512) return error.PrecompileFailed;
    if (out.len < g2_len) return error.OutputTooLarge;
    const a = try decode_g2(input[0..g2_len], false);
    const b = try decode_g2(input[g2_len..], false);
    encode_g2(g2_add(a, b), out[0..g2_len]);
    return @intCast(g2_len);
}

pub fn execute_g1_msm(input: []const u8, out: []u8) error{ OutputTooLarge, PrecompileFailed }!u32 {
    if (input.len == 0 or input.len % g1_pair_len != 0) return error.PrecompileFailed;
    if (out.len < g1_len) return error.OutputTooLarge;
    const k = input.len / g1_pair_len;
    var acc = G1{ .inf = true, .p = std.mem.zeroes(c.blst_p1_affine) };
    var i: usize = 0;
    while (i < k) : (i += 1) {
        const slice = input[i * g1_pair_len ..][0..g1_pair_len];
        const pt = try decode_g1(slice[0..g1_len], true);
        const product = g1_mul(pt, slice[g1_len..]);
        acc = g1_add(acc, product);
    }
    encode_g1(acc, out[0..g1_len]);
    return @intCast(g1_len);
}

pub fn execute_g2_msm(input: []const u8, out: []u8) error{ OutputTooLarge, PrecompileFailed }!u32 {
    if (input.len == 0 or input.len % g2_pair_len != 0) return error.PrecompileFailed;
    if (out.len < g2_len) return error.OutputTooLarge;
    const k = input.len / g2_pair_len;
    var acc = G2{ .inf = true, .p = std.mem.zeroes(c.blst_p2_affine) };
    var i: usize = 0;
    while (i < k) : (i += 1) {
        const slice = input[i * g2_pair_len ..][0..g2_pair_len];
        const pt = try decode_g2(slice[0..g2_len], true);
        const product = g2_mul(pt, slice[g2_len..]);
        acc = g2_add(acc, product);
    }
    encode_g2(acc, out[0..g2_len]);
    return @intCast(g2_len);
}

pub fn execute_pairing(input: []const u8, out: []u8) error{ OutputTooLarge, PrecompileFailed }!u32 {
    if (input.len == 0 or input.len % pairing_pair_len != 0) return error.PrecompileFailed;
    if (out.len < 32) return error.OutputTooLarge;
    const k = input.len / pairing_pair_len;
    var acc = c.blst_fp12_one().*;
    var i: usize = 0;
    while (i < k) : (i += 1) {
        const slice = input[i * pairing_pair_len ..][0..pairing_pair_len];
        const p1 = try decode_g1(slice[0..g1_len], true);
        const p2 = try decode_g2(slice[g1_len..], true);
        if (p1.inf or p2.inf) continue;
        var miller: c.blst_fp12 = undefined;
        c.blst_miller_loop(&miller, &p2.p, &p1.p);
        var next: c.blst_fp12 = undefined;
        c.blst_fp12_mul(&next, &acc, &miller);
        acc = next;
    }
    var fin: c.blst_fp12 = undefined;
    c.blst_final_exp(&fin, &acc);
    @memset(out[0..32], 0);
    if (c.blst_fp12_is_one(&fin)) out[31] = 1;
    return 32;
}

pub fn execute_map_fp_to_g1(input: []const u8, out: []u8) error{ OutputTooLarge, PrecompileFailed }!u32 {
    if (input.len != fp_len) return error.PrecompileFailed;
    if (out.len < g1_len) return error.OutputTooLarge;
    var u: c.blst_fp = undefined;
    try fp_from_bytes(&u, input[0..fp_len]);
    var jac: c.blst_p1 = undefined;
    c.blst_map_to_g1(&jac, &u, null);
    var aff: c.blst_p1_affine = undefined;
    c.blst_p1_to_affine(&aff, &jac);
    encode_g1(.{ .inf = c.blst_p1_affine_is_inf(&aff), .p = aff }, out[0..g1_len]);
    return @intCast(g1_len);
}

pub fn execute_map_fp2_to_g2(input: []const u8, out: []u8) error{ OutputTooLarge, PrecompileFailed }!u32 {
    if (input.len != 128) return error.PrecompileFailed;
    if (out.len < g2_len) return error.OutputTooLarge;
    var u: c.blst_fp2 = undefined;
    try fp_from_bytes(&u.fp[0], input[0..fp_len]);
    try fp_from_bytes(&u.fp[1], input[fp_len..128]);
    var jac: c.blst_p2 = undefined;
    c.blst_map_to_g2(&jac, &u, null);
    var aff: c.blst_p2_affine = undefined;
    c.blst_p2_to_affine(&aff, &jac);
    encode_g2(.{ .inf = c.blst_p2_affine_is_inf(&aff), .p = aff }, out[0..g2_len]);
    return @intCast(g2_len);
}

fn fp_from_bytes(out: *c.blst_fp, buf: []const u8) !void {
    std.debug.assert(buf.len == fp_len);
    const v = std.mem.readInt(u512, buf[0..64], .big);
    if (v >= fp_mod) return error.PrecompileFailed;
    var be48: [48]u8 = undefined;
    @memcpy(&be48, buf[16..64]);
    c.blst_fp_from_bendian(out, &be48);
}

fn decode_g1(buf: []const u8, subgroup: bool) !G1 {
    if (buf.len != g1_len) return error.PrecompileFailed;
    if (std.mem.allEqual(u8, buf, 0)) {
        return .{ .inf = true, .p = std.mem.zeroes(c.blst_p1_affine) };
    }
    var p: c.blst_p1_affine = undefined;
    try fp_from_bytes(&p.x, buf[0..fp_len]);
    try fp_from_bytes(&p.y, buf[fp_len..g1_len]);
    if (!c.blst_p1_affine_on_curve(&p)) return error.PrecompileFailed;
    if (subgroup and !c.blst_p1_affine_in_g1(&p)) return error.PrecompileFailed;
    return .{ .inf = c.blst_p1_affine_is_inf(&p), .p = p };
}

fn decode_g2(buf: []const u8, subgroup: bool) !G2 {
    if (buf.len != g2_len) return error.PrecompileFailed;
    if (std.mem.allEqual(u8, buf, 0)) {
        return .{ .inf = true, .p = std.mem.zeroes(c.blst_p2_affine) };
    }
    var p: c.blst_p2_affine = undefined;
    try fp_from_bytes(&p.x.fp[0], buf[0..fp_len]);
    try fp_from_bytes(&p.x.fp[1], buf[fp_len .. 2 * fp_len]);
    try fp_from_bytes(&p.y.fp[0], buf[2 * fp_len .. 3 * fp_len]);
    try fp_from_bytes(&p.y.fp[1], buf[3 * fp_len .. g2_len]);
    if (!c.blst_p2_affine_on_curve(&p)) return error.PrecompileFailed;
    if (subgroup and !c.blst_p2_affine_in_g2(&p)) return error.PrecompileFailed;
    return .{ .inf = c.blst_p2_affine_is_inf(&p), .p = p };
}

fn encode_fp(fp: c.blst_fp, out: []u8) void {
    std.debug.assert(out.len == fp_len);
    @memset(out, 0);
    var be48: [48]u8 = undefined;
    c.blst_bendian_from_fp(&be48, &fp);
    @memcpy(out[16..64], &be48);
}

fn encode_g1(pt: G1, out: []u8) void {
    @memset(out, 0);
    if (pt.inf) return;
    encode_fp(pt.p.x, out[0..fp_len]);
    encode_fp(pt.p.y, out[fp_len..g1_len]);
}

fn encode_g2(pt: G2, out: []u8) void {
    @memset(out, 0);
    if (pt.inf) return;
    encode_fp(pt.p.x.fp[0], out[0..fp_len]);
    encode_fp(pt.p.x.fp[1], out[fp_len .. 2 * fp_len]);
    encode_fp(pt.p.y.fp[0], out[2 * fp_len .. 3 * fp_len]);
    encode_fp(pt.p.y.fp[1], out[3 * fp_len .. g2_len]);
}

fn g1_add(a: G1, b: G1) G1 {
    if (a.inf) return b;
    if (b.inf) return a;
    var ja: c.blst_p1 = undefined;
    var jb: c.blst_p1 = undefined;
    var jr: c.blst_p1 = undefined;
    var aff: c.blst_p1_affine = undefined;
    c.blst_p1_from_affine(&ja, &a.p);
    c.blst_p1_from_affine(&jb, &b.p);
    c.blst_p1_add_or_double(&jr, &ja, &jb);
    c.blst_p1_to_affine(&aff, &jr);
    return .{ .inf = c.blst_p1_affine_is_inf(&aff), .p = aff };
}

fn g2_add(a: G2, b: G2) G2 {
    if (a.inf) return b;
    if (b.inf) return a;
    var ja: c.blst_p2 = undefined;
    var jb: c.blst_p2 = undefined;
    var jr: c.blst_p2 = undefined;
    var aff: c.blst_p2_affine = undefined;
    c.blst_p2_from_affine(&ja, &a.p);
    c.blst_p2_from_affine(&jb, &b.p);
    c.blst_p2_add_or_double(&jr, &ja, &jb);
    c.blst_p2_to_affine(&aff, &jr);
    return .{ .inf = c.blst_p2_affine_is_inf(&aff), .p = aff };
}

fn scalar_le(be: []const u8) [32]u8 {
    std.debug.assert(be.len == scalar_len);
    var le: [32]u8 = undefined;
    var i: usize = 0;
    while (i < 32) : (i += 1) le[i] = be[31 - i];
    return le;
}

fn g1_mul(pt: G1, scalar_be: []const u8) G1 {
    if (pt.inf or std.mem.allEqual(u8, scalar_be, 0)) {
        return .{ .inf = true, .p = std.mem.zeroes(c.blst_p1_affine) };
    }
    var jac: c.blst_p1 = undefined;
    var out: c.blst_p1 = undefined;
    var aff: c.blst_p1_affine = undefined;
    c.blst_p1_from_affine(&jac, &pt.p);
    const le = scalar_le(scalar_be);
    c.blst_p1_mult(&out, &jac, &le, 256);
    c.blst_p1_to_affine(&aff, &out);
    return .{ .inf = c.blst_p1_affine_is_inf(&aff), .p = aff };
}

fn g2_mul(pt: G2, scalar_be: []const u8) G2 {
    if (pt.inf or std.mem.allEqual(u8, scalar_be, 0)) {
        return .{ .inf = true, .p = std.mem.zeroes(c.blst_p2_affine) };
    }
    var jac: c.blst_p2 = undefined;
    var outp: c.blst_p2 = undefined;
    var aff: c.blst_p2_affine = undefined;
    c.blst_p2_from_affine(&jac, &pt.p);
    const le = scalar_le(scalar_be);
    c.blst_p2_mult(&outp, &jac, &le, 256);
    c.blst_p2_to_affine(&aff, &outp);
    return .{ .inf = c.blst_p2_affine_is_inf(&aff), .p = aff };
}

test "bls12 g1 add inf plus inf is inf" {
    var input: [256]u8 = @splat(0);
    var out: [128]u8 = undefined;
    const n = try execute_g1_add(&input, &out);
    try std.testing.expectEqual(@as(u32, 128), n);
    try std.testing.expect(std.mem.allEqual(u8, &out, 0));
}

test "bls12 g1 add rejects short input" {
    var out: [128]u8 = undefined;
    try std.testing.expectError(error.PrecompileFailed, execute_g1_add(&[_]u8{1}, &out));
}
