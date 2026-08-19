//! Precompiles. `0x01` ecrecover, `0x02` sha256, `0x04` identity,
//! `0x05` modexp, `0x100` p256verify (Osaka). Others stay empty accounts.

const std = @import("std");
const gas_mod = @import("gas.zig");
const word = @import("u256.zig");
const fork_mod = @import("fork.zig");
const limits = @import("limits.zig");
const modexp = @import("modexp.zig");

const Curve = std.crypto.ecc.Secp256k1;
const secp256k1n: u256 = Curve.scalar.field_order;
const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Fork = fork_mod.Fork;

pub const ecrecover_address: u256 = 1;
pub const sha256_address: u256 = 2;
pub const identity_address: u256 = 4;
pub const modexp_address: u256 = 5;
pub const p256verify_address: u256 = 0x100;

pub fn is_precompile(address: u256, fork: Fork) bool {
    if (address == ecrecover_address or address == sha256_address or
        address == identity_address or address == modexp_address)
        return true;
    return address == p256verify_address and fork.at_least(.osaka);
}

pub fn gas_cost(address: u256, input: []const u8, fork: Fork) error{OutOfGas}!u64 {
    const words = (@as(u64, input.len) + 31) / 32;
    return switch (address) {
        ecrecover_address => gas_mod.gas_ecrecover,
        sha256_address => gas_mod.gas_sha256_base + words * gas_mod.gas_sha256_word,
        identity_address => gas_mod.gas_identity_base + words * gas_mod.gas_identity_word,
        modexp_address => modexp.gas_cost(input, fork),
        p256verify_address => gas_mod.gas_p256verify,
        else => unreachable,
    };
}

/// Writes output into `out`. Returns bytes written. Empty ecrecover is `0`.
pub fn execute(address: u256, input: []const u8, out: []u8, fork: Fork) error{ OutOfGas, OutputTooLarge }!u32 {
    return switch (address) {
        ecrecover_address => exec_ecrecover(input, out),
        sha256_address => exec_sha256(input, out),
        identity_address => exec_identity(input, out),
        modexp_address => modexp.execute(input, out, fork),
        p256verify_address => exec_p256verify(input, out),
        else => unreachable,
    };
}

fn exec_ecrecover(input: []const u8, out: []u8) error{OutputTooLarge}!u32 {
    const recovered = ecrecover_from_calldata(input) orelse return 0;
    if (out.len < 32) return error.OutputTooLarge;
    out[0..32].* = recovered;
    return 32;
}

fn exec_sha256(input: []const u8, out: []u8) error{OutputTooLarge}!u32 {
    if (out.len < 32) return error.OutputTooLarge;
    std.crypto.hash.sha2.Sha256.hash(input, out[0..32], .{});
    return 32;
}

fn exec_identity(input: []const u8, out: []u8) error{OutputTooLarge}!u32 {
    if (input.len > out.len) return error.OutputTooLarge;
    if (input.len > 0) @memcpy(out[0..input.len], input);
    return @intCast(input.len);
}

fn exec_p256verify(input: []const u8, out: []u8) error{OutputTooLarge}!u32 {
    if (input.len != limits.p256verify_input_bytes) return 0;
    if (out.len < 32) return error.OutputTooLarge;
    const P256Curve = std.crypto.ecc.P256;
    const hash = input[0..32].*;
    const r_bytes = input[32..64].*;
    const s_bytes = input[64..96].*;
    const qx = input[96..128].*;
    const qy = input[128..160].*;
    const r = P256Curve.scalar.Scalar.fromBytes(r_bytes, .big) catch return 0;
    const s = P256Curve.scalar.Scalar.fromBytes(s_bytes, .big) catch return 0;
    if (r.isZero() or s.isZero()) return 0;
    const q = P256Curve.fromSerializedAffineCoordinates(qx, qy, .big) catch return 0;
    q.rejectIdentity() catch return 0;

    var z_pad: [48]u8 = @splat(0);
    @memcpy(z_pad[16..], &hash);
    const z = P256Curve.scalar.Scalar.fromBytes48(z_pad, .big);
    const s_inv = s.invert();
    const v1 = z.mul(s_inv).toBytes(.little);
    const v2 = r.mul(s_inv).toBytes(.little);
    const recovered = P256Curve.mulDoubleBasePublic(P256Curve.basePoint, v1, q, v2, .little) catch return 0;
    const rx = recovered.affineCoordinates().x.toBytes(.big);
    var r_pad: [48]u8 = @splat(0);
    @memcpy(r_pad[16..], &rx);
    const vr = P256Curve.scalar.Scalar.fromBytes48(r_pad, .big);
    if (!r.equivalent(vr)) return 0;

    @memset(out[0..32], 0);
    out[31] = 1;
    return 32;
}

/// Returns 32-byte left-padded address, or null if the signature does not recover.
pub fn ecrecover(hash: [32]u8, v: u256, r: u256, s: u256) ?[32]u8 {
    if (v != 27 and v != 28) return null;
    if (r == 0 or r >= secp256k1n) return null;
    if (s == 0 or s >= secp256k1n) return null;

    var r_bytes: [32]u8 = undefined;
    var s_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &r_bytes, r, .big);
    std.mem.writeInt(u256, &s_bytes, s, .big);

    var sec1: [33]u8 = undefined;
    sec1[0] = if (v == 28) 0x03 else 0x02;
    @memcpy(sec1[1..], &r_bytes);
    const R = Curve.fromSec1(&sec1) catch return null;

    var z = std.mem.readInt(u256, &hash, .big);
    z %= secp256k1n;
    var z_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &z_bytes, z, .big);

    const r_scalar = Curve.scalar.Scalar.fromBytes(r_bytes, .big) catch return null;
    const s_scalar = Curve.scalar.Scalar.fromBytes(s_bytes, .big) catch return null;
    const z_scalar = Curve.scalar.Scalar.fromBytes(z_bytes, .big) catch return null;
    const r_inv = r_scalar.invert();
    const coeff_r = s_scalar.mul(r_inv).toBytes(.big);
    const coeff_g = z_scalar.neg().mul(r_inv).toBytes(.big);

    const sR = R.mul(coeff_r, .big) catch return null;
    const Q = if (z == 0)
        sR
    else blk: {
        const zG = Curve.basePoint.mul(coeff_g, .big) catch return null;
        break :blk sR.add(zG);
    };
    Q.rejectIdentity() catch return null;

    const uncompressed = Q.toUncompressedSec1();
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(uncompressed[1..], &digest, .{});
    var out: [32]u8 = undefined;
    @memset(&out, 0);
    @memcpy(out[12..], digest[12..]);
    return out;
}

pub fn ecrecover_from_calldata(data: []const u8) ?[32]u8 {
    var buf: [128]u8 = undefined;
    @memset(&buf, 0);
    const copy_len = @min(data.len, buf.len);
    if (copy_len > 0) @memcpy(buf[0..copy_len], data[0..copy_len]);
    const hash = buf[0..32].*;
    const v = word.from_bytes_be(buf[32..64]);
    const r = word.from_bytes_be(buf[64..96]);
    const s = word.from_bytes_be(buf[96..128]);
    return ecrecover(hash, v, r, s);
}

fn address_from_pubkey(public_key: std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256.PublicKey) [32]u8 {
    const uncompressed = public_key.toUncompressedSec1();
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(uncompressed[1..], &digest, .{});
    var out: [32]u8 = undefined;
    @memset(&out, 0);
    @memcpy(out[12..], digest[12..]);
    return out;
}

test "sha256 empty" {
    var out: [32]u8 = undefined;
    const len = try exec_sha256(&[_]u8{}, &out);
    try std.testing.expectEqual(@as(u32, 32), len);
    try std.testing.expectEqual(@as(u8, 0xe3), out[0]);
    try std.testing.expectEqual(@as(u8, 0x55), out[31]);
}

test "identity copies input" {
    const input = [_]u8{ 0x11, 0x22, 0x33 };
    var out: [8]u8 = undefined;
    const len = try exec_identity(&input, &out);
    try std.testing.expectEqual(@as(u32, 3), len);
    try std.testing.expectEqualSlices(u8, &input, out[0..3]);
}

test "ecrecover round trip" {
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
    var seed: [Ecdsa.KeyPair.seed_length]u8 = undefined;
    @memset(&seed, 0x42);
    const kp = try Ecdsa.KeyPair.generateDeterministic(seed);
    const hash = hex32("18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c");
    const sig = try kp.signPrehashed(hash, null);
    const r = word.from_bytes_be(&sig.r);
    const s = word.from_bytes_be(&sig.s);
    const want = address_from_pubkey(kp.public_key);
    const rec27 = ecrecover(hash, 27, r, s);
    const rec28 = ecrecover(hash, 28, r, s);
    const recovered = if (rec27) |a| (if (std.mem.eql(u8, &a, &want)) a else rec28) else rec28;
    const got = recovered orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "p256verify round trip" {
    var seed: [P256.KeyPair.seed_length]u8 = undefined;
    @memset(&seed, 0x11);
    const kp = try P256.KeyPair.generateDeterministic(seed);
    const hash = hex32("18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c");
    const sig = try kp.signPrehashed(hash, null);
    const uncompressed = kp.public_key.toUncompressedSec1();
    var input: [160]u8 = undefined;
    @memcpy(input[0..32], &hash);
    @memcpy(input[32..64], &sig.r);
    @memcpy(input[64..96], &sig.s);
    @memcpy(input[96..128], uncompressed[1..33]);
    @memcpy(input[128..160], uncompressed[33..65]);
    var out: [32]u8 = undefined;
    const n = try exec_p256verify(&input, &out);
    try std.testing.expectEqual(@as(u32, 32), n);
    try std.testing.expectEqual(@as(u8, 1), out[31]);
}

test "p256verify rejects short input" {
    var out: [32]u8 = undefined;
    const n = try exec_p256verify(&[_]u8{1, 2, 3}, &out);
    try std.testing.expectEqual(@as(u32, 0), n);
}

fn hex32(text: *const [64]u8) [32]u8 {
    var out: [32]u8 = undefined;
    var index: u32 = 0;
    while (index < 32) : (index += 1) {
        out[index] = std.fmt.parseInt(u8, text[index * 2 .. index * 2 + 2], 16) catch unreachable;
    }
    return out;
}
