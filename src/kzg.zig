//! EIP-4844 `POINT_EVALUATION` precompile at `0x0a`.
//! C-KZG-4844 plus blst; the setup heap-allocates once per process.

const std = @import("std");
const limits = @import("limits.zig");
const word = @import("u256.zig");

const c = @import("ckzg_c");

const input_len: u32 = limits.kzg_input_bytes;
const output_len: u32 = limits.kzg_output_bytes;
const versioned_hash_version: u8 = 0x01;
const setup_txt = @import("kzg_trusted_setup_txt").txt;

/// BLS12-381 scalar field modulus, big-endian.
const bls_modulus = [_]u8{
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48,
    0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
};

var settings_cell: c.KZGSettings = undefined;
var settings_ready: bool = false;
var settings_mu: std.c.pthread_mutex_t = std.c.PTHREAD_MUTEX_INITIALIZER;

pub fn execute(input: []const u8, out: []u8) error{ OutputTooLarge, PrecompileFailed }!u32 {
    if (input.len != input_len) return error.PrecompileFailed;
    if (out.len < output_len) return error.OutputTooLarge;

    const versioned = input[0..32];
    const z_slice = input[32..64];
    const y_slice = input[64..96];
    const commitment = input[96..144];
    const proof = input[144..192];
    const want = versioned_hash(commitment);
    if (!std.mem.eql(u8, versioned, &want)) return error.PrecompileFailed;

    var z: c.Bytes32 = undefined;
    var y: c.Bytes32 = undefined;
    var commit: c.Bytes48 = undefined;
    var prf: c.Bytes48 = undefined;
    @memcpy(&z.bytes, z_slice);
    @memcpy(&y.bytes, y_slice);
    @memcpy(&commit.bytes, commitment);
    @memcpy(&prf.bytes, proof);

    var ok = false;
    const ret = c.verify_kzg_proof(&ok, &commit, &z, &y, &prf, settings());
    if (ret != c.C_KZG_OK or !ok) return error.PrecompileFailed;

    word.to_bytes_be(limits.kzg_field_elements_per_blob, out[0..32]);
    @memcpy(out[32..64], &bls_modulus);
    return output_len;
}

fn versioned_hash(commitment: *const [48]u8) [32]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(commitment, &hash, .{});
    hash[0] = versioned_hash_version;
    return hash;
}

fn settings() *const c.KZGSettings {
    _ = std.c.pthread_mutex_lock(&settings_mu);
    defer _ = std.c.pthread_mutex_unlock(&settings_mu);
    if (!settings_ready) {
        load_settings() catch |err| std.debug.panic("kzg trusted setup: {s}", .{@errorName(err)});
        settings_ready = true;
    }
    return &settings_cell;
}

fn load_settings() !void {
    const decoded = try decode_setup(std.heap.page_allocator);
    defer {
        std.heap.page_allocator.free(decoded.g1_lagrange);
        std.heap.page_allocator.free(decoded.g2_monomial);
        std.heap.page_allocator.free(decoded.g1_monomial);
    }
    const ret = c.load_trusted_setup(
        &settings_cell,
        decoded.g1_monomial.ptr,
        decoded.g1_monomial.len,
        decoded.g1_lagrange.ptr,
        decoded.g1_lagrange.len,
        decoded.g2_monomial.ptr,
        decoded.g2_monomial.len,
        0,
    );
    if (ret != c.C_KZG_OK) return error.TrustedSetup;
}

const DecodedSetup = struct {
    g1_lagrange: []u8,
    g2_monomial: []u8,
    g1_monomial: []u8,
};

fn decode_setup(allocator: std.mem.Allocator) !DecodedSetup {
    var it = std.mem.tokenizeAny(u8, setup_txt, " \t\r\n");
    const n_g1 = try parse_count(&it);
    const n_g2 = try parse_count(&it);
    const g1_lagrange = try decode_points(allocator, &it, n_g1, 48);
    errdefer allocator.free(g1_lagrange);
    const g2_monomial = try decode_points(allocator, &it, n_g2, 96);
    errdefer allocator.free(g2_monomial);
    const g1_monomial = try decode_points(allocator, &it, n_g1, 48);
    return .{
        .g1_lagrange = g1_lagrange,
        .g2_monomial = g2_monomial,
        .g1_monomial = g1_monomial,
    };
}

fn parse_count(it: anytype) !usize {
    const token = it.next() orelse return error.TrustedSetup;
    return std.fmt.parseInt(usize, token, 10);
}

fn decode_points(allocator: std.mem.Allocator, it: anytype, count: usize, point_size: usize) ![]u8 {
    const out = try allocator.alloc(u8, count * point_size);
    errdefer allocator.free(out);
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const hex = it.next() orelse return error.TrustedSetup;
        if (hex.len != point_size * 2) return error.TrustedSetup;
        _ = std.fmt.hexToBytes(out[i * point_size ..][0..point_size], hex) catch return error.TrustedSetup;
    }
    return out;
}

test "point evaluation rejects short input" {
    var out: [64]u8 = undefined;
    try std.testing.expectError(error.PrecompileFailed, execute(&[_]u8{ 1, 2, 3 }, &out));
}

test "point evaluation rejects versioned hash mismatch" {
    var input: [192]u8 = @splat(0);
    input[0] = 0x01;
    var out: [64]u8 = undefined;
    try std.testing.expectError(error.PrecompileFailed, execute(&input, &out));
}

test "point evaluation round trip" {
    var blob: c.Blob = std.mem.zeroes(c.Blob);
    blob.bytes[31] = 1;
    const s = settings();
    var commitment: c.KZGCommitment = undefined;
    try std.testing.expect(c.blob_to_kzg_commitment(&commitment, &blob, s) == c.C_KZG_OK);
    var z: c.Bytes32 = std.mem.zeroes(c.Bytes32);
    var proof: c.KZGProof = undefined;
    var y: c.Bytes32 = undefined;
    try std.testing.expect(c.compute_kzg_proof(&proof, &y, &blob, &z, s) == c.C_KZG_OK);
    const hash = versioned_hash(&commitment.bytes);

    var input: [192]u8 = undefined;
    @memcpy(input[0..32], &hash);
    @memcpy(input[32..64], &z.bytes);
    @memcpy(input[64..96], &y.bytes);
    @memcpy(input[96..144], &commitment.bytes);
    @memcpy(input[144..192], &proof.bytes);

    var out: [64]u8 = undefined;
    const n = try execute(&input, &out);
    try std.testing.expectEqual(@as(u32, 64), n);
    try std.testing.expectEqual(@as(u256, 4096), word.from_bytes_be(out[0..32]));
    try std.testing.expectEqualSlices(u8, &bls_modulus, out[32..64]);

    input[191] ^= 1;
    try std.testing.expectError(error.PrecompileFailed, execute(&input, &out));
}
