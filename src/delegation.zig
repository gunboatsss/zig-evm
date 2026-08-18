//! EIP-7702 EOA delegation: designation bytes, authority recovery, code follow.

const std = @import("std");
const precompile = @import("precompile.zig");
const rlp = @import("rlp.zig");
const word = @import("u256.zig");

const secp256k1n: u256 = std.crypto.ecc.Secp256k1.scalar.field_order;
const secp256k1n_half: u256 = secp256k1n / 2;

pub const designation_len: u32 = 23;
const marker = [_]u8{ 0xef, 0x01, 0x00 };

pub const Authorization = struct {
    chain_id: u256,
    address: u256,
    nonce: u64,
    y_parity: u8,
    r: u256,
    s: u256,
};

pub fn is_valid(code: []const u8) bool {
    return code.len == designation_len and std.mem.eql(u8, code[0..3], &marker);
}

pub fn delegated_address(code: []const u8) ?u256 {
    if (!is_valid(code)) return null;
    var padded: [32]u8 = @splat(0);
    @memcpy(padded[12..32], code[3..23]);
    return word.to_address(word.from_bytes_be(&padded));
}

pub fn designation(address: u256) [designation_len]u8 {
    var out: [designation_len]u8 = undefined;
    out[0..3].* = marker;
    var bytes: [32]u8 = undefined;
    word.to_bytes_be(address, &bytes);
    @memcpy(out[3..23], bytes[12..32]);
    return out;
}

/// Recover the signing authority, or null if the signature is invalid.
pub fn recover_authority(auth: Authorization) ?u256 {
    if (auth.y_parity > 1) return null;
    if (auth.r == 0 or auth.r >= secp256k1n) return null;
    if (auth.s == 0 or auth.s > secp256k1n_half) return null;
    const hash = rlp.auth_signing_hash(auth.chain_id, auth.address, auth.nonce);
    const recovered = precompile.ecrecover(hash, 27 + auth.y_parity, auth.r, auth.s) orelse return null;
    return word.to_address(word.from_bytes_be(&recovered));
}

test "designation is 23 bytes starting ef0100" {
    const code = designation(0x11);
    try std.testing.expect(is_valid(&code));
    try std.testing.expectEqual(@as(u256, 0x11), delegated_address(&code).?);
    try std.testing.expect(delegated_address(&[_]u8{0x00}) == null);
}

test "recover_authority from EEST clz set_code tuple" {
    const auth = Authorization{
        .chain_id = 0,
        .address = 0x3d8e2d77bca8c0ed68f6d4860444bad2cc2cd661,
        .nonce = 0,
        .y_parity = 1,
        .r = 0xd7e81ad52b1ff78769c3b925b06176b76280242c83ebaf4cdb624820ab2b08db,
        .s = 0x0367ba5e94031aac8cfb792d405da03d4a7874fb4f4cd37e653f56271e9522e6,
    };
    try std.testing.expectEqual(
        @as(u256, 0x89873a93c67fc34d662483a081ebaabe443ea62f),
        recover_authority(auth).?,
    );
}
