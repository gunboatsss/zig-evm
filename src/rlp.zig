//! Minimal RLP for `CREATE` address and EIP-7702 authorization signing hashes.

const std = @import("std");
const word = @import("u256.zig");

pub fn create_address(sender: u256, nonce: u64) u256 {
    var payload: [64]u8 = undefined;
    var len: u32 = 0;
    len += encode_address(payload[len..], sender);
    len += encode_int(payload[len..], nonce);
    var list: [65]u8 = undefined;
    list[0] = 0xc0 + @as(u8, @intCast(len));
    @memcpy(list[1 .. 1 + len], payload[0..len]);
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(list[0 .. 1 + len], &hash, .{});
    return word.to_address(word.from_bytes_be(&hash));
}

pub fn create2_address(sender: u256, salt: u256, init_code: []const u8) u256 {
    var init_hash: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(init_code, &init_hash, .{});
    var preimage: [85]u8 = undefined;
    preimage[0] = 0xff;
    var sender_bytes: [32]u8 = undefined;
    word.to_bytes_be(sender, &sender_bytes);
    @memcpy(preimage[1..21], sender_bytes[12..32]);
    word.to_bytes_be(salt, preimage[21..53]);
    @memcpy(preimage[53..85], &init_hash);
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(&preimage, &hash, .{});
    return word.to_address(word.from_bytes_be(&hash));
}

fn encode_address(out: []u8, address: u256) u32 {
    std.debug.assert(out.len >= 21);
    out[0] = 0x94;
    var bytes: [32]u8 = undefined;
    word.to_bytes_be(address, &bytes);
    @memcpy(out[1..21], bytes[12..32]);
    return 21;
}

/// `keccak256(0x05 || rlp([chain_id, address, nonce]))`.
pub fn auth_signing_hash(chain_id: u256, address: u256, nonce: u64) [32]u8 {
    var payload: [72]u8 = undefined;
    var len: u32 = 0;
    len += encode_u256(payload[len..], chain_id);
    len += encode_address(payload[len..], address);
    len += encode_int(payload[len..], nonce);
    var msg: [96]u8 = undefined;
    msg[0] = 0x05;
    const head: u32 = encode_list_header(msg[1..], len);
    @memcpy(msg[1 + head .. 1 + head + len], payload[0..len]);
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(msg[0 .. 1 + head + len], &hash, .{});
    return hash;
}

fn encode_list_header(out: []u8, payload_len: u32) u32 {
    if (payload_len < 56) {
        out[0] = 0xc0 + @as(u8, @intCast(payload_len));
        return 1;
    }
    std.debug.assert(payload_len <= 255);
    out[0] = 0xf8;
    out[1] = @intCast(payload_len);
    return 2;
}

fn encode_u256(out: []u8, value: u256) u32 {
    if (value == 0) {
        out[0] = 0x80;
        return 1;
    }
    if (value < 128) {
        out[0] = @intCast(value);
        return 1;
    }
    var bytes: [32]u8 = undefined;
    word.to_bytes_be(value, &bytes);
    var start: u32 = 0;
    while (start < 32 and bytes[start] == 0) start += 1;
    const len: u32 = 32 - start;
    out[0] = 0x80 + @as(u8, @intCast(len));
    @memcpy(out[1 .. 1 + len], bytes[start..32]);
    return 1 + len;
}

fn encode_int(out: []u8, value: u64) u32 {
    if (value == 0) {
        out[0] = 0x80;
        return 1;
    }
    if (value < 128) {
        out[0] = @intCast(value);
        return 1;
    }
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    var start: u32 = 0;
    while (start < 8 and bytes[start] == 0) start += 1;
    const len: u32 = 8 - start;
    out[0] = 0x80 + @as(u8, @intCast(len));
    @memcpy(out[1 .. 1 + len], bytes[start..8]);
    return 1 + len;
}

test "create address nonce zero" {
    const addr = create_address(0x0000000000000000000000000000000000000000, 0);
    try std.testing.expect(addr != 0);
}
