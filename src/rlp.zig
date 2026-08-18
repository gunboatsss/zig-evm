//! Minimal RLP for `CREATE` address: `keccak256(rlp([sender, nonce]))[12:]`.

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
