//! RLP for CREATE addresses, 7702 hashes, headers, and MPT nodes.

const std = @import("std");
const word = @import("u256.zig");

pub fn create_address(sender: u256, nonce: u64) u256 {
    var payload: [64]u8 = undefined;
    var len: u32 = 0;
    len += encode_address(payload[len..], sender);
    len += uint(payload[len..], nonce);
    var list_buf: [72]u8 = undefined;
    const wrapped = list(list_buf[0..], payload[0..len]);
    var hash: [32]u8 = undefined;
    keccak(list_buf[0..wrapped], &hash);
    return word.to_address(word.from_bytes_be(&hash));
}

pub fn create2_address(sender: u256, salt: u256, init_code: []const u8) u256 {
    var init_hash: [32]u8 = undefined;
    keccak(init_code, &init_hash);
    var preimage: [85]u8 = undefined;
    preimage[0] = 0xff;
    var sender_bytes: [32]u8 = undefined;
    word.to_bytes_be(sender, &sender_bytes);
    @memcpy(preimage[1..21], sender_bytes[12..32]);
    word.to_bytes_be(salt, preimage[21..53]);
    @memcpy(preimage[53..85], &init_hash);
    var hash: [32]u8 = undefined;
    keccak(&preimage, &hash);
    return word.to_address(word.from_bytes_be(&hash));
}

/// `keccak256(0x05 || rlp([chain_id, address, nonce]))`.
pub fn auth_signing_hash(chain_id: u256, address: u256, nonce: u64) [32]u8 {
    var payload: [72]u8 = undefined;
    var len: u32 = 0;
    len += uint(payload[len..], chain_id);
    len += encode_address(payload[len..], address);
    len += uint(payload[len..], nonce);
    var msg: [96]u8 = undefined;
    msg[0] = 0x05;
    const wrapped = list(msg[1..], payload[0..len]);
    var hash: [32]u8 = undefined;
    keccak(msg[0 .. 1 + wrapped], &hash);
    return hash;
}

pub fn keccak(data: []const u8, out: *[32]u8) void {
    std.crypto.hash.sha3.Keccak256.hash(data, out, .{});
}

pub fn uint(out: []u8, value: u256) u32 {
    if (value == 0) {
        std.debug.assert(out.len >= 1);
        out[0] = 0x80;
        return 1;
    }
    var be: [32]u8 = undefined;
    word.to_bytes_be(value, &be);
    var start: u32 = 0;
    while (start < 32 and be[start] == 0) start += 1;
    return bytes(out, be[start..32]);
}

pub fn bytes(out: []u8, data: []const u8) u32 {
    if (data.len == 1 and data[0] < 0x80) {
        std.debug.assert(out.len >= 1);
        out[0] = data[0];
        return 1;
    }
    if (data.len < 56) {
        std.debug.assert(out.len >= 1 + data.len);
        out[0] = 0x80 + @as(u8, @intCast(data.len));
        if (data.len != 0) @memcpy(out[1 .. 1 + data.len], data);
        return 1 + @as(u32, @intCast(data.len));
    }
    const len_len = uint_width(data.len);
    std.debug.assert(out.len >= 1 + len_len + data.len);
    out[0] = 0xb7 + len_len;
    write_uint(out[1..], data.len, len_len);
    @memcpy(out[1 + len_len .. 1 + len_len + data.len], data);
    return 1 + len_len + @as(u32, @intCast(data.len));
}

pub fn list(out: []u8, payload: []const u8) u32 {
    if (payload.len < 56) {
        std.debug.assert(out.len >= 1 + payload.len);
        out[0] = 0xc0 + @as(u8, @intCast(payload.len));
        if (payload.len != 0) @memcpy(out[1 .. 1 + payload.len], payload);
        return 1 + @as(u32, @intCast(payload.len));
    }
    const len_len = uint_width(payload.len);
    std.debug.assert(out.len >= 1 + len_len + payload.len);
    out[0] = 0xf7 + len_len;
    write_uint(out[1..], payload.len, len_len);
    @memcpy(out[1 + len_len .. 1 + len_len + payload.len], payload);
    return 1 + len_len + @as(u32, @intCast(payload.len));
}

/// Room for the longest RLP list prefix (`0xf7` + 8-byte length).
pub const list_header_room: u32 = 9;

/// `out[hdr_room .. end]` is already the list payload. Slide it down and write
/// the header at `out[0]` so the result does not need a second copy buffer.
pub fn wrap_list(out: []u8, hdr_room: u32, end: u32) u32 {
    std.debug.assert(hdr_room == list_header_room);
    std.debug.assert(end >= hdr_room);
    const payload_len = end - hdr_room;
    const hdr_len = list_header_len(payload_len);
    std.debug.assert(hdr_len <= hdr_room);
    if (hdr_len != hdr_room and payload_len != 0) {
        std.mem.copyForwards(u8, out[hdr_len .. hdr_len + payload_len], out[hdr_room..end]);
    }
    write_list_header(out, payload_len);
    return hdr_len + payload_len;
}

fn list_header_len(payload_len: usize) u32 {
    if (payload_len < 56) return 1;
    return 1 + uint_width(payload_len);
}

fn write_list_header(out: []u8, payload_len: usize) void {
    if (payload_len < 56) {
        std.debug.assert(out.len >= 1);
        out[0] = 0xc0 + @as(u8, @intCast(payload_len));
        return;
    }
    const len_len = uint_width(payload_len);
    std.debug.assert(out.len >= 1 + len_len);
    out[0] = 0xf7 + len_len;
    write_uint(out[1..], payload_len, len_len);
}

pub fn encode_address(out: []u8, addr: u256) u32 {
    std.debug.assert(out.len >= 21);
    out[0] = 0x94;
    var be: [32]u8 = undefined;
    word.to_bytes_be(addr, &be);
    @memcpy(out[1..21], be[12..32]);
    return 21;
}

fn uint_width(value: usize) u8 {
    std.debug.assert(value >= 56);
    var tmp = value;
    var n: u8 = 0;
    while (tmp != 0) {
        n += 1;
        tmp >>= 8;
    }
    return n;
}

fn write_uint(out: []u8, value: usize, width: u8) void {
    var tmp = value;
    var i = width;
    while (i > 0) {
        i -= 1;
        out[i] = @truncate(tmp);
        tmp >>= 8;
    }
}

test "create address nonce zero" {
    const addr = create_address(0x0000000000000000000000000000000000000000, 0);
    try std.testing.expect(addr != 0);
}

test "rlp empty string is 0x80" {
    var out: [1]u8 = undefined;
    try std.testing.expectEqual(@as(u32, 1), bytes(&out, &[_]u8{}));
    try std.testing.expectEqual(@as(u8, 0x80), out[0]);
}

test "rlp empty list is 0xc0" {
    var out: [1]u8 = undefined;
    try std.testing.expectEqual(@as(u32, 1), list(&out, &[_]u8{}));
    try std.testing.expectEqual(@as(u8, 0xc0), out[0]);
}

test "wrap_list matches list" {
    var src: [80]u8 = undefined;
    for (&src, 0..) |*b, i| b.* = @truncate(i);
    var via_copy: [100]u8 = undefined;
    const n = list(&via_copy, src[0..80]);
    var via_wrap: [100]u8 = undefined;
    @memcpy(via_wrap[9..89], src[0..80]);
    const m = wrap_list(&via_wrap, 9, 89);
    try std.testing.expectEqual(n, m);
    try std.testing.expectEqualSlices(u8, via_copy[0..n], via_wrap[0..m]);
}
