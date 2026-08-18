const std = @import("std");
const limits = @import("limits.zig");
const word = @import("u256.zig");

/// Frame memory is a window into the VM's bump pool. Parent and child windows
/// may overlap in the backing array; the parent is paused while the child runs.
pub const Memory = struct {
    bytes: []u8,
    active_bytes: u32,

    pub fn init(buffer: []u8) Memory {
        std.debug.assert(buffer.len <= limits.memory_bytes_max);
        return .{
            .bytes = buffer,
            .active_bytes = 0,
        };
    }

    pub fn size(self: *const Memory) u32 {
        std.debug.assert(self.active_bytes <= self.bytes.len);
        return self.active_bytes;
    }

    pub fn expand(self: *Memory, offset: u32, length: u32) !void {
        if (length == 0) return;
        const cap: u32 = @intCast(self.bytes.len);
        std.debug.assert(cap <= limits.memory_bytes_max);
        const end = add_u32(offset, length) orelse return error.MemoryOverflow;
        if (end > cap) return error.MemoryOverflow;
        if (end > self.active_bytes) {
            const old = self.active_bytes;
            const aligned = align_up_32(end);
            if (aligned > cap) return error.MemoryOverflow;
            self.active_bytes = aligned;
            if (self.active_bytes > old) {
                @memset(self.bytes[old..self.active_bytes], 0);
            }
        }
    }

    pub fn load(self: *Memory, offset: u32) !u256 {
        try self.expand(offset, 32);
        var word_bytes: [32]u8 = undefined;
        @memcpy(&word_bytes, self.bytes[offset .. offset + 32]);
        return word.from_bytes_be(&word_bytes);
    }

    pub fn store(self: *Memory, offset: u32, value: u256) !void {
        try self.expand(offset, 32);
        var word_bytes: [32]u8 = undefined;
        word.to_bytes_be(value, &word_bytes);
        @memcpy(self.bytes[offset .. offset + 32], &word_bytes);
    }

    pub fn store_byte(self: *Memory, offset: u32, byte: u8) !void {
        try self.expand(offset, 1);
        self.bytes[offset] = byte;
    }

    pub fn copy(self: *Memory, dest_offset: u32, src_offset: u32, length: u32) !void {
        try self.expand(dest_offset, length);
        try self.expand(src_offset, length);
        if (length == 0) return;
        std.debug.assert(dest_offset + length <= self.bytes.len);
        std.debug.assert(src_offset + length <= self.bytes.len);
        if (dest_offset < src_offset) {
            var index: u32 = 0;
            while (index < length) : (index += 1) {
                self.bytes[dest_offset + index] = self.bytes[src_offset + index];
            }
        } else {
            var index: u32 = length;
            while (index > 0) {
                index -= 1;
                self.bytes[dest_offset + index] = self.bytes[src_offset + index];
            }
        }
    }

    pub fn read_slice(self: *Memory, offset: u32, length: u32, out: []u8) !void {
        std.debug.assert(out.len >= length);
        try self.expand(offset, length);
        @memcpy(out[0..length], self.bytes[offset .. offset + length]);
    }

    fn align_up_32(value: u32) u32 {
        const remainder = value % 32;
        if (remainder == 0) return value;
        return value + (32 - remainder);
    }

    fn add_u32(a: u32, b: u32) ?u32 {
        const sum = @addWithOverflow(a, b);
        if (sum[1] == 1) return null;
        return sum[0];
    }
};

/// End of a copy range. Length 0 does not expand. Overflow is OutOfGas.
pub fn range_end(offset: u256, length: u256) !u256 {
    if (length == 0) return 0;
    const sum = @addWithOverflow(offset, length);
    if (sum[1] == 1) return error.OutOfGas;
    return sum[0];
}

pub fn expansion_end(current: u32, dest: u256, src: u256, length: u256) !u32 {
    var end: u256 = current;
    const dest_end = try range_end(dest, length);
    const src_end = try range_end(src, length);
    if (dest_end > end) end = dest_end;
    if (src_end > end) end = src_end;
    const rem = end % 32;
    if (rem != 0) {
        const aligned = @addWithOverflow(end, 32 - rem);
        if (aligned[1] == 1) return error.OutOfGas;
        end = aligned[0];
    }
    if (end > std.math.maxInt(u32)) return error.OutOfGas;
    return @intCast(end);
}

test "memory store load" {
    var buffer: [256]u8 = undefined;
    var memory = Memory.init(&buffer);
    try memory.store(0, 0xdeadbeef);
    try std.testing.expectEqual(@as(u256, 0xdeadbeef), try memory.load(0));
}

test "expand length zero does not grow" {
    var buffer: [256]u8 = undefined;
    var memory = Memory.init(&buffer);
    try memory.expand(32, 0);
    try std.testing.expectEqual(@as(u32, 0), memory.size());
}

test "expansion end zero length stays current" {
    try std.testing.expectEqual(@as(u32, 0), try expansion_end(0, 32, 0, 0));
    try std.testing.expectEqual(@as(u32, 0), try expansion_end(0, std.math.maxInt(u256), 0, 0));
}
