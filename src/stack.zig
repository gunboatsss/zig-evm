const std = @import("std");
const limits = @import("limits.zig");

pub const Stack = struct {
    words: [limits.stack_depth_max]u256,
    depth: u32,

    pub fn init() Stack {
        return .{
            .words = undefined,
            .depth = 0,
        };
    }

    pub fn push(self: *Stack, word: u256) !void {
        std.debug.assert(self.depth <= limits.stack_depth_max);
        if (self.depth >= limits.stack_depth_max) return error.StackOverflow;
        self.words[self.depth] = word;
        self.depth += 1;
        std.debug.assert(self.depth <= limits.stack_depth_max);
    }

    pub fn pop(self: *Stack) !u256 {
        std.debug.assert(self.depth <= limits.stack_depth_max);
        if (self.depth == 0) return error.StackUnderflow;
        self.depth -= 1;
        const word = self.words[self.depth];
        std.debug.assert(self.depth <= limits.stack_depth_max);
        return word;
    }

    pub fn peek(self: *const Stack, offset: u32) !u256 {
        std.debug.assert(offset < limits.stack_depth_max);
        if (offset >= self.depth) return error.StackUnderflow;
        const index = self.depth - 1 - offset;
        std.debug.assert(index < limits.stack_depth_max);
        return self.words[index];
    }

    pub fn dup(self: *Stack, offset: u32) !void {
        const word = try self.peek(offset);
        try self.push(word);
    }

    pub fn swap(self: *Stack, offset: u32) !void {
        std.debug.assert(offset > 0);
        if (offset >= self.depth) return error.StackUnderflow;
        try self.exchange(0, offset);
    }

    pub fn exchange(self: *Stack, offset_a: u32, offset_b: u32) !void {
        if (offset_a >= self.depth) return error.StackUnderflow;
        if (offset_b >= self.depth) return error.StackUnderflow;
        const index_a = self.depth - 1 - offset_a;
        const index_b = self.depth - 1 - offset_b;
        std.debug.assert(index_a < limits.stack_depth_max);
        std.debug.assert(index_b < limits.stack_depth_max);
        const temp = self.words[index_a];
        self.words[index_a] = self.words[index_b];
        self.words[index_b] = temp;
    }
};

test "stack push pop" {
    var stack = Stack.init();
    try stack.push(7);
    try stack.push(9);
    try std.testing.expectEqual(@as(u256, 9), try stack.pop());
}
