//! Hard forks from ethereum/execution-specs.
//! Osaka is the baseline. Amsterdam is additive.
//! `*_breakpoint` is a zig-evm opt-in that adds BREAKPOINT (`0xCC`).

const std = @import("std");

pub const Fork = enum(u8) {
    prague = 0,
    osaka = 1,
    amsterdam = 2,
    prague_breakpoint = 16,
    osaka_breakpoint = 17,
    amsterdam_breakpoint = 18,

    pub const default = Fork.osaka;

    pub fn name(self: Fork) []const u8 {
        return switch (self) {
            .prague => "prague",
            .osaka => "osaka",
            .amsterdam => "amsterdam",
            .prague_breakpoint => "prague_breakpoint",
            .osaka_breakpoint => "osaka_breakpoint",
            .amsterdam_breakpoint => "amsterdam_breakpoint",
        };
    }

    pub fn from_name(text: []const u8) ?Fork {
        if (std.ascii.eqlIgnoreCase(text, "prague")) return .prague;
        if (std.ascii.eqlIgnoreCase(text, "osaka")) return .osaka;
        if (std.ascii.eqlIgnoreCase(text, "amsterdam")) return .amsterdam;
        if (std.ascii.eqlIgnoreCase(text, "prague_breakpoint")) return .prague_breakpoint;
        if (std.ascii.eqlIgnoreCase(text, "osaka_breakpoint")) return .osaka_breakpoint;
        if (std.ascii.eqlIgnoreCase(text, "amsterdam_breakpoint")) return .amsterdam_breakpoint;
        return null;
    }

    /// Ethereum spec this fork is based on (`prague` / `osaka` / `amsterdam`).
    pub fn spec(self: Fork) Fork {
        return switch (self) {
            .prague, .prague_breakpoint => .prague,
            .osaka, .osaka_breakpoint => .osaka,
            .amsterdam, .amsterdam_breakpoint => .amsterdam,
        };
    }

    pub fn has_breakpoint(self: Fork) bool {
        return switch (self) {
            .prague_breakpoint, .osaka_breakpoint, .amsterdam_breakpoint => true,
            else => false,
        };
    }

    pub fn at_least(self: Fork, other: Fork) bool {
        return @intFromEnum(self.spec()) >= @intFromEnum(other.spec());
    }
};

test "osaka is the default" {
    try std.testing.expectEqual(Fork.osaka, Fork.default);
}

test "fork order prague < osaka < amsterdam" {
    try std.testing.expect(Fork.osaka.at_least(.prague));
    try std.testing.expect(Fork.amsterdam.at_least(.osaka));
    try std.testing.expect(!Fork.osaka.at_least(.amsterdam));
    try std.testing.expect(!Fork.prague.at_least(.osaka));
}

test "breakpoint forks keep spec order" {
    try std.testing.expectEqual(Fork.prague, Fork.prague_breakpoint.spec());
    try std.testing.expectEqual(Fork.osaka, Fork.osaka_breakpoint.spec());
    try std.testing.expectEqual(Fork.amsterdam, Fork.amsterdam_breakpoint.spec());
    try std.testing.expect(Fork.osaka_breakpoint.at_least(.osaka));
    try std.testing.expect(Fork.osaka_breakpoint.at_least(.prague));
    try std.testing.expect(!Fork.prague_breakpoint.at_least(.osaka));
    try std.testing.expect(Fork.prague_breakpoint.has_breakpoint());
    try std.testing.expect(Fork.osaka_breakpoint.has_breakpoint());
    try std.testing.expect(!Fork.prague.has_breakpoint());
    try std.testing.expect(!Fork.osaka.has_breakpoint());
}

test "from_name is case insensitive" {
    try std.testing.expectEqual(Fork.osaka, Fork.from_name("Osaka").?);
    try std.testing.expectEqual(Fork.prague, Fork.from_name("PRAGUE").?);
    try std.testing.expectEqual(Fork.amsterdam, Fork.from_name("Amsterdam").?);
    try std.testing.expectEqual(Fork.prague_breakpoint, Fork.from_name("prague_breakpoint").?);
    try std.testing.expectEqual(Fork.osaka_breakpoint, Fork.from_name("Osaka_Breakpoint").?);
    try std.testing.expectEqual(Fork.amsterdam_breakpoint, Fork.from_name("AMSTERDAM_BREAKPOINT").?);
}
