//! Hard forks from ethereum/execution-specs.
//! Osaka is the baseline. Amsterdam is additive.

const std = @import("std");

pub const Fork = enum(u8) {
    prague = 0,
    osaka = 1,
    amsterdam = 2,

    pub const default = Fork.osaka;

    pub fn name(self: Fork) []const u8 {
        return switch (self) {
            .prague => "prague",
            .osaka => "osaka",
            .amsterdam => "amsterdam",
        };
    }

    pub fn from_name(text: []const u8) ?Fork {
        if (std.ascii.eqlIgnoreCase(text, "prague")) return .prague;
        if (std.ascii.eqlIgnoreCase(text, "osaka")) return .osaka;
        if (std.ascii.eqlIgnoreCase(text, "amsterdam")) return .amsterdam;
        return null;
    }

    pub fn at_least(self: Fork, other: Fork) bool {
        return @intFromEnum(self) >= @intFromEnum(other);
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

test "from_name is case insensitive" {
    try std.testing.expectEqual(Fork.osaka, Fork.from_name("Osaka").?);
    try std.testing.expectEqual(Fork.prague, Fork.from_name("PRAGUE").?);
    try std.testing.expectEqual(Fork.amsterdam, Fork.from_name("Amsterdam").?);
}
