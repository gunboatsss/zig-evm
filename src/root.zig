//! Test root: pull every module's inline tests into `zig build test`.

const std = @import("std");

test {
    _ = @import("u256.zig");
    _ = @import("stack.zig");
    _ = @import("memory.zig");
    _ = @import("gas.zig");
    _ = @import("fork.zig");
    _ = @import("opcode.zig");
    _ = @import("world.zig");
    _ = @import("rlp.zig");
    _ = @import("header.zig");
    _ = @import("trie.zig");
    _ = @import("delegation.zig");
    _ = @import("precompile.zig");
    _ = @import("modexp.zig");
    _ = @import("ripemd160.zig");
    _ = @import("blake2f.zig");
    _ = @import("kzg.zig");
    _ = @import("bn254.zig");
    _ = @import("bls12.zig");
    _ = @import("cheatcode.zig");
    _ = @import("artifact.zig");
    _ = @import("interpreter.zig");
    _ = @import("trace.zig");
    _ = @import("debug.zig");
    _ = @import("evm.zig");
    _ = @import("forge_test.zig");
    _ = @import("jsontest.zig");
    _ = @import("chaintest.zig");
    std.testing.refAllDecls(@This());
}
