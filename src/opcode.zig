//! Opcode table for Osaka (baseline) and Amsterdam (additive).
//! Byte values match `ethereum/execution-specs` `forks/osaka` and `forks/amsterdam`.

const std = @import("std");
const fork_mod = @import("fork.zig");
const word = @import("u256.zig");

pub const Fork = fork_mod.Fork;

pub const gas_base: u64 = 2;
pub const gas_very_low: u64 = 3;
pub const gas_low: u64 = 5;
pub const gas_mid: u64 = 8;
pub const gas_high: u64 = 10;
pub const gas_warm_access: u64 = 100;
pub const gas_jumpdest: u64 = 1;
pub const gas_blockhash: u64 = 20;
pub const gas_exp_base: u64 = 10;
pub const gas_keccak_base: u64 = 30;
pub const gas_copy_per_word: u64 = 3;
pub const gas_tload: u64 = 100;
pub const gas_tstore: u64 = 100;

pub const Opcode = enum(u8) {
    stop = 0x00,
    add = 0x01,
    mul = 0x02,
    sub = 0x03,
    div = 0x04,
    sdiv = 0x05,
    mod_ = 0x06,
    smod = 0x07,
    addmod = 0x08,
    mulmod = 0x09,
    exp = 0x0a,
    signextend = 0x0b,
    lt = 0x10,
    gt = 0x11,
    slt = 0x12,
    sgt = 0x13,
    eq = 0x14,
    iszero_ = 0x15,
    and_ = 0x16,
    or_ = 0x17,
    xor = 0x18,
    not_ = 0x19,
    byte = 0x1a,
    shl = 0x1b,
    shr = 0x1c,
    sar = 0x1d,
    clz = 0x1e,
    keccak256 = 0x20,
    address = 0x30,
    balance = 0x31,
    origin = 0x32,
    caller = 0x33,
    callvalue = 0x34,
    calldataload = 0x35,
    calldatasize = 0x36,
    calldatacopy = 0x37,
    codesize = 0x38,
    codecopy = 0x39,
    gasprice = 0x3a,
    extcodesize = 0x3b,
    extcodecopy = 0x3c,
    returndatasize = 0x3d,
    returndatacopy = 0x3e,
    extcodehash = 0x3f,
    blockhash = 0x40,
    coinbase = 0x41,
    timestamp = 0x42,
    number = 0x43,
    prevrandao = 0x44,
    gaslimit = 0x45,
    chainid = 0x46,
    selfbalance = 0x47,
    basefee = 0x48,
    blobhash = 0x49,
    blobbasefee = 0x4a,
    slotnum = 0x4b,
    pop = 0x50,
    mload = 0x51,
    mstore = 0x52,
    mstore8 = 0x53,
    sload = 0x54,
    sstore = 0x55,
    jump = 0x56,
    jumpi = 0x57,
    pc = 0x58,
    msize = 0x59,
    gas = 0x5a,
    jumpdest = 0x5b,
    tload = 0x5c,
    tstore = 0x5d,
    mcopy = 0x5e,
    push0 = 0x5f,
    push1 = 0x60,
    push32 = 0x7f,
    dup1 = 0x80,
    dup16 = 0x8f,
    swap1 = 0x90,
    swap16 = 0x9f,
    log0 = 0xa0,
    log1 = 0xa1,
    log2 = 0xa2,
    log3 = 0xa3,
    log4 = 0xa4,
    dupn = 0xe6,
    swapn = 0xe7,
    exchange = 0xe8,
    create = 0xf0,
    call = 0xf1,
    callcode = 0xf2,
    return_ = 0xf3,
    delegatecall = 0xf4,
    create2 = 0xf5,
    staticcall = 0xfa,
    revert = 0xfd,
    invalid = 0xfe,
    selfdestruct = 0xff,
    _,

    pub fn from_byte(byte: u8) Opcode {
        return @enumFromInt(byte);
    }

    pub fn is_push(opcode: Opcode) bool {
        const raw: u8 = @intFromEnum(opcode);
        return raw >= 0x5f and raw <= 0x7f;
    }

    pub fn push_width(opcode: Opcode) u32 {
        std.debug.assert(is_push(opcode));
        const raw: u8 = @intFromEnum(opcode);
        if (raw == 0x5f) return 0;
        return @as(u32, raw - 0x60) + 1;
    }

    pub fn is_dup(opcode: Opcode) bool {
        const raw: u8 = @intFromEnum(opcode);
        return raw >= 0x80 and raw <= 0x8f;
    }

    pub fn dup_offset(opcode: Opcode) u32 {
        std.debug.assert(is_dup(opcode));
        const raw: u8 = @intFromEnum(opcode);
        return @as(u32, raw - 0x80) + 1;
    }

    pub fn is_swap(opcode: Opcode) bool {
        const raw: u8 = @intFromEnum(opcode);
        return raw >= 0x90 and raw <= 0x9f;
    }

    pub fn swap_offset(opcode: Opcode) u32 {
        std.debug.assert(is_swap(opcode));
        const raw: u8 = @intFromEnum(opcode);
        return @as(u32, raw - 0x90) + 1;
    }

    pub fn is_terminal(opcode: Opcode) bool {
        return switch (opcode) {
            .stop, .return_, .revert, .selfdestruct => true,
            else => false,
        };
    }

    /// Osaka is the baseline (`CLZ`). Amsterdam adds `SLOTNUM` and EIP-8024.
    pub fn introduced_in(opcode: Opcode) Fork {
        return switch (opcode) {
            .slotnum, .dupn, .swapn, .exchange => .amsterdam,
            .clz => .osaka,
            else => .prague,
        };
    }

    pub fn enabled(opcode: Opcode, fork: Fork) bool {
        return fork.at_least(introduced_in(opcode));
    }

    /// Static (base) gas only. Dynamic costs are charged in the interpreter.
    pub fn static_gas(opcode: Opcode) u64 {
        const raw: u8 = @intFromEnum(opcode);
        if (raw >= 0x60 and raw <= 0x7f) return gas_very_low;
        if (raw >= 0x80 and raw <= 0x8f) return gas_very_low;
        if (raw >= 0x90 and raw <= 0x9f) return gas_very_low;
        return switch (opcode) {
            .stop, .invalid, .return_, .revert => 0,
            .jumpdest => gas_jumpdest,
            .pop, .pc, .msize, .gas, .address, .origin, .caller, .callvalue, .calldatasize, .codesize, .gasprice, .coinbase, .timestamp, .number, .prevrandao, .gaslimit, .chainid, .basefee, .blobbasefee, .slotnum, .push0, .returndatasize => gas_base,
            .add, .sub, .not_, .lt, .gt, .slt, .sgt, .eq, .iszero_, .and_, .or_, .xor, .byte, .shl, .shr, .sar, .calldataload, .mload, .mstore, .mstore8, .calldatacopy, .codecopy, .returndatacopy, .mcopy, .dupn, .swapn, .exchange, .blobhash => gas_very_low,
            .mul, .div, .sdiv, .mod_, .smod, .signextend, .clz, .selfbalance => gas_low,
            .addmod, .mulmod, .jump => gas_mid,
            .jumpi, .exp => gas_high,
            .blockhash => gas_blockhash,
            .keccak256 => gas_keccak_base,
            .sload, .tload => gas_warm_access,
            .tstore => gas_tstore,
            .sstore => 20000,
            .log0, .log1, .log2, .log3, .log4 => 0,
            .balance, .extcodesize, .extcodehash, .extcodecopy, .create, .create2, .call, .callcode, .delegatecall, .staticcall, .selfdestruct => 0,
            else => gas_very_low,
        };
    }
};

pub fn read_push_immediate(code: []const u8, pc: u32, width: u32) ?u256 {
    std.debug.assert(width > 0);
    std.debug.assert(width <= 32);
    if (pc + width > code.len) return null;
    var bytes: [32]u8 = undefined;
    @memset(&bytes, 0);
    @memcpy(bytes[32 - width ..], code[pc .. pc + width]);
    return word.from_bytes_be(&bytes);
}

/// EIP-8024: missing immediate at end of code is 0, same as PUSH.
pub fn read_immediate_byte(code: []const u8, pc: u32) u8 {
    const next = pc + 1;
    if (next >= code.len) return 0;
    return code[next];
}

/// EIP-8024 `decode_single`. Returns n in 17..=235.
pub fn decode_single(x: u8) u32 {
    return (@as(u32, x) + 145) % 256;
}

/// EIP-8024 `decode_pair`. Returns (n, m) with 1 <= n < m and n + m <= 30.
pub fn decode_pair(x: u8) struct { n: u32, m: u32 } {
    const k: u32 = x ^ 143;
    const q = k / 16;
    const r = k % 16;
    if (q < r) return .{ .n = q + 1, .m = r + 1 };
    return .{ .n = r + 1, .m = 29 - q };
}

pub fn dupn_immediate_valid(x: u8) bool {
    return x <= 90 or x >= 128;
}

pub fn exchange_immediate_valid(x: u8) bool {
    return x <= 81 or x >= 128;
}

test "push width" {
    try std.testing.expectEqual(@as(u32, 1), Opcode.push_width(.push1));
    try std.testing.expectEqual(@as(u32, 32), Opcode.push_width(.push32));
}

test "eip-8024 decode_single" {
    try std.testing.expectEqual(@as(u32, 145), decode_single(0));
    try std.testing.expectEqual(@as(u32, 17), decode_single(128));
}

test "eip-8024 decode_pair of zero" {
    const pair = decode_pair(0);
    try std.testing.expectEqual(@as(u32, 9), pair.n);
    try std.testing.expectEqual(@as(u32, 16), pair.m);
}

test "jumpdest gas is 1" {
    try std.testing.expectEqual(@as(u64, 1), Opcode.static_gas(.jumpdest));
}

test "clz is osaka, slotnum is amsterdam" {
    try std.testing.expect(!Opcode.enabled(.clz, .prague));
    try std.testing.expect(Opcode.enabled(.clz, .osaka));
    try std.testing.expect(Opcode.enabled(.clz, .amsterdam));
    try std.testing.expect(!Opcode.enabled(.slotnum, .osaka));
    try std.testing.expect(Opcode.enabled(.slotnum, .amsterdam));
    try std.testing.expect(Opcode.enabled(.mcopy, .osaka));
}
