const std = @import("std");
const interpreter = @import("interpreter.zig");
const limits = @import("limits.zig");
const opcode_mod = @import("opcode.zig");
const precompile = @import("precompile.zig");
const cheatcode = @import("cheatcode.zig");
const state_mod = @import("state.zig");
const word = @import("u256.zig");
const rlp = @import("rlp.zig");
const delegation = @import("delegation.zig");

pub const Frame = interpreter.Frame;
pub const Status = interpreter.Status;
pub const ExecutionContext = state_mod.ExecutionContext;
pub const Fork = opcode_mod.Fork;
pub const Vm = interpreter.Vm;
pub const AccessListItem = interpreter.AccessListItem;
pub const Authorization = interpreter.Authorization;
pub const BlockTx = interpreter.BlockTx;

pub const Result = struct {
    status: Status,
    gas_used: u64,
    return_buffer: [limits.returndata_bytes_max]u8,
    return_len: u32,
    log_count: u32,

    pub fn return_data(self: *const Result) []const u8 {
        return self.return_buffer[0..self.return_len];
    }
};

pub fn execute(
    allocator: std.mem.Allocator,
    code: []const u8,
    calldata: []const u8,
    gas_limit: u64,
    context: ExecutionContext,
) !Result {
    return execute_with_fork(allocator, code, calldata, gas_limit, context, Fork.default);
}

pub fn execute_with_fork(
    allocator: std.mem.Allocator,
    code: []const u8,
    calldata: []const u8,
    gas_limit: u64,
    context: ExecutionContext,
    fork: Fork,
) !Result {
    std.debug.assert(gas_limit > 0);
    const vm = try allocator.create(Vm);
    defer allocator.destroy(vm);
    try vm.init(code, calldata, gas_limit, context, fork);
    try vm.run();
    var result = Result{
        .status = vm.current().status,
        .gas_used = vm.current().gas.used,
        .return_buffer = undefined,
        .return_len = vm.output_len,
        .log_count = vm.log_count,
    };
    std.debug.assert(result.return_len <= limits.returndata_bytes_max);
    @memcpy(
        result.return_buffer[0..result.return_len],
        vm.output_buffer[0..result.return_len],
    );
    return result;
}

test "interpreter add" {
    const code = [_]u8{ 0x60, 0x02, 0x60, 0x03, 0x01, 0x00 };
    const result = try execute(std.testing.allocator, &code, &[_]u8{}, 1_000_000, ExecutionContext.default());
    try std.testing.expectEqual(Status.stopped, result.status);
}

test "blockhash of parent is nonzero" {
    const code = [_]u8{ 0x60, 0x00, 0x40, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3 };
    var ctx = ExecutionContext.default();
    ctx.number = 1;
    const result = try execute(std.testing.allocator, &code, &[_]u8{}, 1_000_000, ctx);
    try std.testing.expectEqual(Status.returned, result.status);
    try std.testing.expect(!std.mem.allEqual(u8, result.return_data(), 0));
}

test "blockhash of current number is zero" {
    const code = [_]u8{ 0x60, 0x01, 0x40, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3 };
    var ctx = ExecutionContext.default();
    ctx.number = 1;
    const result = try execute(std.testing.allocator, &code, &[_]u8{}, 1_000_000, ctx);
    try std.testing.expectEqual(Status.returned, result.status);
    try std.testing.expect(std.mem.allEqual(u8, result.return_data(), 0));
}

test "interpreter gt is top greater than second" {
    const code = [_]u8{ 0x60, 0x02, 0x60, 0x03, 0x11, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3 };
    const result = try execute(std.testing.allocator, &code, &[_]u8{}, 1_000_000, ExecutionContext.default());
    try std.testing.expectEqual(Status.returned, result.status);
    try std.testing.expectEqual(@as(u8, 1), result.return_data()[31]);
}

test "interpreter exp is top to the power of second" {
    // PUSH1 2 PUSH1 10 EXP → 10**2
    const code = [_]u8{ 0x60, 0x02, 0x60, 0x0a, 0x0a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3 };
    const result = try execute(std.testing.allocator, &code, &[_]u8{}, 1_000_000, ExecutionContext.default());
    try std.testing.expectEqual(Status.returned, result.status);
    try std.testing.expectEqual(@as(u8, 100), result.return_data()[31]);
}

test "exp gas is 10 plus 50 per exponent byte" {
    // PUSH1 1 PUSH1 2 EXP STOP → 2**1, exponent 1 byte: 3+3+10+50
    const one_byte = [_]u8{ 0x60, 0x01, 0x60, 0x02, 0x0a, 0x00 };
    const one = try execute(std.testing.allocator, &one_byte, &[_]u8{}, 1_000, ExecutionContext.default());
    try std.testing.expectEqual(Status.stopped, one.status);
    try std.testing.expectEqual(@as(u64, 66), one.gas_used);

    // PUSH1 0 PUSH1 2 EXP STOP → 2**0, exponent 0 bytes: 3+3+10
    const zero = [_]u8{ 0x60, 0x00, 0x60, 0x02, 0x0a, 0x00 };
    const z = try execute(std.testing.allocator, &zero, &[_]u8{}, 1_000, ExecutionContext.default());
    try std.testing.expectEqual(Status.stopped, z.status);
    try std.testing.expectEqual(@as(u64, 16), z.gas_used);
}

test "interpreter addmod is (top + second) mod third" {
    // PUSH1 5 PUSH1 4 PUSH1 3 ADDMOD → (3+4)%5
    const code = [_]u8{ 0x60, 0x05, 0x60, 0x04, 0x60, 0x03, 0x08, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3 };
    const result = try execute(std.testing.allocator, &code, &[_]u8{}, 1_000_000, ExecutionContext.default());
    try std.testing.expectEqual(Status.returned, result.status);
    try std.testing.expectEqual(@as(u8, 2), result.return_data()[31]);
}

test "interpreter return word" {
    const code = [_]u8{ 0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3 };
    const result = try execute(std.testing.allocator, &code, &[_]u8{}, 1_000_000, ExecutionContext.default());
    try std.testing.expectEqual(Status.returned, result.status);
    try std.testing.expectEqual(@as(usize, 32), result.return_data().len);
    try std.testing.expectEqual(@as(u8, 0x2a), result.return_data()[31]);
}

test "interpreter jump" {
    const code = [_]u8{ 0x60, 0x03, 0x56, 0x5b, 0x60, 0x01, 0x00 };
    const result = try execute(std.testing.allocator, &code, &[_]u8{}, 1_000_000, ExecutionContext.default());
    try std.testing.expectEqual(Status.stopped, result.status);
}

test "prague rejects clz" {
    const code = [_]u8{ 0x60, 0x01, 0x1e, 0x00 };
    const result = execute_with_fork(std.testing.allocator, &code, &[_]u8{}, 1_000_000, ExecutionContext.default(), .prague);
    try std.testing.expectError(error.InvalidOpcode, result);
}

test "osaka clz" {
    const code = [_]u8{ 0x60, 0x01, 0x1e, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3 };
    const result = try execute(std.testing.allocator, &code, &[_]u8{}, 1_000_000, ExecutionContext.default());
    try std.testing.expectEqual(Status.returned, result.status);
    try std.testing.expectEqual(@as(u8, 0xff), result.return_data()[31]);
}

test "osaka rejects slotnum" {
    const code = [_]u8{ 0x4b, 0x00 };
    const result = execute(std.testing.allocator, &code, &[_]u8{}, 1_000_000, ExecutionContext.default());
    try std.testing.expectError(error.InvalidOpcode, result);
}

test "amsterdam slotnum" {
    const code = [_]u8{ 0x4b, 0x00 };
    const result = try execute_with_fork(std.testing.allocator, &code, &[_]u8{}, 1_000_000, ExecutionContext.default(), .amsterdam);
    try std.testing.expectEqual(Status.stopped, result.status);
}

test "osaka tstore tload" {
    const code = [_]u8{
        0x60, 0x07, 0x60, 0x00, 0x5d,
        0x60, 0x00, 0x5c,
        0x60, 0x00, 0x52,
        0x60, 0x20, 0x60, 0x00, 0xf3,
    };
    const result = try execute(std.testing.allocator, &code, &[_]u8{}, 1_000_000, ExecutionContext.default());
    try std.testing.expectEqual(Status.returned, result.status);
    try std.testing.expectEqual(@as(u8, 0x07), result.return_data()[31]);
}

test "osaka mcopy" {
    const code = [_]u8{
        0x60, 0x42, 0x60, 0x00, 0x53,
        0x60, 0x01, 0x60, 0x00, 0x60, 0x20, 0x5e,
        0x60, 0x20, 0x60, 0x20, 0xf3,
    };
    const result = try execute(std.testing.allocator, &code, &[_]u8{}, 1_000_000, ExecutionContext.default());
    try std.testing.expectEqual(Status.returned, result.status);
    try std.testing.expectEqual(@as(u8, 0x42), result.return_data()[0]);
}

test "mcopy length zero does not expand memory" {
    // PUSH1 0 PUSH1 0 PUSH1 32 MCOPY MSIZE PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN
    const code = [_]u8{
        0x60, 0x00, 0x60, 0x00, 0x60, 0x20, 0x5e,
        0x59, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
    };
    const result = try execute(std.testing.allocator, &code, &[_]u8{}, 1_000_000, ExecutionContext.default());
    try std.testing.expectEqual(Status.returned, result.status);
    try std.testing.expectEqual(@as(u8, 0), result.return_data()[31]);
}

test "mcopy huge dest zero length succeeds" {
    var code: [38]u8 = undefined;
    code[0] = 0x60;
    code[1] = 0x00;
    code[2] = 0x60;
    code[3] = 0x00;
    code[4] = 0x7f;
    @memset(code[5..37], 0xff);
    code[37] = 0x5e;
    const result = try execute(std.testing.allocator, &code, &[_]u8{}, 1_000_000, ExecutionContext.default());
    try std.testing.expectEqual(Status.stopped, result.status);
}

test "apply_tx access list adds intrinsic gas" {
    const vm = try std.testing.allocator.create(Vm);
    defer std.testing.allocator.destroy(vm);
    vm.init_plain(.osaka);
    try vm.world.set_balance(1, 1_000_000);
    vm.env.gas_price = 1;
    vm.env.base_fee = 0;
    vm.env.coinbase = 2;
    const keys = [_]u256{};
    const items = [_]AccessListItem{.{ .address = 9, .keys = &keys }};
    vm.access_list = &items;
    try std.testing.expectError(error.IntrinsicGas, vm.apply_tx(3, &[_]u8{}, 23_399, 0, 1));
    const status = try vm.apply_tx(3, &[_]u8{}, 23_400, 0, 1);
    try std.testing.expectEqual(Status.stopped, status);
    try std.testing.expectEqual(@as(u256, 23_400), vm.world.get_balance(2));
}

test "apply_tx warms an access list larger than 4096 keys" {
    const vm = try std.testing.allocator.create(Vm);
    defer std.testing.allocator.destroy(vm);
    vm.init_plain(.osaka);
    const key_count: u32 = 5_000;
    const keys = try std.testing.allocator.alloc(u256, key_count);
    defer std.testing.allocator.free(keys);
    for (keys, 0..) |*key, index| key.* = index;
    const items = [_]AccessListItem{.{ .address = 9, .keys = keys }};
    vm.access_list = &items;
    const intrinsic = 21_000 + 2_400 + 1_900 * @as(u64, key_count);
    try vm.world.set_balance(1, @as(u256, intrinsic) * 2);
    vm.env.gas_price = 1;
    vm.env.base_fee = 0;
    vm.env.coinbase = 2;
    const status = try vm.apply_tx(3, &[_]u8{}, intrinsic, 0, 1);
    try std.testing.expectEqual(Status.stopped, status);
}

test "selfdestruct pre-existing transfers and keeps code" {
    const vm = try std.testing.allocator.create(Vm);
    defer std.testing.allocator.destroy(vm);
    var ctx = ExecutionContext.default();
    ctx.address = 3;
    try vm.init(&[_]u8{ 0x60, 0x04, 0xff }, &[_]u8{}, 1_000_000, ctx, .osaka);
    try vm.world.set_balance(3, 1_000);
    try vm.run();
    try std.testing.expectEqual(Status.stopped, vm.current().status);
    try std.testing.expectEqual(@as(u256, 0), vm.world.get_balance(3));
    try std.testing.expectEqual(@as(u256, 1_000), vm.world.get_balance(4));
    try std.testing.expectEqual(@as(usize, 3), vm.world.code_of(3).len);
}

test "create then selfdestruct deletes new account" {
    const vm = try std.testing.allocator.create(Vm);
    defer std.testing.allocator.destroy(vm);
    vm.init_plain(.osaka);
    try vm.world.set_balance(1, 1_000_000);
    vm.env.gas_price = 1;
    vm.env.base_fee = 0;
    vm.env.coinbase = 2;
    const init_code = [_]u8{ 0x60, 0x04, 0xff };
    const status = try vm.apply_tx(null, &init_code, 100_000, 0, 1);
    try std.testing.expectEqual(Status.stopped, status);
    const created = rlp.create_address(1, 0);
    try std.testing.expect(!vm.world.is_alive(created));
}

test "call empty account returns one" {
    // CALL into address 2 (warm, no precompile, no code) and RETURN the success flag.
    const code = [_]u8{
        0x60, 0x00, // retSize
        0x60, 0x00, // retOffset
        0x60, 0x00, // argSize
        0x60, 0x00, // argOffset
        0x60, 0x00, // value
        0x60, 0x02, // to
        0x61, 0xff, 0xff, // gas
        0xf1, // CALL
        0x60, 0x00, 0x52, // MSTORE
        0x60, 0x20, 0x60, 0x00, 0xf3, // RETURN 32 bytes
    };
    const result = try execute(std.testing.allocator, &code, &[_]u8{}, 1_000_000, ExecutionContext.default());
    try std.testing.expectEqual(Status.returned, result.status);
    try std.testing.expectEqual(@as(u8, 0x01), result.return_data()[31]);
}

test "self call stops at stack depth limit" {
    // ADDRESS CALL STOP — each frame calls itself once. Depth 1024's CALL
    // returns 0; every shallower CALL succeeds. Must not crash.
    const code = [_]u8{
        0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00,
        0x30, // ADDRESS
        0x5a, // GAS
        0xf1, // CALL
        0x00, // STOP
    };
    const result = try execute(std.testing.allocator, &code, &[_]u8{}, 10_000_000_000, ExecutionContext.default());
    try std.testing.expectEqual(Status.stopped, result.status);
}

test "create deploys empty contract" {
    // Init code PUSH1 0 PUSH1 0 RETURN at memory offset 27.
    const code = [_]u8{
        0x64, 0x60, 0x00, 0x60, 0x00, 0xf3,
        0x60, 0x00, 0x52,
        0x60, 0x05, // size 5
        0x60, 0x1b, // offset 27
        0x60, 0x00, // endowment
        0xf0, // CREATE
        0x15, // ISZERO
        0x60, 0x00, 0x52,
        0x60, 0x20, 0x60, 0x00, 0xf3,
    };
    const result = try execute(std.testing.allocator, &code, &[_]u8{}, 1_000_000, ExecutionContext.default());
    try std.testing.expectEqual(Status.returned, result.status);
    // ISZERO(address) == 0 means CREATE returned a non-zero address.
    try std.testing.expectEqual(@as(u8, 0x00), result.return_data()[31]);
}

test "keccak256 empty" {
    const code = [_]u8{
        0x60, 0x00, 0x60, 0x00, 0x20,
        0x60, 0x00, 0x52,
        0x60, 0x20, 0x60, 0x00, 0xf3,
    };
    const result = try execute(std.testing.allocator, &code, &[_]u8{}, 1_000_000, ExecutionContext.default());
    try std.testing.expectEqual(Status.returned, result.status);
    try std.testing.expectEqual(@as(u8, 0xc5), result.return_data()[0]);
    try std.testing.expectEqual(@as(u8, 0x70), result.return_data()[31]);
}

test "log0 records one log" {
    const code = [_]u8{
        0x60, 0x61, 0x60, 0x00, 0x53, // MSTORE8 0x61 at 0
        0x60, 0x01, 0x60, 0x00, 0xa0, // LOG0 size=1 offset=0
        0x00,
    };
    const result = try execute(std.testing.allocator, &code, &[_]u8{}, 1_000_000, ExecutionContext.default());
    try std.testing.expectEqual(Status.stopped, result.status);
    try std.testing.expectEqual(@as(u32, 1), result.log_count);
}

test "ecrecover precompile recovers signer" {
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
    var seed: [Ecdsa.KeyPair.seed_length]u8 = undefined;
    @memset(&seed, 0x42);
    const kp = try Ecdsa.KeyPair.generateDeterministic(seed);
    var hash: [32]u8 = undefined;
    @memset(&hash, 0x11);
    const sig = try kp.signPrehashed(hash, null);
    const r = word.from_bytes_be(&sig.r);
    const s = word.from_bytes_be(&sig.s);
    const rec27 = precompile.ecrecover(hash, 27, r, s);
    const rec28 = precompile.ecrecover(hash, 28, r, s);
    const want = rec27 orelse rec28 orelse return error.TestUnexpectedResult;
    const v: u8 = if (rec27 != null) 27 else 28;

    const code = [_]u8{
        0x60, 0x80, 0x60, 0x00, 0x60, 0x00, 0x37, // CALLDATACOPY dest=0 off=0 size=128
        0x60, 0x20, // retSize
        0x60, 0x00, // retOffset
        0x60, 0x80, // argSize
        0x60, 0x00, // argOffset
        0x60, 0x00, // value
        0x60, 0x01, // to = ecrecover
        0x61, 0xff, 0xff, // gas
        0xf1, // CALL
        0x60, 0x20, 0x60, 0x00, 0xf3, // RETURN
    };
    var calldata: [128]u8 = undefined;
    @memset(&calldata, 0);
    @memcpy(calldata[0..32], &hash);
    calldata[63] = v;
    @memcpy(calldata[64..96], &sig.r);
    @memcpy(calldata[96..128], &sig.s);
    const result = try execute(std.testing.allocator, &code, &calldata, 1_000_000, ExecutionContext.default());
    try std.testing.expectEqual(Status.returned, result.status);
    try std.testing.expectEqualSlices(u8, &want, result.return_data());
}

test "sha256 precompile empty hash" {
    const code = [_]u8{
        0x60, 0x20, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00,
        0x60, 0x02, 0x61, 0xff, 0xff, 0xfa, // STATICCALL sha256
        0x60, 0x20, 0x60, 0x00, 0xf3,
    };
    const result = try execute(std.testing.allocator, &code, &[_]u8{}, 1_000_000, ExecutionContext.default());
    try std.testing.expectEqual(Status.returned, result.status);
    try std.testing.expectEqual(@as(u8, 0xe3), result.return_data()[0]);
    try std.testing.expectEqual(@as(u8, 0x55), result.return_data()[31]);
}

test "identity precompile copies calldata" {
    const code = [_]u8{
        0x60, 0x02, 0x60, 0x00, 0x60, 0x00, 0x37, // CALLDATACOPY size=2
        0x60, 0x02, 0x60, 0x00, 0x60, 0x02, 0x60, 0x00, 0x60, 0x00,
        0x60, 0x04, 0x61, 0xff, 0xff, 0xf1, // CALL identity
        0x60, 0x02, 0x60, 0x00, 0xf3,
    };
    const calldata = [_]u8{ 0xaa, 0xbb };
    const result = try execute(std.testing.allocator, &code, &calldata, 1_000_000, ExecutionContext.default());
    try std.testing.expectEqual(Status.returned, result.status);
    try std.testing.expectEqualSlices(u8, &calldata, result.return_data());
}

test "modexp precompile 3**2 mod 5" {
    const code = [_]u8{
        0x60, 0x63, 0x60, 0x00, 0x60, 0x00, 0x37, // CALLDATACOPY 99
        0x60, 0x20, 0x60, 0x00, 0x60, 0x63, 0x60, 0x00,
        0x60, 0x05, 0x61, 0xff, 0xff, 0xfa, // STATICCALL modexp
        0x60, 0x01, 0x60, 0x00, 0xf3,
    };
    var calldata: [99]u8 = @splat(0);
    calldata[31] = 1;
    calldata[63] = 1;
    calldata[95] = 1;
    calldata[96] = 3;
    calldata[97] = 2;
    calldata[98] = 5;
    const result = try execute(std.testing.allocator, &code, &calldata, 1_000_000, ExecutionContext.default());
    try std.testing.expectEqual(Status.returned, result.status);
    try std.testing.expectEqual(@as(u8, 4), result.return_data()[0]);
}

fn sel4(sig: []const u8) [4]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(sig, &hash, .{});
    return hash[0..4].*;
}

fn pack_word(value: u256, out: *[32]u8) void {
    word.to_bytes_be(value, out);
}

test "cheatcode warp sets timestamp" {
    const vm = try std.testing.allocator.create(Vm);
    defer std.testing.allocator.destroy(vm);
    try vm.init_session(.osaka);
    var ctx = ExecutionContext.default();
    ctx.caller = 1;
    var data: [36]u8 = @splat(0);
    @memcpy(data[0..4], &sel4("warp(uint256)"));
    pack_word(12_345, data[4..36]);
    const status = try vm.apply_call(cheatcode.address, &data, 1_000_000, ctx);
    try std.testing.expectEqual(Status.returned, status);
    try std.testing.expectEqual(@as(u256, 12_345), vm.env.timestamp);
    try vm.world.set_code(0xaaa, &[_]u8{ 0x42, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3 });
    const read = try vm.apply_call(0xaaa, &[_]u8{}, 1_000_000, ctx);
    try std.testing.expectEqual(Status.returned, read);
    try std.testing.expectEqual(@as(u256, 12_345), word.from_bytes_be(vm.output_buffer[0..32]));
}

test "cheatcode deal sets balance" {
    const vm = try std.testing.allocator.create(Vm);
    defer std.testing.allocator.destroy(vm);
    try vm.init_session(.osaka);
    var ctx = ExecutionContext.default();
    ctx.caller = 1;
    var data: [68]u8 = @splat(0);
    @memcpy(data[0..4], &sel4("deal(address,uint256)"));
    pack_word(0x42, data[4..36]);
    pack_word(99, data[36..68]);
    const status = try vm.apply_call(cheatcode.address, &data, 1_000_000, ctx);
    try std.testing.expectEqual(Status.returned, status);
    try std.testing.expectEqual(@as(u256, 99), vm.world.get_balance(0x42));
}

test "cheatcode prank sets next caller" {
    const vm = try std.testing.allocator.create(Vm);
    defer std.testing.allocator.destroy(vm);
    try vm.init_session(.osaka);
    try vm.world.set_code(0xbbb, &[_]u8{ 0x33, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3 });
    var caller_code: [96]u8 = undefined;
    const n = encode_prank_then_call(&caller_code, 0xbbb);
    try vm.world.set_code(0xaaa, caller_code[0..n]);
    var ctx = ExecutionContext.default();
    ctx.caller = 1;
    ctx.origin = 1;
    var data: [36]u8 = @splat(0);
    @memcpy(data[0..4], &sel4("prank(address)"));
    pack_word(0x11, data[4..36]);
    const status = try vm.apply_call(0xaaa, &data, 1_000_000, ctx);
    try std.testing.expectEqual(Status.returned, status);
    try std.testing.expectEqual(@as(u256, 0x11), word.from_bytes_be(vm.output_buffer[0..32]));
}

test "cheatcode expectRevert swallows revert" {
    const vm = try std.testing.allocator.create(Vm);
    defer std.testing.allocator.destroy(vm);
    try vm.init_session(.osaka);
    try vm.world.set_code(0xccc, &[_]u8{ 0x60, 0x00, 0x60, 0x00, 0xfd });
    var caller_code: [96]u8 = undefined;
    const n = encode_expect_then_call(&caller_code, 0xccc);
    try vm.world.set_code(0xaaa, caller_code[0..n]);
    var ctx = ExecutionContext.default();
    ctx.caller = 1;
    var data: [4]u8 = sel4("expectRevert()");
    const status = try vm.apply_call(0xaaa, &data, 1_000_000, ctx);
    try std.testing.expectEqual(Status.returned, status);
    try std.testing.expectEqual(@as(u8, 1), vm.output_buffer[31]);
}

test "extcodesize of hevm is nonzero" {
    const vm = try std.testing.allocator.create(Vm);
    defer std.testing.allocator.destroy(vm);
    try vm.init_session(.osaka);
    var code: [32]u8 = undefined;
    code[0] = 0x73;
    var addr: [32]u8 = undefined;
    word.to_bytes_be(cheatcode.address, &addr);
    @memcpy(code[1..21], addr[12..32]);
    @memcpy(code[21..30], &[_]u8{ 0x3b, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3 });
    try vm.world.set_code(0xaaa, code[0..30]);
    var ctx = ExecutionContext.default();
    ctx.caller = 1;
    const status = try vm.apply_call(0xaaa, &[_]u8{}, 1_000_000, ctx);
    try std.testing.expectEqual(Status.returned, status);
    try std.testing.expectEqual(@as(u8, 1), vm.output_buffer[31]);
}

test "run path does not intercept hevm" {
    const code = [_]u8{
        0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00,
        0x73, 0x71, 0x09, 0x70, 0x9e, 0xcf, 0xa9, 0x1a, 0x80, 0x62,
        0x6f, 0xf3, 0x98, 0x9d, 0x68, 0xf6, 0x7f, 0x5b, 0x1d, 0xd1, 0x2d,
        0x61, 0xff, 0xff, 0xf1, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
    };
    const result = try execute(std.testing.allocator, &code, &[_]u8{}, 1_000_000, ExecutionContext.default());
    try std.testing.expectEqual(Status.returned, result.status);
    try std.testing.expectEqual(@as(u8, 1), result.return_data()[31]);
}

fn encode_prank_then_call(out: []u8, target: u256) u32 {
    return encode_vm_call_tail(out, target, true);
}

fn encode_expect_then_call(out: []u8, target: u256) u32 {
    return encode_vm_call_tail(out, target, false);
}

fn encode_vm_call_tail(out: []u8, target: u256, return_data: bool) u32 {
    var n: u32 = 0;
    out[n] = 0x36;
    n += 1;
    out[n] = 0x5f;
    n += 1;
    out[n] = 0x5f;
    n += 1;
    out[n] = 0x37;
    n += 1;
    out[n] = 0x5f;
    n += 1;
    out[n] = 0x5f;
    n += 1;
    out[n] = 0x36;
    n += 1;
    out[n] = 0x5f;
    n += 1;
    out[n] = 0x5f;
    n += 1;
    n += push20(out[n..], cheatcode.address);
    out[n] = 0x5a;
    n += 1;
    out[n] = 0xf1;
    n += 1;
    out[n] = 0x50;
    n += 1;
    out[n] = 0x60;
    n += 1;
    out[n] = if (return_data) 0x20 else 0x00;
    n += 1;
    out[n] = 0x5f;
    n += 1;
    out[n] = 0x5f;
    n += 1;
    out[n] = 0x5f;
    n += 1;
    out[n] = 0x5f;
    n += 1;
    n += push20(out[n..], target);
    out[n] = 0x5a;
    n += 1;
    out[n] = 0xf1;
    n += 1;
    if (return_data) {
        out[n] = 0x50;
        n += 1;
        out[n] = 0x60;
        n += 1;
        out[n] = 0x20;
        n += 1;
        out[n] = 0x5f;
        n += 1;
        out[n] = 0xf3;
        n += 1;
    } else {
        out[n] = 0x60;
        n += 1;
        out[n] = 0x00;
        n += 1;
        out[n] = 0x52;
        n += 1;
        out[n] = 0x60;
        n += 1;
        out[n] = 0x20;
        n += 1;
        out[n] = 0x5f;
        n += 1;
        out[n] = 0xf3;
        n += 1;
    }
    return n;
}

fn push20(out: []u8, who: u256) u32 {
    out[0] = 0x73;
    var addr: [32]u8 = undefined;
    word.to_bytes_be(who, &addr);
    @memcpy(out[1..21], addr[12..32]);
    return 21;
}

test "apply_tx charges intrinsic gas" {
    const vm = try std.testing.allocator.create(Vm);
    defer std.testing.allocator.destroy(vm);
    vm.init_plain(.osaka);
    try vm.world.set_balance(1, 1_000_000);
    vm.env.gas_price = 1;
    vm.env.base_fee = 0;
    vm.env.coinbase = 2;
    const status = try vm.apply_tx(3, &[_]u8{}, 21_000, 0, 1);
    try std.testing.expectEqual(Status.stopped, status);
    try std.testing.expectEqual(@as(u256, 979_000), vm.world.get_balance(1));
    try std.testing.expectEqual(@as(u256, 21_000), vm.world.get_balance(2));
    try std.testing.expectEqual(@as(u64, 1), vm.world.get_nonce(1));
}

test "sload cold then warm" {
    // PUSH1 0 SLOAD POP PUSH1 0 SLOAD STOP
    const code = [_]u8{ 0x60, 0x00, 0x54, 0x50, 0x60, 0x00, 0x54, 0x00 };
    const result = try execute(std.testing.allocator, &code, &[_]u8{}, 1_000_000, ExecutionContext.default());
    try std.testing.expectEqual(Status.stopped, result.status);
    try std.testing.expectEqual(@as(u64, 2_208), result.gas_used);
}

test "sstore cold set from zero" {
    // PUSH1 1 PUSH1 0 SSTORE STOP
    const code = [_]u8{ 0x60, 0x01, 0x60, 0x00, 0x55, 0x00 };
    const result = try execute(std.testing.allocator, &code, &[_]u8{}, 1_000_000, ExecutionContext.default());
    try std.testing.expectEqual(Status.stopped, result.status);
    try std.testing.expectEqual(@as(u64, 22_106), result.gas_used);
}

test "apply_tx refunds sstore clear" {
    const vm = try std.testing.allocator.create(Vm);
    defer std.testing.allocator.destroy(vm);
    vm.init_plain(.osaka);
    try vm.world.set_balance(1, 1_000_000);
    try vm.world.set_code(3, &[_]u8{ 0x60, 0x00, 0x60, 0x00, 0x55, 0x00 });
    try vm.world.store(3, 0, 1);
    vm.env.gas_price = 1;
    vm.env.base_fee = 0;
    vm.env.coinbase = 2;
    const status = try vm.apply_tx(3, &[_]u8{}, 100_000, 0, 1);
    try std.testing.expectEqual(Status.stopped, status);
    try std.testing.expectEqual(@as(u256, 0), vm.world.load(3, 0));
    try std.testing.expectEqual(@as(u256, 978_794), vm.world.get_balance(1));
    try std.testing.expectEqual(@as(u256, 21_206), vm.world.get_balance(2));
}

test "top-level revert undoes sstore" {
    const vm = try std.testing.allocator.create(Vm);
    defer std.testing.allocator.destroy(vm);
    vm.init_plain(.osaka);
    try vm.world.set_balance(1, 1_000_000);
    try vm.world.set_code(3, &[_]u8{ 0x60, 0x01, 0x60, 0x00, 0x55, 0x60, 0x00, 0x60, 0x00, 0xfd });
    vm.env.gas_price = 1;
    vm.env.base_fee = 0;
    vm.env.coinbase = 2;
    const status = try vm.apply_tx(3, &[_]u8{}, 100_000, 0, 1);
    try std.testing.expectEqual(Status.reverted, status);
    try std.testing.expectEqual(@as(u256, 0), vm.world.load(3, 0));
}

fn clz_set_code_auth() Authorization {
    return .{
        .chain_id = 0,
        .address = 0x3d8e2d77bca8c0ed68f6d4860444bad2cc2cd661,
        .nonce = 0,
        .y_parity = 1,
        .r = 0xd7e81ad52b1ff78769c3b925b06176b76280242c83ebaf4cdb624820ab2b08db,
        .s = 0x0367ba5e94031aac8cfb792d405da03d4a7874fb4f4cd37e653f56271e9522e6,
    };
}

test "call follows eip-7702 designation" {
    const vm = try std.testing.allocator.create(Vm);
    defer std.testing.allocator.destroy(vm);
    vm.init_plain(.osaka);
    const impl: u256 = 0xaaa;
    const eoa: u256 = 0xbbb;
    try vm.world.set_code(impl, &[_]u8{ 0x60, 0x01, 0x60, 0x00, 0x55, 0x00 });
    const des = delegation.designation(impl);
    try vm.world.set_code(eoa, &des);
    var ctx = ExecutionContext.default();
    ctx.caller = 1;
    const status = try vm.apply_call(eoa, &[_]u8{}, 1_000_000, ctx);
    try std.testing.expectEqual(Status.stopped, status);
    try std.testing.expectEqual(@as(u256, 1), vm.world.load(eoa, 0));
    try std.testing.expectEqual(@as(u256, 0), vm.world.load(impl, 0));
}

test "apply_tx processes authorization and executes delegated code" {
    const vm = try std.testing.allocator.create(Vm);
    defer std.testing.allocator.destroy(vm);
    vm.init_plain(.osaka);
    const impl: u256 = 0x3d8e2d77bca8c0ed68f6d4860444bad2cc2cd661;
    const authority: u256 = 0x89873a93c67fc34d662483a081ebaabe443ea62f;
    try vm.world.set_code(impl, &[_]u8{
        0x60, 0x01, 0x1e, 0x60, 0x00, 0x55,
        0x60, 0x02, 0x1e, 0x60, 0x01, 0x55,
        0x70, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x1e, 0x60, 0x02, 0x55, 0x00,
    });
    try vm.world.set_nonce(impl, 1);
    try vm.world.set_balance(1, 10_000_000);
    vm.env.gas_price = 1;
    vm.env.base_fee = 0;
    vm.env.coinbase = 2;
    vm.env.chain_id = 1;
    const auths = [_]Authorization{clz_set_code_auth()};
    vm.authorizations = &auths;
    const status = try vm.apply_tx(authority, &[_]u8{}, 200_000, 0, 1);
    try std.testing.expectEqual(Status.stopped, status);
    try std.testing.expectEqualSlices(u8, &delegation.designation(impl), vm.world.code_of(authority));
    try std.testing.expectEqual(@as(u64, 1), vm.world.get_nonce(authority));
    try std.testing.expectEqual(@as(u256, 0xff), vm.world.load(authority, 0));
    try std.testing.expectEqual(@as(u256, 0xfe), vm.world.load(authority, 1));
    try std.testing.expectEqual(@as(u256, 0x7f), vm.world.load(authority, 2));
}

test "authorization survives top-level revert" {
    const vm = try std.testing.allocator.create(Vm);
    defer std.testing.allocator.destroy(vm);
    vm.init_plain(.osaka);
    const authority: u256 = 0x89873a93c67fc34d662483a081ebaabe443ea62f;
    const impl: u256 = 0x3d8e2d77bca8c0ed68f6d4860444bad2cc2cd661;
    try vm.world.set_code(3, &[_]u8{ 0x60, 0x00, 0x60, 0x00, 0xfd });
    try vm.world.set_balance(1, 10_000_000);
    vm.env.gas_price = 1;
    vm.env.base_fee = 0;
    vm.env.coinbase = 2;
    vm.env.chain_id = 1;
    const auths = [_]Authorization{clz_set_code_auth()};
    vm.authorizations = &auths;
    const status = try vm.apply_tx(3, &[_]u8{}, 100_000, 0, 1);
    try std.testing.expectEqual(Status.reverted, status);
    try std.testing.expectEqualSlices(u8, &delegation.designation(impl), vm.world.code_of(authority));
    try std.testing.expectEqual(@as(u64, 1), vm.world.get_nonce(authority));
}

test "existing authority refunds auth base cost" {
    const vm = try std.testing.allocator.create(Vm);
    defer std.testing.allocator.destroy(vm);
    vm.init_plain(.osaka);
    const authority: u256 = 0x89873a93c67fc34d662483a081ebaabe443ea62f;
    try vm.world.set_balance(authority, 1);
    try vm.world.set_balance(1, 10_000_000);
    try vm.world.set_code(3, &[_]u8{0x00});
    vm.env.gas_price = 1;
    vm.env.base_fee = 0;
    vm.env.coinbase = 2;
    vm.env.chain_id = 1;
    const auths = [_]Authorization{clz_set_code_auth()};
    vm.authorizations = &auths;
    const status = try vm.apply_tx(3, &[_]u8{}, 100_000, 0, 1);
    try std.testing.expectEqual(Status.stopped, status);
    try std.testing.expectEqual(@as(i64, 12_500), vm.gas_refund);
}

test "apply_tx authorization adds intrinsic gas" {
    const vm = try std.testing.allocator.create(Vm);
    defer std.testing.allocator.destroy(vm);
    vm.init_plain(.osaka);
    try vm.world.set_balance(1, 1_000_000);
    vm.env.gas_price = 1;
    vm.env.base_fee = 0;
    vm.env.coinbase = 2;
    const auths = [_]Authorization{clz_set_code_auth()};
    vm.authorizations = &auths;
    try std.testing.expectError(error.IntrinsicGas, vm.apply_tx(3, &[_]u8{}, 45_999, 0, 1));
}

test "apply_block runs a tx and BLOCKHASH sees the parent" {
    const header_mod = @import("header.zig");
    const trie_mod = @import("trie.zig");
    const vm = try std.testing.allocator.create(Vm);
    defer std.testing.allocator.destroy(vm);
    vm.init_plain(.osaka);
    try vm.world.set_balance(1, 1_000_000);
    try vm.world.set_code(3, &[_]u8{ 0x60, 0x00, 0x40, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3 });
    vm.env.chain_id = 1;
    const genesis = header_mod.Header{
        .number = 0,
        .gas_limit = 30_000_000,
        .timestamp = 1,
        .coinbase = 2,
        .withdrawals_root = trie_mod.empty_root,
    };
    const genesis_hash = genesis.hash();
    vm.push_block_hash(genesis_hash);
    const block = header_mod.Header{
        .parent_hash = genesis_hash,
        .coinbase = 2,
        .number = 1,
        .gas_limit = 30_000_000,
        .timestamp = 2,
        .base_fee = 0,
        .withdrawals_root = trie_mod.empty_root,
    };
    const txs = [_]BlockTx{.{
        .to = 3,
        .data = &.{},
        .gas_limit = 100_000,
        .value = 0,
        .sender = 1,
        .gas_price = 1,
    }};
    const gas_used = try vm.apply_block(block, &txs);
    try std.testing.expect(gas_used >= 21_000);
    try std.testing.expectEqual(@as(u32, 32), vm.output_len);
    try std.testing.expectEqualSlices(u8, &genesis_hash, vm.output_buffer[0..32]);
    vm.push_block_hash(block.hash());
    try std.testing.expectEqual(@as(u32, 2), vm.block_hash_count);
}

test "push_block_hash keeps a 256-window" {
    const vm = try std.testing.allocator.create(Vm);
    defer std.testing.allocator.destroy(vm);
    vm.init_plain(.osaka);
    var i: u32 = 0;
    while (i < 257) : (i += 1) {
        var hash: [32]u8 = @splat(0);
        hash[31] = @intCast(i & 0xff);
        hash[30] = @intCast(i >> 8);
        vm.push_block_hash(hash);
    }
    try std.testing.expectEqual(@as(u32, 256), vm.block_hash_count);
    try std.testing.expectEqual(@as(u8, 1), vm.block_hashes[0][31]);
    try std.testing.expectEqual(@as(u8, 0), vm.block_hashes[255][31]);
}
