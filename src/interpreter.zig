const std = @import("std");
const gas_mod = @import("gas.zig");
const limits = @import("limits.zig");
const memory_mod = @import("memory.zig");
const opcode_mod = @import("opcode.zig");
const precompile = @import("precompile.zig");
const cheatcode = @import("cheatcode.zig");
const rlp = @import("rlp.zig");
const stack_mod = @import("stack.zig");
const state_mod = @import("state.zig");
const word = @import("u256.zig");
const world_mod = @import("world.zig");

pub const Status = enum {
    running,
    stopped,
    returned,
    reverted,
    faulted,
};

const CallKind = enum {
    call,
    create,
};

pub const Frame = struct {
    code: []const u8,
    calldata: []const u8,
    stack: stack_mod.Stack,
    memory: memory_mod.Memory,
    gas: gas_mod.Gas,
    context: state_mod.ExecutionContext,
    pc: u32,
    status: Status,
    depth: u32,
    is_static: bool,
    kind: CallKind,
    code_address: u256,
    out_offset: u32,
    out_size: u32,
    pool_mark: u32,
    journal_mark: u32,
    log_mark: u32,
    log_data_mark: u32,
    mem_offset: u32,
};

pub const Log = struct {
    address: u256,
    topics: [limits.log_topics_max]u256,
    topic_count: u32,
    data_off: u32,
    data_len: u32,
};

pub const Vm = struct {
    world: world_mod.World,
    frames: [limits.call_frames_max]Frame,
    frame_count: u32,
    memory_pool: [limits.memory_pool_bytes_max]u8,
    memory_used: u32,
    last_return: [limits.returndata_bytes_max]u8,
    last_return_len: u32,
    output_buffer: [limits.returndata_bytes_max]u8,
    output_len: u32,
    accessed: [limits.accessed_addresses_max]u256,
    accessed_count: u32,
    logs: [limits.logs_max]Log,
    log_count: u32,
    log_data: [limits.log_data_pool_bytes_max]u8,
    log_data_used: u32,
    fork: opcode_mod.Fork,
    steps: u32,
    env: state_mod.ExecutionContext,
    cheats: cheatcode.State,
    cheats_enabled: bool,

    pub fn init(
        self: *Vm,
        code: []const u8,
        calldata: []const u8,
        gas_limit: u64,
        context: state_mod.ExecutionContext,
        fork: opcode_mod.Fork,
    ) !void {
        std.debug.assert(gas_limit > 0);
        std.debug.assert(code.len <= limits.code_bytes_max);
        std.debug.assert(calldata.len <= limits.calldata_bytes_max);
        self.world.init();
        self.frame_count = 0;
        self.memory_used = 0;
        self.last_return_len = 0;
        self.output_len = 0;
        self.accessed_count = 0;
        self.log_count = 0;
        self.log_data_used = 0;
        self.fork = fork;
        self.steps = 0;
        self.env = context;
        self.cheats = .{};
        self.cheats_enabled = false;
        try self.world.set_code(context.address, code);
        self.world.journal_count = 0;
        try self.warm_precompiles();
        try self.mark_warm(context.address);
        try self.mark_warm(context.caller);
        try self.mark_warm(context.origin);
        try self.push_message(.{
            .code = self.world.code_of(context.address),
            .calldata = calldata,
            .gas_limit = gas_limit,
            .context = context,
            .depth = 0,
            .is_static = false,
            .kind = .call,
            .code_address = context.address,
            .out_offset = 0,
            .out_size = 0,
            .should_transfer = false,
            .value = 0,
        });
    }

    pub fn init_session(self: *Vm, fork: opcode_mod.Fork) !void {
        self.init_plain(fork);
        self.cheats_enabled = true;
        try self.world.set_code(cheatcode.address, &cheatcode.dummy_code);
        self.world.journal_count = 0;
    }

    /// Empty world, no hevm. Used by JSON state tests.
    pub fn init_plain(self: *Vm, fork: opcode_mod.Fork) void {
        self.world.init();
        self.fork = fork;
        self.env = state_mod.ExecutionContext.default();
        self.cheats = .{};
        self.cheats_enabled = false;
        self.reset_tx();
    }

    pub fn apply_create(
        self: *Vm,
        init_code: []const u8,
        gas_limit: u64,
        value: u256,
        context: state_mod.ExecutionContext,
    ) !u256 {
        std.debug.assert(gas_limit > 0);
        std.debug.assert(init_code.len <= limits.init_code_bytes_max);
        self.reset_tx();
        try self.warm_precompiles();
        const sender = context.caller;
        try self.mark_warm(sender);
        try self.mark_warm(context.origin);
        const nonce = self.world.get_nonce(sender);
        const address = rlp.create_address(sender, nonce);
        try self.world.increment_nonce(sender);
        try self.mark_warm(address);
        var child_context = context;
        child_context.address = address;
        child_context.call_value = value;
        try self.push_message(.{
            .code = init_code,
            .calldata = &[_]u8{},
            .gas_limit = gas_limit,
            .context = child_context,
            .depth = 0,
            .is_static = false,
            .kind = .create,
            .code_address = address,
            .out_offset = 0,
            .out_size = 0,
            .should_transfer = true,
            .value = value,
        });
        try self.run();
        const frame = self.current();
        const success = frame.status == .returned or frame.status == .stopped;
        if (!success) return 0;
        return address;
    }

    pub fn apply_call(
        self: *Vm,
        to: u256,
        calldata: []const u8,
        gas_limit: u64,
        context: state_mod.ExecutionContext,
    ) !Status {
        return self.apply_message(to, calldata, gas_limit, 0, context);
    }

    pub fn apply_message(
        self: *Vm,
        to: u256,
        calldata: []const u8,
        gas_limit: u64,
        value: u256,
        context: state_mod.ExecutionContext,
    ) !Status {
        std.debug.assert(gas_limit > 0);
        std.debug.assert(calldata.len <= limits.calldata_bytes_max);
        self.reset_tx();
        try self.warm_precompiles();
        try self.mark_warm(to);
        try self.mark_warm(context.caller);
        try self.mark_warm(context.origin);
        var child_context = context;
        child_context.address = to;
        child_context.call_value = value;
        try self.push_message(.{
            .code = self.world.code_of(to),
            .calldata = calldata,
            .gas_limit = gas_limit,
            .context = child_context,
            .depth = 0,
            .is_static = false,
            .kind = .call,
            .code_address = to,
            .out_offset = 0,
            .out_size = 0,
            .should_transfer = value != 0,
            .value = value,
        });
        try self.run();
        return self.current().status;
    }

    /// One state-test transaction: bump sender nonce, then CALL or CREATE.
    /// Gas fees are not charged; compare `post.state` storage/code, not balances of the sender.
    pub fn apply_tx(
        self: *Vm,
        to: ?u256,
        data: []const u8,
        gas_limit: u64,
        value: u256,
        sender: u256,
    ) !Status {
        var ctx = self.env;
        ctx.caller = sender;
        ctx.origin = sender;
        ctx.call_value = value;
        if (to) |dest| {
            try self.world.increment_nonce(sender);
            return self.apply_message(dest, data, gas_limit, value, ctx);
        }
        _ = try self.apply_create(data, gas_limit, value, ctx);
        return self.current().status;
    }

    fn reset_tx(self: *Vm) void {
        self.frame_count = 0;
        self.memory_used = 0;
        self.last_return_len = 0;
        self.output_len = 0;
        self.accessed_count = 0;
        self.log_count = 0;
        self.log_data_used = 0;
        self.steps = 0;
        self.world.transient_count = 0;
    }

    pub fn run(self: *Vm) !void {
        std.debug.assert(self.frame_count == 1);
        while (true) {
            const frame = self.current();
            if (frame.status != .running) {
                if (self.frame_count == 1) {
                    try self.finish_top();
                    return;
                }
                try self.exit_child();
                continue;
            }
            if (self.steps >= limits.trace_steps_max) return error.StepLimitExceeded;
            self.steps += 1;
            self.step() catch |err| {
                if (self.frame_count == 1) return err;
                self.fault_current();
            };
        }
    }

    fn finish_top(self: *Vm) !void {
        const frame = self.current();
        if (frame.status == .stopped) self.output_len = 0;
        if (frame.kind != .create) return;
        const success = frame.status == .returned or frame.status == .stopped;
        if (!success) {
            self.world.rollback(frame.journal_mark);
            return;
        }
        self.deposit_create_code(frame) catch {
            frame.status = .faulted;
            frame.gas.used = frame.gas.limit;
            self.output_len = 0;
            self.world.rollback(frame.journal_mark);
        };
    }

    pub fn current(self: *Vm) *Frame {
        std.debug.assert(self.frame_count > 0);
        std.debug.assert(self.frame_count <= limits.call_frames_max);
        return &self.frames[self.frame_count - 1];
    }

    fn step(self: *Vm) !void {
        const frame = self.current();
        if (self.cheats_enabled and cheatcode.is_cheatcode(frame.code_address)) {
            self.exec_cheatcode();
            return;
        }
        if (precompile.is_precompile(frame.code_address)) {
            try self.exec_precompile();
            return;
        }
        std.debug.assert(frame.pc <= frame.code.len);
        if (frame.pc >= frame.code.len) {
            frame.status = .stopped;
            return;
        }
        const opcode_byte = frame.code[frame.pc];
        const opcode = opcode_mod.Opcode.from_byte(opcode_byte);
        if (!opcode_mod.Opcode.enabled(opcode, self.fork)) return error.InvalidOpcode;
        try frame.gas.consume(opcode_mod.Opcode.static_gas(opcode));
        const next_pc = try self.execute(opcode);
        std.debug.assert(next_pc <= frame.code.len);
        frame.pc = next_pc;
    }

    fn execute(self: *Vm, opcode: opcode_mod.Opcode) !u32 {
        const frame = self.current();
        if (opcode_mod.Opcode.is_push(opcode)) return try exec_push(frame, opcode);
        if (opcode_mod.Opcode.is_dup(opcode)) return try exec_dup(frame, opcode);
        if (opcode_mod.Opcode.is_swap(opcode)) return try exec_swap(frame, opcode);
        return switch (opcode) {
            .stop => exec_stop(frame),
            .add => try exec_wrapping(frame, add),
            .mul => try exec_wrapping(frame, mul),
            .sub => try exec_wrapping(frame, sub),
            .div => try exec_wrapping(frame, word.div),
            .sdiv => try exec_wrapping(frame, word.sdiv),
            .mod_ => try exec_wrapping(frame, word.mod),
            .smod => try exec_wrapping(frame, word.smod),
            .addmod => try exec_addmod(frame),
            .mulmod => try exec_mulmod(frame),
            .exp => try exec_exp(frame),
            .signextend => try exec_signextend(frame),
            .lt => try exec_cmp(frame, lt),
            .gt => try exec_cmp(frame, gt),
            .slt => try exec_cmp(frame, word.slt),
            .sgt => try exec_sgt(frame),
            .eq => try exec_cmp(frame, eq),
            .iszero_ => try exec_iszero(frame),
            .and_ => try exec_wrapping(frame, bit_and),
            .or_ => try exec_wrapping(frame, bit_or),
            .xor => try exec_wrapping(frame, bit_xor),
            .not_ => try exec_not(frame),
            .byte => try exec_wrapping(frame, word.byte),
            .shl => try exec_shift(frame, word.shl),
            .shr => try exec_shift(frame, word.shr),
            .sar => try exec_shift(frame, word.sar),
            .clz => try exec_clz(frame),
            .keccak256 => try self.exec_keccak256(),
            .address => try exec_push_const(frame, frame.context.address),
            .origin => try exec_push_const(frame, frame.context.origin),
            .caller => try exec_push_const(frame, frame.context.caller),
            .callvalue => try exec_push_const(frame, frame.context.call_value),
            .calldataload => try exec_calldataload(frame),
            .calldatasize => try exec_push_const(frame, @intCast(frame.calldata.len)),
            .calldatacopy => try exec_calldatacopy(frame),
            .codesize => try exec_push_const(frame, @intCast(frame.code.len)),
            .codecopy => try exec_codecopy(frame),
            .gasprice => try exec_push_const(frame, self.env.gas_price),
            .returndatasize => try exec_push_const(frame, self.last_return_len),
            .returndatacopy => try self.exec_returndatacopy(),
            .coinbase => try exec_push_const(frame, self.env.coinbase),
            .timestamp => try exec_push_const(frame, self.env.timestamp),
            .number => try exec_push_const(frame, self.env.number),
            .prevrandao => try exec_push_const(frame, self.env.prev_randao),
            .gaslimit => try exec_push_const(frame, self.env.gas_limit),
            .chainid => try exec_push_const(frame, self.env.chain_id),
            .selfbalance => try exec_push_const(frame, self.world.get_balance(frame.context.address)),
            .basefee => try exec_push_const(frame, self.env.base_fee),
            .blobhash => try exec_blobhash(frame),
            .blobbasefee => try exec_push_const(frame, self.env.blob_base_fee),
            .slotnum => try exec_push_const(frame, self.env.slot_number),
            .blockhash => try exec_blockhash(frame),
            .pop => try exec_pop(frame),
            .mload => try exec_mload(frame),
            .mstore => try exec_mstore(frame),
            .mstore8 => try exec_mstore8(frame),
            .mcopy => try exec_mcopy(frame),
            .sload => try self.exec_sload(),
            .sstore => try self.exec_sstore(),
            .tload => try self.exec_tload(),
            .tstore => try self.exec_tstore(),
            .jump => try exec_jump(frame),
            .jumpi => try exec_jumpi(frame),
            .pc => try exec_push_const(frame, frame.pc),
            .msize => try exec_push_const(frame, frame.memory.size()),
            .gas => try exec_push_const(frame, frame.gas.remaining()),
            .jumpdest => frame.pc + 1,
            .dupn => try exec_dupn(frame),
            .swapn => try exec_swapn(frame),
            .exchange => try exec_exchange(frame),
            .return_ => try self.halt_with_output(.returned),
            .revert => try self.halt_with_output(.reverted),
            .balance => try self.exec_balance(),
            .extcodesize => try self.exec_extcodesize(),
            .extcodecopy => try self.exec_extcodecopy(),
            .extcodehash => try self.exec_extcodehash(),
            .call => try self.exec_call(.call),
            .callcode => try self.exec_call(.callcode),
            .delegatecall => try self.exec_call(.delegatecall),
            .staticcall => try self.exec_call(.staticcall),
            .create => try self.exec_create(false),
            .create2 => try self.exec_create(true),
            .log0 => try self.exec_log(0),
            .log1 => try self.exec_log(1),
            .log2 => try self.exec_log(2),
            .log3 => try self.exec_log(3),
            .log4 => try self.exec_log(4),
            else => return error.InvalidOpcode,
        };
    }

    fn exec_sload(self: *Vm) !u32 {
        const frame = self.current();
        const key = try frame.stack.pop();
        try frame.stack.push(self.world.load(frame.context.address, key));
        return frame.pc + 1;
    }

    fn exec_sstore(self: *Vm) !u32 {
        const frame = self.current();
        if (frame.is_static) return error.WriteInStaticContext;
        const key = try frame.stack.pop();
        const value = try frame.stack.pop();
        try self.world.store(frame.context.address, key, value);
        return frame.pc + 1;
    }

    fn exec_tload(self: *Vm) !u32 {
        const frame = self.current();
        const key = try frame.stack.pop();
        try frame.stack.push(self.world.tload(frame.context.address, key));
        return frame.pc + 1;
    }

    fn exec_tstore(self: *Vm) !u32 {
        const frame = self.current();
        if (frame.is_static) return error.WriteInStaticContext;
        const key = try frame.stack.pop();
        const value = try frame.stack.pop();
        try self.world.tstore(frame.context.address, key, value);
        return frame.pc + 1;
    }

    fn exec_balance(self: *Vm) !u32 {
        const frame = self.current();
        const address = word.to_address(try frame.stack.pop());
        try frame.gas.consume(try self.access_account(address));
        try frame.stack.push(self.world.get_balance(address));
        return frame.pc + 1;
    }

    fn exec_extcodesize(self: *Vm) !u32 {
        const frame = self.current();
        const address = word.to_address(try frame.stack.pop());
        try frame.gas.consume(try self.access_account(address));
        try frame.stack.push(self.world.code_of(address).len);
        return frame.pc + 1;
    }

    fn exec_extcodehash(self: *Vm) !u32 {
        const frame = self.current();
        const address = word.to_address(try frame.stack.pop());
        try frame.gas.consume(try self.access_account(address));
        if (!self.world.is_alive(address)) {
            try frame.stack.push(0);
            return frame.pc + 1;
        }
        const code = self.world.code_of(address);
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(code, &hash, .{});
        try frame.stack.push(word.from_bytes_be(&hash));
        return frame.pc + 1;
    }

    fn exec_extcodecopy(self: *Vm) !u32 {
        const frame = self.current();
        const address = word.to_address(try frame.stack.pop());
        const dest = try word.to_u32(try frame.stack.pop());
        const offset = try word.to_u32(try frame.stack.pop());
        const size = try word.to_u32(try frame.stack.pop());
        try frame.gas.consume(try self.access_account(address));
        try frame.gas.consume_copy(size);
        const old_size = frame.memory.size();
        try frame.memory.expand(dest, size);
        try frame.gas.consume_memory(old_size, frame.memory.size());
        const code = self.world.code_of(address);
        var index: u32 = 0;
        while (index < size) : (index += 1) {
            const src = offset + index;
            const byte: u8 = if (src < code.len) code[src] else 0;
            try frame.memory.store_byte(dest + index, byte);
        }
        return frame.pc + 1;
    }

    fn exec_call(self: *Vm, kind: CallOpcode) !u32 {
        const frame = self.current();
        const requested = word.to_u64_saturating(try frame.stack.pop());
        const to = word.to_address(try frame.stack.pop());
        const value: u256 = switch (kind) {
            .delegatecall, .staticcall => 0,
            .call, .callcode => try frame.stack.pop(),
        };
        const in_offset = try word.to_u32(try frame.stack.pop());
        const in_size = try word.to_u32(try frame.stack.pop());
        const out_offset = try word.to_u32(try frame.stack.pop());
        const out_size = try word.to_u32(try frame.stack.pop());
        const old_size = frame.memory.size();
        try frame.memory.expand(in_offset, in_size);
        try frame.memory.expand(out_offset, out_size);
        const memory_cost = memory_gas_delta(old_size, frame.memory.size());
        try frame.gas.consume(memory_cost);

        const code_address = switch (kind) {
            .call, .staticcall => to,
            .callcode, .delegatecall => to,
        };
        const target = switch (kind) {
            .call, .staticcall => to,
            .callcode, .delegatecall => frame.context.address,
        };
        const access_cost = try self.access_account(code_address);
        var extra = access_cost;
        const transfer_value: u256 = switch (kind) {
            .delegatecall => frame.context.call_value,
            .staticcall => 0,
            .call, .callcode => value,
        };
        const should_transfer = kind != .delegatecall;
        if (should_transfer and transfer_value != 0) extra += gas_mod.gas_call_value;
        if (kind == .call and transfer_value != 0 and !self.world.is_alive(target)) {
            extra += gas_mod.gas_new_account;
        }
        const call_gas = gas_mod.calculate_message_call_gas(
            if (kind == .delegatecall) 0 else transfer_value,
            requested,
            frame.gas.remaining(),
            0,
            extra,
        );
        try frame.gas.consume(call_gas.cost);
        if (frame.is_static and should_transfer and transfer_value != 0) return error.WriteInStaticContext;
        self.last_return_len = 0;
        if (frame.depth + 1 > limits.call_depth_limit) {
            frame.gas.refund(call_gas.sub_call);
            try frame.stack.push(0);
            return frame.pc + 1;
        }
        if (should_transfer and self.world.get_balance(frame.context.address) < transfer_value) {
            frame.gas.refund(call_gas.sub_call);
            try frame.stack.push(0);
            return frame.pc + 1;
        }
        var child_context = frame.context;
        child_context.address = target;
        switch (kind) {
            .call, .staticcall => {
                child_context.caller = frame.context.address;
                child_context.call_value = transfer_value;
            },
            .callcode => {
                child_context.caller = frame.context.address;
                child_context.call_value = transfer_value;
            },
            .delegatecall => {
                child_context.caller = frame.context.caller;
                child_context.call_value = frame.context.call_value;
            },
        }
        if (kind != .delegatecall) {
            self.apply_prank(&child_context, code_address, frame.depth);
        }
        if (kind == .call or kind == .staticcall) {
            if (try self.try_mock(
                code_address,
                transfer_value,
                in_offset,
                in_size,
                out_offset,
                out_size,
                call_gas.sub_call,
            )) return frame.pc + 1;
        }
        self.bump_pool(frame);
        try self.push_message(.{
            .code = self.world.code_of(code_address),
            .calldata = frame.memory.bytes[in_offset .. in_offset + in_size],
            .gas_limit = call_gas.sub_call,
            .context = child_context,
            .depth = frame.depth + 1,
            .is_static = kind == .staticcall or frame.is_static,
            .kind = .call,
            .code_address = code_address,
            .out_offset = out_offset,
            .out_size = out_size,
            .should_transfer = should_transfer,
            .value = transfer_value,
        });
        return frame.pc + 1;
    }

    fn exec_create(self: *Vm, is_create2: bool) !u32 {
        const frame = self.current();
        if (frame.is_static) return error.WriteInStaticContext;
        const endowment = try frame.stack.pop();
        const in_offset = try word.to_u32(try frame.stack.pop());
        const in_size = try word.to_u32(try frame.stack.pop());
        const salt: u256 = if (is_create2) try frame.stack.pop() else 0;
        if (in_size > limits.init_code_bytes_max) return error.OutOfGas;
        const old_size = frame.memory.size();
        try frame.memory.expand(in_offset, in_size);
        var cost: u64 = gas_mod.gas_create_base;
        cost += init_code_gas(in_size);
        if (is_create2) cost += @as(u64, (in_size + 31) / 32) * 6;
        try frame.gas.consume(cost);
        try frame.gas.consume_memory(old_size, frame.memory.size());
        self.last_return_len = 0;
        const create_gas = gas_mod.max_message_call_gas(frame.gas.remaining());
        try frame.gas.consume(create_gas);
        const sender = frame.context.address;
        const nonce = self.world.get_nonce(sender);
        if (self.world.get_balance(sender) < endowment or nonce == std.math.maxInt(u64) or frame.depth + 1 > limits.call_depth_limit) {
            frame.gas.refund(create_gas);
            try frame.stack.push(0);
            return frame.pc + 1;
        }
        const init_code = frame.memory.bytes[in_offset .. in_offset + in_size];
        const contract = if (is_create2)
            rlp.create2_address(sender, salt, init_code)
        else
            rlp.create_address(sender, nonce);
        try self.mark_warm(contract);
        if (self.world.get_nonce(contract) != 0 or self.world.code_of(contract).len != 0) {
            try self.world.increment_nonce(sender);
            try frame.stack.push(0);
            return frame.pc + 1;
        }
        try self.world.increment_nonce(sender);
        var child_context = frame.context;
        child_context.address = contract;
        child_context.caller = sender;
        child_context.call_value = endowment;
        self.apply_prank(&child_context, contract, frame.depth);
        self.bump_pool(frame);
        try self.push_message(.{
            .code = init_code,
            .calldata = &[_]u8{},
            .gas_limit = create_gas,
            .context = child_context,
            .depth = frame.depth + 1,
            .is_static = false,
            .kind = .create,
            .code_address = contract,
            .out_offset = 0,
            .out_size = 0,
            .should_transfer = true,
            .value = endowment,
        });
        return frame.pc + 1;
    }

    fn halt_with_output(self: *Vm, status: Status) !u32 {
        const frame = self.current();
        const offset = try word.to_u32(try frame.stack.pop());
        const size = try word.to_u32(try frame.stack.pop());
        if (size > limits.returndata_bytes_max) return error.ReturnDataTooLarge;
        const old_size = frame.memory.size();
        try frame.memory.expand(offset, size);
        try frame.gas.consume_memory(old_size, frame.memory.size());
        @memcpy(self.output_buffer[0..size], frame.memory.bytes[offset .. offset + size]);
        self.output_len = size;
        frame.status = status;
        return @intCast(frame.code.len);
    }

    fn exec_keccak256(self: *Vm) !u32 {
        const frame = self.current();
        const offset = try word.to_u32(try frame.stack.pop());
        const size = try word.to_u32(try frame.stack.pop());
        const old_size = frame.memory.size();
        try frame.memory.expand(offset, size);
        try frame.gas.consume_memory(old_size, frame.memory.size());
        const words_count = (size + 31) / 32;
        try frame.gas.consume(@as(u64, words_count) * 6);
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(frame.memory.bytes[offset .. offset + size], &hash, .{});
        try frame.stack.push(word.from_bytes_be(&hash));
        return frame.pc + 1;
    }

    fn exec_log(self: *Vm, topic_count: u32) !u32 {
        std.debug.assert(topic_count <= limits.log_topics_max);
        const frame = self.current();
        if (frame.is_static) return error.WriteInStaticContext;
        const offset = try word.to_u32(try frame.stack.pop());
        const size = try word.to_u32(try frame.stack.pop());
        if (size > limits.log_data_bytes_max) return error.LogDataTooLarge;
        var topics: [limits.log_topics_max]u256 = undefined;
        var index: u32 = 0;
        while (index < topic_count) : (index += 1) {
            topics[index] = try frame.stack.pop();
        }
        const log_gas = 375 + 375 * @as(u64, topic_count) + @as(u64, size) * gas_mod.gas_log_data;
        try frame.gas.consume(log_gas);
        const old_size = frame.memory.size();
        try frame.memory.expand(offset, size);
        try frame.gas.consume_memory(old_size, frame.memory.size());
        if (self.log_count >= limits.logs_max) return error.LogLimit;
        if (self.log_data_used + size > limits.log_data_pool_bytes_max) return error.LogDataTooLarge;
        const data_off = self.log_data_used;
        if (size > 0) {
            @memcpy(self.log_data[data_off .. data_off + size], frame.memory.bytes[offset .. offset + size]);
        }
        self.log_data_used += size;
        self.logs[self.log_count] = .{
            .address = frame.context.address,
            .topics = topics,
            .topic_count = topic_count,
            .data_off = data_off,
            .data_len = size,
        };
        self.log_count += 1;
        return frame.pc + 1;
    }

    fn exec_precompile(self: *Vm) !void {
        const frame = self.current();
        std.debug.assert(precompile.is_precompile(frame.code_address));
        const input_len: u32 = @intCast(frame.calldata.len);
        try frame.gas.consume(precompile.gas_cost(frame.code_address, input_len));
        self.output_len = try precompile.execute(
            frame.code_address,
            frame.calldata,
            self.output_buffer[0..],
        );
        frame.status = .returned;
    }

    fn exec_cheatcode(self: *Vm) void {
        const frame = self.current();
        std.debug.assert(cheatcode.is_cheatcode(frame.code_address));
        const parent_depth: u32 = if (self.frame_count >= 2)
            self.frames[self.frame_count - 2].depth
        else
            0;
        const result = cheatcode.apply(
            &self.cheats,
            &self.world,
            &self.env,
            parent_depth,
            frame.calldata,
            self.output_buffer[0..],
            self.log_count,
            self.log_data_used,
        );
        self.output_len = result.len;
        if (result.restore_logs) {
            self.log_count = result.log_count;
            self.log_data_used = result.log_data_used;
        }
        frame.status = if (result.revert) .reverted else .returned;
    }

    fn apply_prank(self: *Vm, ctx: *state_mod.ExecutionContext, dest: u256, depth: u32) void {
        if (!self.cheats_enabled) return;
        if (cheatcode.is_cheatcode(dest)) return;
        if (!self.cheats.prank.active) return;
        if (self.cheats.prank.depth != depth) return;
        ctx.caller = self.cheats.prank.sender;
        if (self.cheats.prank.has_origin) ctx.origin = self.cheats.prank.origin;
        if (!self.cheats.prank.persistent) self.cheats.prank.active = false;
    }

    fn try_mock(
        self: *Vm,
        to: u256,
        value: u256,
        in_offset: u32,
        in_size: u32,
        out_offset: u32,
        out_size: u32,
        sub_call: u64,
    ) !bool {
        const frame = self.current();
        if (!self.cheats_enabled) return false;
        const input = frame.memory.bytes[in_offset .. in_offset + in_size];
        const mock = cheatcode.find_mock(&self.cheats, to, value, input) orelse return false;
        const ret = cheatcode.mock_return(&self.cheats, mock);
        frame.gas.refund(sub_call);
        const ret_len: u32 = @intCast(@min(ret.len, limits.returndata_bytes_max));
        self.last_return_len = ret_len;
        if (ret_len > 0) @memcpy(self.last_return[0..ret_len], ret[0..ret_len]);
        const copy_len = @min(out_size, ret_len);
        if (copy_len > 0) {
            @memcpy(frame.memory.bytes[out_offset .. out_offset + copy_len], self.last_return[0..copy_len]);
        }
        try frame.stack.push(1);
        return true;
    }

    fn consume_expect_revert(self: *Vm, child: *Frame, raw_ok: bool, parent_ok: *bool) bool {
        if (!self.cheats_enabled) return false;
        if (child.kind != .call) return false;
        if (cheatcode.is_cheatcode(child.code_address)) return false;
        if (self.cheats.expect.kind == .none) return false;
        const expect = self.cheats.expect;
        self.cheats.expect.kind = .none;
        if (raw_ok) return true;
        const ret = self.output_buffer[0..self.output_len];
        if (cheatcode.revert_matches(expect, ret)) parent_ok.* = true;
        return false;
    }

    fn exec_returndatacopy(self: *Vm) !u32 {
        const frame = self.current();
        const dest = try word.to_u32(try frame.stack.pop());
        const offset = try word.to_u32(try frame.stack.pop());
        const size = try word.to_u32(try frame.stack.pop());
        if (offset + size > self.last_return_len) return error.ReturnDataOutOfBounds;
        try frame.gas.consume_copy(size);
        const old_size = frame.memory.size();
        try frame.memory.expand(dest, size);
        try frame.gas.consume_memory(old_size, frame.memory.size());
        @memcpy(frame.memory.bytes[dest .. dest + size], self.last_return[offset .. offset + size]);
        return frame.pc + 1;
    }

    fn push_message(self: *Vm, params: MessageParams) !void {
        if (self.frame_count >= limits.call_frames_max) return error.CallDepth;
        const pool_mark = self.memory_used;
        const calldata = try self.copy_to_pool(params.calldata);
        const code = if (params.kind == .create) try self.copy_to_pool(params.code) else params.code;
        const mem_offset = self.memory_used;
        const journal_mark = self.world.mark();
        if (params.should_transfer and params.value != 0) {
            try self.world.touch(params.context.address);
            try self.world.move_ether(params.context.caller, params.context.address, params.value);
        } else {
            try self.world.touch(params.context.address);
        }
        if (params.kind == .create) {
            try self.world.set_nonce(params.context.address, 1);
        }
        self.frames[self.frame_count] = .{
            .code = code,
            .calldata = calldata,
            .stack = stack_mod.Stack.init(),
            .memory = self.memory_at(mem_offset),
            .gas = gas_mod.Gas.init(params.gas_limit),
            .context = params.context,
            .pc = 0,
            .status = .running,
            .depth = params.depth,
            .is_static = params.is_static,
            .kind = params.kind,
            .code_address = params.code_address,
            .out_offset = params.out_offset,
            .out_size = params.out_size,
            .pool_mark = pool_mark,
            .journal_mark = journal_mark,
            .log_mark = self.log_count,
            .log_data_mark = self.log_data_used,
            .mem_offset = mem_offset,
        };
        self.frame_count += 1;
        std.debug.assert(self.frame_count <= limits.call_frames_max);
        std.debug.assert(params.depth <= limits.call_depth_limit);
    }

    fn exit_child(self: *Vm) !void {
        std.debug.assert(self.frame_count > 1);
        const child = self.current();
        const success = child.status == .returned or child.status == .stopped;
        const revert = child.status == .reverted;
        if (child.status == .stopped) self.output_len = 0;
        if (child.kind == .create and success) {
            self.deposit_create_code(child) catch {
                child.status = .faulted;
                child.gas.used = child.gas.limit;
                self.output_len = 0;
            };
        }
        const raw_ok = child.status == .returned or child.status == .stopped;
        var parent_ok = raw_ok;
        const fail_parent = self.consume_expect_revert(child, raw_ok, &parent_ok);
        if (!raw_ok) {
            self.world.rollback(child.journal_mark);
            self.log_count = child.log_mark;
            self.log_data_used = child.log_data_mark;
        }
        if (raw_ok or revert) {
            self.frames[self.frame_count - 2].gas.refund(child.gas.remaining());
        }
        @memcpy(self.last_return[0..self.output_len], self.output_buffer[0..self.output_len]);
        self.last_return_len = self.output_len;
        const parent = &self.frames[self.frame_count - 2];
        if (child.kind == .call) {
            const copy_len = @min(child.out_size, self.last_return_len);
            if (copy_len > 0) {
                const old_size = parent.memory.size();
                try parent.memory.expand(child.out_offset, copy_len);
                try parent.gas.consume_memory(old_size, parent.memory.size());
                @memcpy(
                    parent.memory.bytes[child.out_offset .. child.out_offset + copy_len],
                    self.last_return[0..copy_len],
                );
            }
            try parent.stack.push(if (parent_ok) 1 else 0);
        } else if (parent_ok) {
            self.last_return_len = 0;
            try parent.stack.push(child.context.address);
        } else {
            try parent.stack.push(0);
        }
        if (fail_parent) parent.status = .reverted;
        self.memory_used = child.pool_mark;
        self.frame_count -= 1;
        self.output_len = 0;
    }

    fn deposit_create_code(self: *Vm, child: *Frame) !void {
        const code = self.output_buffer[0..self.output_len];
        if (self.output_len > limits.code_bytes_max or (code.len > 0 and code[0] == 0xef)) {
            return error.InvalidCode;
        }
        const deposit = @as(u64, self.output_len) * gas_mod.gas_code_deposit;
        try child.gas.consume(deposit);
        try self.world.set_code(child.context.address, code);
    }

    fn bump_pool(self: *Vm, frame: *Frame) void {
        const end = frame.mem_offset + frame.memory.active_bytes;
        if (end > self.memory_used) self.memory_used = end;
    }

    fn fault_current(self: *Vm) void {
        const frame = self.current();
        frame.status = .faulted;
        frame.gas.used = frame.gas.limit;
        self.output_len = 0;
    }

    fn copy_to_pool(self: *Vm, data: []const u8) ![]const u8 {
        const len: u32 = @intCast(data.len);
        if (self.memory_used + len > limits.memory_pool_bytes_max) return error.MemoryOverflow;
        const start = self.memory_used;
        if (len > 0) @memcpy(self.memory_pool[start .. start + len], data);
        self.memory_used += len;
        return self.memory_pool[start .. start + len];
    }

    fn memory_at(self: *Vm, offset: u32) memory_mod.Memory {
        std.debug.assert(offset <= limits.memory_pool_bytes_max);
        var cap = @min(limits.memory_bytes_max, limits.memory_pool_bytes_max - offset);
        cap -= cap % 32;
        return memory_mod.Memory.init(self.memory_pool[offset .. offset + cap]);
    }

    fn access_account(self: *Vm, address: u256) !u64 {
        if (self.is_warm(address)) return gas_mod.gas_warm_access;
        try self.mark_warm(address);
        return gas_mod.gas_cold_account;
    }

    fn is_warm(self: *const Vm, address: u256) bool {
        var index: u32 = 0;
        while (index < self.accessed_count) : (index += 1) {
            if (self.accessed[index] == address) return true;
        }
        return false;
    }

    fn mark_warm(self: *Vm, address: u256) !void {
        if (self.is_warm(address)) return;
        if (self.accessed_count >= limits.accessed_addresses_max) return error.AccessListFull;
        self.accessed[self.accessed_count] = address;
        self.accessed_count += 1;
    }

    fn warm_precompiles(self: *Vm) !void {
        var address: u256 = 1;
        while (address <= 10) : (address += 1) {
            try self.mark_warm(address);
        }
    }
};

const CallOpcode = enum { call, callcode, delegatecall, staticcall };

const MessageParams = struct {
    code: []const u8,
    calldata: []const u8,
    gas_limit: u64,
    context: state_mod.ExecutionContext,
    depth: u32,
    is_static: bool,
    kind: CallKind,
    code_address: u256,
    out_offset: u32,
    out_size: u32,
    should_transfer: bool,
    value: u256,
};

fn memory_gas_delta(old_size: u32, new_size: u32) u64 {
    std.debug.assert(new_size >= old_size);
    const old_words = (old_size + 31) / 32;
    const new_words = (new_size + 31) / 32;
    if (new_words <= old_words) return 0;
    const delta_words = new_words - old_words;
    const linear = @as(u64, delta_words) * 3;
    const quadratic = (@as(u64, new_words) * @as(u64, new_words)) / 512;
    return linear + quadratic;
}

fn init_code_gas(length: u32) u64 {
    return gas_mod.gas_init_code_word * @as(u64, (length + 31) / 32);
}

fn exec_stop(frame: *Frame) u32 {
    frame.status = .stopped;
    return frame.pc + 1;
}

fn exec_push(frame: *Frame, opcode: opcode_mod.Opcode) !u32 {
    const width = opcode_mod.Opcode.push_width(opcode);
    if (width == 0) {
        try frame.stack.push(0);
        return frame.pc + 1;
    }
    const immediate = opcode_mod.read_push_immediate(frame.code, frame.pc + 1, width) orelse
        return error.InvalidJump;
    try frame.stack.push(immediate);
    return frame.pc + 1 + width;
}

fn exec_dup(frame: *Frame, opcode: opcode_mod.Opcode) !u32 {
    try frame.stack.dup(opcode_mod.Opcode.dup_offset(opcode) - 1);
    return frame.pc + 1;
}

fn exec_swap(frame: *Frame, opcode: opcode_mod.Opcode) !u32 {
    try frame.stack.swap(opcode_mod.Opcode.swap_offset(opcode));
    return frame.pc + 1;
}

fn exec_wrapping(frame: *Frame, op: *const fn (u256, u256) u256) !u32 {
    const b = try frame.stack.pop();
    const a = try frame.stack.pop();
    try frame.stack.push(op(a, b));
    return frame.pc + 1;
}

fn exec_shift(frame: *Frame, op: *const fn (u256, u256) u256) !u32 {
    const shift = try frame.stack.pop();
    const value = try frame.stack.pop();
    try frame.stack.push(op(value, shift));
    return frame.pc + 1;
}

fn exec_addmod(frame: *Frame) !u32 {
    const modulus = try frame.stack.pop();
    const b = try frame.stack.pop();
    const a = try frame.stack.pop();
    try frame.stack.push(word.addmod(a, b, modulus));
    return frame.pc + 1;
}

fn exec_mulmod(frame: *Frame) !u32 {
    const modulus = try frame.stack.pop();
    const b = try frame.stack.pop();
    const a = try frame.stack.pop();
    try frame.stack.push(word.mulmod(a, b, modulus));
    return frame.pc + 1;
}

fn exec_exp(frame: *Frame) !u32 {
    const exponent = try frame.stack.pop();
    const base = try frame.stack.pop();
    const exp_bytes = word.exponent_byte_size(exponent);
    if (exp_bytes > 0) try frame.gas.consume((exp_bytes - 1) * 50);
    try frame.stack.push(word.exp(base, exponent));
    return frame.pc + 1;
}

fn exec_signextend(frame: *Frame) !u32 {
    const byte_index = try frame.stack.pop();
    const value = try frame.stack.pop();
    try frame.stack.push(word.signextend(byte_index, value));
    return frame.pc + 1;
}

fn exec_cmp(frame: *Frame, cmp: *const fn (u256, u256) bool) !u32 {
    const b = try frame.stack.pop();
    const a = try frame.stack.pop();
    try frame.stack.push(if (cmp(a, b)) 1 else 0);
    return frame.pc + 1;
}

fn exec_sgt(frame: *Frame) !u32 {
    const b = try frame.stack.pop();
    const a = try frame.stack.pop();
    try frame.stack.push(if (word.slt(b, a)) 1 else 0);
    return frame.pc + 1;
}

fn exec_iszero(frame: *Frame) !u32 {
    const a = try frame.stack.pop();
    try frame.stack.push(if (a == 0) 1 else 0);
    return frame.pc + 1;
}

fn exec_not(frame: *Frame) !u32 {
    const a = try frame.stack.pop();
    try frame.stack.push(~a);
    return frame.pc + 1;
}

fn exec_clz(frame: *Frame) !u32 {
    try frame.stack.push(word.clz(try frame.stack.pop()));
    return frame.pc + 1;
}

fn exec_push_const(frame: *Frame, value: u256) !u32 {
    try frame.stack.push(value);
    return frame.pc + 1;
}

fn exec_pop(frame: *Frame) !u32 {
    _ = try frame.stack.pop();
    return frame.pc + 1;
}

fn exec_mload(frame: *Frame) !u32 {
    const offset = try word.to_u32(try frame.stack.pop());
    const old_size = frame.memory.size();
    const value = try frame.memory.load(offset);
    try frame.gas.consume_memory(old_size, frame.memory.size());
    try frame.stack.push(value);
    return frame.pc + 1;
}

fn exec_mstore(frame: *Frame) !u32 {
    const offset = try word.to_u32(try frame.stack.pop());
    const value = try frame.stack.pop();
    const old_size = frame.memory.size();
    try frame.memory.store(offset, value);
    try frame.gas.consume_memory(old_size, frame.memory.size());
    return frame.pc + 1;
}

fn exec_mstore8(frame: *Frame) !u32 {
    const offset = try word.to_u32(try frame.stack.pop());
    const value = try frame.stack.pop();
    const old_size = frame.memory.size();
    try frame.memory.store_byte(offset, @truncate(value));
    try frame.gas.consume_memory(old_size, frame.memory.size());
    return frame.pc + 1;
}

fn exec_mcopy(frame: *Frame) !u32 {
    const dest = try word.to_u32(try frame.stack.pop());
    const src = try word.to_u32(try frame.stack.pop());
    const length = try word.to_u32(try frame.stack.pop());
    try frame.gas.consume_copy(length);
    const old_size = frame.memory.size();
    try frame.memory.copy(dest, src, length);
    try frame.gas.consume_memory(old_size, frame.memory.size());
    return frame.pc + 1;
}

fn exec_blobhash(frame: *Frame) !u32 {
    _ = try frame.stack.pop();
    try frame.stack.push(0);
    return frame.pc + 1;
}

fn exec_blockhash(frame: *Frame) !u32 {
    _ = try frame.stack.pop();
    try frame.stack.push(0);
    return frame.pc + 1;
}

fn exec_dupn(frame: *Frame) !u32 {
    const immediate = opcode_mod.read_immediate_byte(frame.code, frame.pc);
    if (!opcode_mod.dupn_immediate_valid(immediate)) return error.InvalidOpcode;
    const n = opcode_mod.decode_single(immediate);
    if (n == 0 or n > frame.stack.depth) return error.StackUnderflow;
    try frame.stack.dup(n - 1);
    return frame.pc + 2;
}

fn exec_swapn(frame: *Frame) !u32 {
    const immediate = opcode_mod.read_immediate_byte(frame.code, frame.pc);
    if (!opcode_mod.dupn_immediate_valid(immediate)) return error.InvalidOpcode;
    const n = opcode_mod.decode_single(immediate);
    try frame.stack.swap(n);
    return frame.pc + 2;
}

fn exec_exchange(frame: *Frame) !u32 {
    const immediate = opcode_mod.read_immediate_byte(frame.code, frame.pc);
    if (!opcode_mod.exchange_immediate_valid(immediate)) return error.InvalidOpcode;
    const pair = opcode_mod.decode_pair(immediate);
    try frame.stack.exchange(pair.n, pair.m);
    return frame.pc + 2;
}

fn exec_jump(frame: *Frame) !u32 {
    const dest = try word.to_u32(try frame.stack.pop());
    if (!is_jumpdest(frame.code, dest)) return error.InvalidJump;
    return dest;
}

fn exec_jumpi(frame: *Frame) !u32 {
    const dest_word = try frame.stack.pop();
    const condition = try frame.stack.pop();
    if (condition == 0) return frame.pc + 1;
    const dest = try word.to_u32(dest_word);
    if (!is_jumpdest(frame.code, dest)) return error.InvalidJump;
    return dest;
}

fn exec_calldataload(frame: *Frame) !u32 {
    const offset = try word.to_u32(try frame.stack.pop());
    var word_bytes: [32]u8 = undefined;
    @memset(&word_bytes, 0);
    var index: u32 = 0;
    while (index < 32) : (index += 1) {
        const source = offset + index;
        if (source < frame.calldata.len) word_bytes[index] = frame.calldata[source];
    }
    try frame.stack.push(word.from_bytes_be(&word_bytes));
    return frame.pc + 1;
}

fn exec_calldatacopy(frame: *Frame) !u32 {
    return try exec_copy_from(frame, frame.calldata);
}

fn exec_codecopy(frame: *Frame) !u32 {
    return try exec_copy_from(frame, frame.code);
}

fn exec_copy_from(frame: *Frame, source: []const u8) !u32 {
    const dest = try word.to_u32(try frame.stack.pop());
    const offset = try word.to_u32(try frame.stack.pop());
    const size = try word.to_u32(try frame.stack.pop());
    try frame.gas.consume_copy(size);
    const old_size = frame.memory.size();
    try frame.memory.expand(dest, size);
    try frame.gas.consume_memory(old_size, frame.memory.size());
    var index: u32 = 0;
    while (index < size) : (index += 1) {
        const src = offset + index;
        const byte: u8 = if (src < source.len) source[src] else 0;
        try frame.memory.store_byte(dest + index, byte);
    }
    return frame.pc + 1;
}

fn is_jumpdest(code: []const u8, dest: u32) bool {
    if (dest >= code.len) return false;
    var pc: u32 = 0;
    while (pc < code.len) {
        const opcode = code[pc];
        if (pc == dest) return opcode == @intFromEnum(opcode_mod.Opcode.jumpdest);
        if (opcode >= 0x5f and opcode <= 0x7f) {
            const push_width: u32 = if (opcode == 0x5f) 0 else @as(u32, opcode - 0x60) + 1;
            pc += 1 + push_width;
        } else {
            pc += 1;
        }
    }
    return false;
}

fn add(a: u256, b: u256) u256 {
    return a +% b;
}

fn mul(a: u256, b: u256) u256 {
    return a *% b;
}

fn sub(a: u256, b: u256) u256 {
    return a -% b;
}

fn lt(a: u256, b: u256) bool {
    return a < b;
}

fn gt(a: u256, b: u256) bool {
    return a > b;
}

fn eq(a: u256, b: u256) bool {
    return a == b;
}

fn bit_and(a: u256, b: u256) u256 {
    return a & b;
}

fn bit_or(a: u256, b: u256) u256 {
    return a | b;
}

fn bit_xor(a: u256, b: u256) u256 {
    return a ^ b;
}
