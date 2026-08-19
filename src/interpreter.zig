const std = @import("std");
const gas_mod = @import("gas.zig");
const limits = @import("limits.zig");
const memory_mod = @import("memory.zig");
const opcode_mod = @import("opcode.zig");
const precompile = @import("precompile.zig");
const cheatcode = @import("cheatcode.zig");
const rlp = @import("rlp.zig");
const header_mod = @import("header.zig");
const trie_mod = @import("trie.zig");
const delegation = @import("delegation.zig");
const stack_mod = @import("stack.zig");
const state_mod = @import("state.zig");
const word = @import("u256.zig");
const world_mod = @import("world.zig");
const trace_mod = @import("trace.zig");

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
    disable_precompiles: bool,
    out_offset: u32,
    out_size: u32,
    pool_mark: u32,
    journal_mark: u32,
    refund_mark: i64,
    log_mark: u32,
    log_data_mark: u32,
    created_mark: u32,
    delete_mark: u32,
    mem_offset: u32,
};

pub const Log = struct {
    address: u256,
    topics: [limits.log_topics_max]u256,
    topic_count: u32,
    data_off: u32,
    data_len: u32,
};

const AccessedSlot = struct {
    address: u256,
    key: u256,
    original: u256,
};

pub const AccessListItem = struct {
    address: u256,
    keys: []const u256,
};

pub const Authorization = delegation.Authorization;

pub const BlockTx = struct {
    to: ?u256,
    data: []const u8,
    gas_limit: u64,
    value: u256,
    sender: u256,
    gas_price: u256,
    access_list: []const AccessListItem = &.{},
    authorizations: []const Authorization = &.{},
};

/// EIP-4788 / EIP-2935 / EIP-7002 / EIP-7251 system caller.
const system_address: u256 = 0xfffffffffffffffffffffffffffffffffffffffe;
const beacon_roots_address: u256 = 0x000F3dF6D732807EF1319Fb7B8BB8522d0BEAC02;
const history_storage_address: u256 = 0x0000F90827F1C53a10cb7A02335B175320002935;
const withdrawal_request_address: u256 = 0x00000961Ef480Eb55e80D19ad83579A64c007002;
const consolidation_request_address: u256 = 0x0000BBddc7CE488642fb579F8B00f3A590007251;
const system_tx_gas: u64 = 30_000_000;

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
    accessed_slots: [limits.accessed_storage_max]AccessedSlot,
    accessed_slot_count: u32,
    logs: [limits.logs_max]Log,
    log_count: u32,
    log_data: [limits.log_data_pool_bytes_max]u8,
    log_data_used: u32,
    fork: opcode_mod.Fork,
    steps: u32,
    env: state_mod.ExecutionContext,
    cheats: cheatcode.State,
    cheats_enabled: bool,
    gas_refund: i64,
    access_list: []const AccessListItem,
    authorizations: []const delegation.Authorization,
    created_this_tx: [limits.accounts_max]u256,
    created_count: u32,
    deleted: [limits.accounts_max]u256,
    delete_count: u32,
    block_hashes: [limits.block_hashes_max][32]u8,
    block_hash_count: u32,
    tx_gas_used: u64,
    /// Null on the jsontest / forge-test path. Set only by `debug`.
    trace: ?*trace_mod.Trace,

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
        self.accessed_slot_count = 0;
        self.log_count = 0;
        self.log_data_used = 0;
        self.fork = fork;
        self.steps = 0;
        self.env = context;
        self.cheats = .{};
        self.cheats_enabled = false;
        self.gas_refund = 0;
        self.access_list = &.{};
        self.authorizations = &.{};
        self.created_count = 0;
        self.delete_count = 0;
        self.block_hash_count = header_mod.fill_window(
            &self.block_hashes,
            context.number,
            context.coinbase,
            context.gas_limit,
            context.timestamp,
            context.base_fee,
            context.prev_randao,
            trie_mod.empty_root,
        );
        self.trace = null;
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
        self.access_list = &.{};
        self.authorizations = &.{};
        self.trace = null;
        self.block_hash_count = 0;
        self.reset_tx();
    }

    pub fn apply_create(
        self: *Vm,
        init_code: []const u8,
        gas_limit: u64,
        value: u256,
        context: state_mod.ExecutionContext,
    ) !u256 {
        if (init_code.len > self.init_code_limit()) return 0;
        self.reset_tx();
        try self.warm_precompiles();
        try self.warm_access_list();
        const sender = context.caller;
        try self.mark_warm(sender);
        try self.mark_warm(context.origin);
        try self.mark_warm(self.env.coinbase);
        const nonce = self.world.get_nonce(sender);
        const address = rlp.create_address(sender, nonce);
        try self.world.increment_nonce(sender);
        try self.mark_warm(address);
        if (self.world.create_collision(address)) return 0;
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
        self.run_or_fault();
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
        std.debug.assert(calldata.len <= limits.calldata_bytes_max);
        self.reset_tx();
        try self.warm_precompiles();
        try self.warm_access_list();
        try self.mark_warm(to);
        try self.mark_warm(context.caller);
        try self.mark_warm(context.origin);
        try self.mark_warm(self.env.coinbase);
        try self.apply_authorizations();
        const resolved = try self.follow_tx_delegation(to);
        var child_context = context;
        child_context.address = to;
        child_context.call_value = value;
        try self.push_message(.{
            .code = resolved.code,
            .calldata = calldata,
            .gas_limit = gas_limit,
            .context = child_context,
            .depth = 0,
            .is_static = false,
            .kind = .call,
            .code_address = resolved.address,
            .disable_precompiles = resolved.disable_precompiles,
            .out_offset = 0,
            .out_size = 0,
            .should_transfer = value != 0,
            .value = value,
        });
        self.run_or_fault();
        return self.current().status;
    }

    /// One state-test transaction: charge gas, bump nonce, CALL or CREATE, then settle fees.
    /// Cold accounts that are never touched stay unloaded (pre-state only).
    pub fn apply_tx(
        self: *Vm,
        to: ?u256,
        data: []const u8,
        gas_limit: u64,
        value: u256,
        sender: u256,
    ) !Status {
        if (self.authorizations.len != 0 and to == null) return error.InvalidTx;
        const intrinsic = gas_mod.intrinsic_gas(data, to == null) + self.access_list_gas() +
            @as(u64, self.authorizations.len) * gas_mod.gas_auth_per_empty;
        if (gas_limit < intrinsic) return error.IntrinsicGas;
        const fees = gas_mod.fees_from_prices(self.env.gas_price, self.env.base_fee);
        const upfront = @as(u256, gas_limit) * fees.effective;
        const sender_bal = self.world.get_balance(sender);
        if (sender_bal < upfront + value) return error.InsufficientFunds;
        try self.world.set_balance(sender, sender_bal - upfront);
        self.env.gas_price = fees.effective;
        var ctx = self.env;
        ctx.caller = sender;
        ctx.origin = sender;
        ctx.call_value = value;
        ctx.gas_price = fees.effective;
        const exec_gas = gas_limit - intrinsic;
        if (to) |dest| {
            try self.world.increment_nonce(sender);
            const status = try self.apply_message(dest, data, exec_gas, value, ctx);
            if (status == .returned or status == .stopped) try self.destroy_deleted();
        } else {
            const created = try self.apply_create(data, exec_gas, value, ctx);
            if (created != 0) try self.destroy_deleted();
        }
        try self.settle_gas(sender, gas_limit, fees, gas_mod.calldata_floor_gas(data));
        return self.current().status;
    }

    /// Run every transaction in a block. Caller sets `env.chain_id`. Gas is
    /// the sum of settled tx gas; the BLOCKHASH window is not updated here.
    pub fn apply_block(self: *Vm, header: header_mod.Header, txs: []const BlockTx) !u64 {
        self.bind_block(header);
        try self.apply_block_system_pre(header);
        var gas_used: u64 = 0;
        for (txs) |tx| {
            try self.apply_block_tx(tx);
            const next = @addWithOverflow(gas_used, self.tx_gas_used);
            if (next[1] == 1) return error.BlockGasOverflow;
            gas_used = next[0];
        }
        try self.apply_block_system_post();
        return gas_used;
    }

    pub fn push_block_hash(self: *Vm, hash: [32]u8) void {
        if (self.block_hash_count < limits.block_hashes_max) {
            self.block_hashes[self.block_hash_count] = hash;
            self.block_hash_count += 1;
            return;
        }
        var i: u32 = 0;
        while (i + 1 < limits.block_hashes_max) : (i += 1) {
            self.block_hashes[i] = self.block_hashes[i + 1];
        }
        self.block_hashes[limits.block_hashes_max - 1] = hash;
    }

    fn bind_block(self: *Vm, header: header_mod.Header) void {
        self.env.coinbase = header.coinbase;
        self.env.number = header.number;
        self.env.timestamp = header.timestamp;
        self.env.gas_limit = header.gas_limit;
        self.env.base_fee = header.base_fee;
        self.env.prev_randao = word.from_bytes_be(&header.prev_randao);
    }

    fn apply_block_tx(self: *Vm, tx: BlockTx) !void {
        if (tx.gas_limit == 0) return error.IntrinsicGas;
        self.access_list = tx.access_list;
        self.authorizations = tx.authorizations;
        self.env.gas_price = tx.gas_price;
        _ = try self.apply_tx(tx.to, tx.data, tx.gas_limit, tx.value, tx.sender);
    }

    fn apply_block_system_pre(self: *Vm, header: header_mod.Header) !void {
        try self.system_call(beacon_roots_address, &header.parent_beacon_root);
        try self.system_call(history_storage_address, &header.parent_hash);
    }

    fn apply_block_system_post(self: *Vm) !void {
        try self.system_call(withdrawal_request_address, &[_]u8{});
        try self.system_call(consolidation_request_address, &[_]u8{});
    }

    fn system_call(self: *Vm, to: u256, data: []const u8) !void {
        if (self.world.code_of(to).len == 0) return;
        const saved_list = self.access_list;
        const saved_auth = self.authorizations;
        self.access_list = &.{};
        self.authorizations = &.{};
        defer {
            self.access_list = saved_list;
            self.authorizations = saved_auth;
        }
        var ctx = self.env;
        ctx.caller = system_address;
        ctx.origin = system_address;
        ctx.call_value = 0;
        _ = self.apply_message(to, data, system_tx_gas, 0, ctx) catch {};
    }

    fn settle_gas(self: *Vm, sender: u256, gas_limit: u64, fees: gas_mod.TxFees, floor: u64) !void {
        std.debug.assert(self.frame_count >= 1);
        const used = gas_mod.settled_gas_used(
            gas_limit,
            self.current().gas.remaining(),
            self.gas_refund,
            floor,
        );
        self.tx_gas_used = used;
        const unused = gas_limit - used;
        try self.world.set_balance(sender, self.world.get_balance(sender) + @as(u256, unused) * fees.effective);
        const tip = @as(u256, used) * fees.priority;
        if (tip == 0) return;
        try self.world.set_balance(self.env.coinbase, self.world.get_balance(self.env.coinbase) + tip);
    }

    fn reset_tx(self: *Vm) void {
        self.frame_count = 0;
        self.memory_used = 0;
        self.last_return_len = 0;
        self.output_len = 0;
        self.accessed_count = 0;
        self.accessed_slot_count = 0;
        self.log_count = 0;
        self.log_data_used = 0;
        self.steps = 0;
        self.gas_refund = 0;
        self.world.transient_count = 0;
        self.created_count = 0;
        self.delete_count = 0;
        self.tx_gas_used = 0;
    }

    fn run_or_fault(self: *Vm) void {
        self.run() catch {
            self.fault_current();
            self.finish_top();
        };
    }

    pub fn run(self: *Vm) !void {
        std.debug.assert(self.frame_count == 1);
        while (true) {
            const frame = self.current();
            if (frame.status != .running) {
                if (self.frame_count == 1) {
                    self.finish_top();
                    return;
                }
                try self.exit_child();
                continue;
            }
            if (self.steps >= limits.trace_steps_max) return error.StepLimitExceeded;
            self.steps += 1;
            if (self.trace) |tr| {
                self.record_trace(tr);
                if (tr.stop_at != 0 and tr.step_count == tr.stop_at) {
                    tr.paused = true;
                    return;
                }
            }
            self.step() catch |err| {
                if (self.frame_count == 1) return err;
                self.fault_current();
            };
        }
    }

    fn finish_top(self: *Vm) void {
        if (self.trace) |tr| tr.close_call(self.frame_count - 1);
        const frame = self.current();
        if (frame.status == .stopped) self.output_len = 0;
        const success = frame.status == .returned or frame.status == .stopped;
        if (!success) {
            self.rollback_frame(frame);
            return;
        }
        if (frame.kind != .create) return;
        self.deposit_create_code(frame) catch {
            frame.status = .faulted;
            frame.gas.used = frame.gas.limit;
            self.output_len = 0;
            self.rollback_frame(frame);
        };
    }

    fn rollback_frame(self: *Vm, frame: *const Frame) void {
        self.world.rollback(frame.journal_mark);
        self.gas_refund = frame.refund_mark;
        self.log_count = frame.log_mark;
        self.log_data_used = frame.log_data_mark;
        self.created_count = frame.created_mark;
        self.delete_count = frame.delete_mark;
    }

    pub fn current(self: *Vm) *Frame {
        std.debug.assert(self.frame_count > 0);
        std.debug.assert(self.frame_count <= limits.call_frames_max);
        return &self.frames[self.frame_count - 1];
    }

    fn step(self: *Vm) !void {
        const frame = self.current();
        if (self.cheats_enabled and cheatcode.is_cheatcode(frame.code_address)) {
            try self.exec_cheatcode();
            return;
        }
        if (precompile.is_precompile(frame.code_address, self.fork) and !frame.disable_precompiles) {
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
            .byte => try exec_byte(frame),
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
            .blockhash => try self.exec_blockhash(),
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
            .selfdestruct => try self.exec_selfdestruct(),
            .log0 => try self.exec_log(0),
            .log1 => try self.exec_log(1),
            .log2 => try self.exec_log(2),
            .log3 => try self.exec_log(3),
            .log4 => try self.exec_log(4),
            else => return error.InvalidOpcode,
        };
    }

    fn exec_blockhash(self: *Vm) !u32 {
        const frame = self.current();
        const wanted = try frame.stack.pop();
        const hash = header_mod.lookup(
            &self.block_hashes,
            self.block_hash_count,
            self.env.number,
            wanted,
        );
        try frame.stack.push(hash);
        return frame.pc + 1;
    }

    fn exec_sload(self: *Vm) !u32 {
        const frame = self.current();
        const key = try frame.stack.pop();
        try frame.gas.consume(try self.access_storage(frame.context.address, key));
        try frame.stack.push(self.world.load(frame.context.address, key));
        return frame.pc + 1;
    }

    fn exec_sstore(self: *Vm) !u32 {
        const frame = self.current();
        const key = try frame.stack.pop();
        const new_value = try frame.stack.pop();
        if (frame.gas.remaining() <= gas_mod.gas_call_stipend) return error.OutOfGas;
        const addr = frame.context.address;
        const cold = !self.is_storage_warm(addr, key);
        try self.mark_storage_warm(addr, key);
        const charge = gas_mod.sstore_gas(
            self.storage_original(addr, key),
            self.world.load(addr, key),
            new_value,
            cold,
        );
        try frame.gas.consume(charge.cost);
        if (frame.is_static) return error.WriteInStaticContext;
        try self.world.store(addr, key, new_value);
        self.gas_refund += charge.refund_delta;
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

    fn exec_selfdestruct(self: *Vm) !u32 {
        const frame = self.current();
        const beneficiary = word.to_address(try frame.stack.pop());
        var cost: u64 = gas_mod.gas_selfdestruct;
        if (!self.is_warm(beneficiary)) {
            try self.mark_warm(beneficiary);
            cost += gas_mod.gas_cold_account;
        }
        const originator = frame.context.address;
        const balance = self.world.get_balance(originator);
        if (!self.world.is_alive(beneficiary) and balance != 0) {
            cost += gas_mod.gas_selfdestruct_new_account;
        }
        try frame.gas.consume(cost);
        if (frame.is_static) return error.WriteInStaticContext;
        try self.world.move_ether(originator, beneficiary, balance);
        if (self.is_created(originator)) {
            if (beneficiary == originator) try self.world.set_balance(originator, 0);
            try self.mark_deleted(originator);
        }
        frame.status = .stopped;
        return @intCast(frame.code.len);
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

        const target = switch (kind) {
            .call, .staticcall => to,
            .callcode, .delegatecall => frame.context.address,
        };
        var extra = try self.access_account(to);
        const resolved = try self.resolve_delegation(to);
        extra += resolved.extra;
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
            self.apply_prank(&child_context, to, frame.depth);
        }
        if (kind == .call or kind == .staticcall) {
            if (try self.try_mock(
                to,
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
            .code = resolved.code,
            .calldata = frame.memory.bytes[in_offset .. in_offset + in_size],
            .gas_limit = call_gas.sub_call,
            .context = child_context,
            .depth = frame.depth + 1,
            .is_static = kind == .staticcall or frame.is_static,
            .kind = .call,
            .code_address = resolved.address,
            .disable_precompiles = resolved.disable_precompiles,
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
        if (self.world.create_collision(contract)) {
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
        std.debug.assert(precompile.is_precompile(frame.code_address, self.fork));
        const cost = precompile.gas_cost(frame.code_address, frame.calldata, self.fork) catch {
            frame.gas.used = frame.gas.limit;
            return error.OutOfGas;
        };
        try frame.gas.consume(cost);
        self.output_len = try precompile.execute(
            frame.code_address,
            frame.calldata,
            self.output_buffer[0..],
            self.fork,
        );
        frame.status = .returned;
    }

    fn exec_cheatcode(self: *Vm) !void {
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
        if (result.restore_logs) {
            self.log_count = result.log_count;
            self.log_data_used = result.log_data_used;
        }
        if (result.spawn_create) {
            if (frame.is_static or !self.spawn_cheat_create()) {
                frame.status = .reverted;
                self.output_len = 0;
                return;
            }
            return;
        }
        self.output_len = result.len;
        frame.status = if (result.revert) .reverted else .returned;
    }

    /// CREATE from the contract that called the cheatcode (`new Foo()`), not hevm.
    fn spawn_cheat_create(self: *Vm) bool {
        std.debug.assert(self.frame_count >= 2);
        const frame = self.current();
        const sender = self.frames[self.frame_count - 2].context.address;
        const init_code = self.cheats.init_code[0..self.cheats.init_code_len];
        const endowment = self.cheats.create_value;
        if (init_code.len > limits.init_code_bytes_max) return false;
        const nonce = self.world.get_nonce(sender);
        if (self.world.get_balance(sender) < endowment or nonce == std.math.maxInt(u64)) return false;
        if (frame.depth + 1 > limits.call_depth_limit) return false;
        const contract = if (self.cheats.use_create2)
            rlp.create2_address(sender, self.cheats.create_salt, init_code)
        else
            rlp.create_address(sender, nonce);
        self.mark_warm(contract) catch return false;
        if (self.world.create_collision(contract)) {
            self.world.increment_nonce(sender) catch return false;
            return false;
        }
        self.world.increment_nonce(sender) catch return false;
        const create_gas = gas_mod.max_message_call_gas(frame.gas.remaining());
        frame.gas.consume(create_gas) catch return false;
        var child_context = frame.context;
        child_context.address = contract;
        child_context.caller = sender;
        child_context.call_value = endowment;
        self.bump_pool(frame);
        self.cheats.deploy_pending = true;
        self.push_message(.{
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
        }) catch {
            self.cheats.deploy_pending = false;
            return false;
        };
        return true;
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
        const created_mark = self.created_count;
        const delete_mark = self.delete_count;
        if (params.should_transfer and params.value != 0) {
            try self.world.touch(params.context.address);
            try self.world.move_ether(params.context.caller, params.context.address, params.value);
        } else {
            try self.world.touch(params.context.address);
        }
        if (params.kind == .create) {
            try self.world.set_nonce(params.context.address, 1);
            try self.mark_created(params.context.address);
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
            .disable_precompiles = params.disable_precompiles,
            .out_offset = params.out_offset,
            .out_size = params.out_size,
            .pool_mark = pool_mark,
            .journal_mark = journal_mark,
            .refund_mark = self.gas_refund,
            .log_mark = self.log_count,
            .log_data_mark = self.log_data_used,
            .created_mark = created_mark,
            .delete_mark = delete_mark,
            .mem_offset = mem_offset,
        };
        self.frame_count += 1;
        std.debug.assert(self.frame_count <= limits.call_frames_max);
        std.debug.assert(params.depth <= limits.call_depth_limit);
        if (self.trace) |tr| {
            const parent = if (self.frame_count >= 2)
                tr.call_of_frame(self.frame_count - 2)
            else
                trace_mod.no_parent;
            tr.open_call(
                self.frame_count - 1,
                parent,
                params.depth,
                params.context.address,
                params.code_address,
                params.kind == .create,
                params.gas_limit,
            );
        }
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
        if (!raw_ok) self.rollback_frame(child);
        if (raw_ok or revert) {
            self.frames[self.frame_count - 2].gas.refund(child.gas.remaining());
        }
        const parent = &self.frames[self.frame_count - 2];
        if (self.cheats.deploy_pending and cheatcode.is_cheatcode(parent.code_address)) {
            self.finish_cheat_create(parent, child, parent_ok);
            if (fail_parent) parent.status = .reverted;
            if (self.trace) |tr| tr.close_call(self.frame_count - 1);
            self.memory_used = child.pool_mark;
            self.frame_count -= 1;
            return;
        }
        @memcpy(self.last_return[0..self.output_len], self.output_buffer[0..self.output_len]);
        self.last_return_len = self.output_len;
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
        if (self.trace) |tr| tr.close_call(self.frame_count - 1);
        self.memory_used = child.pool_mark;
        self.frame_count -= 1;
        self.output_len = 0;
    }

    fn finish_cheat_create(self: *Vm, parent: *Frame, child: *const Frame, parent_ok: bool) void {
        self.cheats.deploy_pending = false;
        if (parent_ok) {
            word.to_bytes_be(child.context.address, self.output_buffer[0..32]);
            self.output_len = 32;
            parent.status = .returned;
        } else {
            self.output_len = 0;
            parent.status = .reverted;
        }
        if (self.output_len > 0) {
            @memcpy(self.last_return[0..self.output_len], self.output_buffer[0..self.output_len]);
        }
        self.last_return_len = self.output_len;
    }

    fn deposit_create_code(self: *Vm, child: *Frame) !void {
        const code = self.output_buffer[0..self.output_len];
        if (self.output_len > self.code_limit() or (code.len > 0 and code[0] == 0xef)) {
            return error.InvalidCode;
        }
        const deposit = @as(u64, self.output_len) * gas_mod.gas_code_deposit;
        try child.gas.consume(deposit);
        try self.world.set_code(child.context.address, code);
    }

    fn code_limit(self: *const Vm) u32 {
        return if (self.cheats_enabled) limits.forge_code_bytes_max else limits.code_bytes_max;
    }

    fn init_code_limit(self: *const Vm) u32 {
        return if (self.cheats_enabled) limits.forge_init_code_bytes_max else limits.init_code_bytes_max;
    }

    fn bump_pool(self: *Vm, frame: *Frame) void {
        const end = frame.mem_offset + frame.memory.active_bytes;
        if (end > self.memory_used) self.memory_used = end;
    }

    fn record_trace(self: *Vm, tr: *trace_mod.Trace) void {
        const frame = self.current();
        const op_byte: u8 = if (frame.pc < frame.code.len) frame.code[frame.pc] else 0;
        tr.record_step(.{
            .pc = frame.pc,
            .opcode = op_byte,
            .gas_remaining = frame.gas.remaining(),
            .depth = frame.depth,
            .stack_depth = frame.stack.depth,
            .call_index = tr.call_of_frame(self.frame_count - 1),
        });
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

    fn access_storage(self: *Vm, address: u256, key: u256) !u64 {
        if (self.is_storage_warm(address, key)) return gas_mod.gas_warm_access;
        try self.mark_storage_warm(address, key);
        return gas_mod.gas_cold_sload;
    }

    fn is_storage_warm(self: *const Vm, address: u256, key: u256) bool {
        var index: u32 = 0;
        while (index < self.accessed_slot_count) : (index += 1) {
            const slot = self.accessed_slots[index];
            if (slot.address == address and slot.key == key) return true;
        }
        return false;
    }

    fn mark_storage_warm(self: *Vm, address: u256, key: u256) !void {
        if (self.is_storage_warm(address, key)) return;
        if (self.accessed_slot_count >= limits.accessed_storage_max) return error.AccessListFull;
        self.accessed_slots[self.accessed_slot_count] = .{
            .address = address,
            .key = key,
            .original = self.world.load(address, key),
        };
        self.accessed_slot_count += 1;
    }

    fn storage_original(self: *const Vm, address: u256, key: u256) u256 {
        var index: u32 = 0;
        while (index < self.accessed_slot_count) : (index += 1) {
            const slot = self.accessed_slots[index];
            if (slot.address == address and slot.key == key) return slot.original;
        }
        return self.world.load(address, key);
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
        if (self.fork.at_least(.osaka)) try self.mark_warm(0x100);
    }

    fn warm_access_list(self: *Vm) !void {
        for (self.access_list) |item| {
            try self.mark_warm(item.address);
            for (item.keys) |key| {
                try self.mark_storage_warm(item.address, key);
            }
        }
    }

    fn access_list_gas(self: *const Vm) u64 {
        var addresses: u64 = 0;
        var keys: u64 = 0;
        for (self.access_list) |item| {
            addresses += 1;
            keys += item.keys.len;
        }
        return gas_mod.access_list_gas(addresses, keys);
    }

    const ResolvedCode = struct {
        address: u256,
        code: []const u8,
        extra: u64,
        disable_precompiles: bool,
    };

    /// Top-level type-4 / call target: follow one designation, no extra gas.
    fn follow_tx_delegation(self: *Vm, to: u256) !ResolvedCode {
        const code = self.world.code_of(to);
        const delegated = delegation.delegated_address(code) orelse
            return .{ .address = to, .code = code, .extra = 0, .disable_precompiles = false };
        try self.mark_warm(delegated);
        return .{
            .address = delegated,
            .code = self.world.code_of(delegated),
            .extra = 0,
            .disable_precompiles = true,
        };
    }

    /// CALL* resolution: follow one designation and charge warm/cold for it.
    fn resolve_delegation(self: *Vm, address: u256) !ResolvedCode {
        const code = self.world.code_of(address);
        const delegated = delegation.delegated_address(code) orelse
            return .{ .address = address, .code = code, .extra = 0, .disable_precompiles = false };
        return .{
            .address = delegated,
            .code = self.world.code_of(delegated),
            .extra = try self.access_account(delegated),
            .disable_precompiles = true,
        };
    }

    fn apply_authorizations(self: *Vm) !void {
        std.debug.assert(self.authorizations.len <= limits.authorizations_max);
        for (self.authorizations) |auth| {
            try self.apply_one_authorization(auth);
        }
    }

    fn apply_one_authorization(self: *Vm, auth: delegation.Authorization) !void {
        if (auth.chain_id != 0 and auth.chain_id != self.env.chain_id) return;
        if (auth.nonce == std.math.maxInt(u64)) return;
        const authority = delegation.recover_authority(auth) orelse return;
        try self.mark_warm(authority);
        const code = self.world.code_of(authority);
        if (code.len != 0 and !delegation.is_valid(code)) return;
        if (self.world.get_nonce(authority) != auth.nonce) return;
        if (self.world.get_account(authority) != null) {
            self.gas_refund += @as(i64, gas_mod.gas_auth_per_empty - gas_mod.gas_auth_base);
        }
        if (auth.address == 0) {
            try self.world.set_code(authority, &[_]u8{});
        } else {
            const des = delegation.designation(auth.address);
            try self.world.set_code(authority, &des);
        }
        try self.world.increment_nonce(authority);
    }

    fn is_created(self: *const Vm, address: u256) bool {
        var index: u32 = 0;
        while (index < self.created_count) : (index += 1) {
            if (self.created_this_tx[index] == address) return true;
        }
        return false;
    }

    fn mark_created(self: *Vm, address: u256) !void {
        if (self.is_created(address)) return;
        if (self.created_count >= limits.accounts_max) return error.AccountLimit;
        self.created_this_tx[self.created_count] = address;
        self.created_count += 1;
    }

    fn mark_deleted(self: *Vm, address: u256) !void {
        var index: u32 = 0;
        while (index < self.delete_count) : (index += 1) {
            if (self.deleted[index] == address) return;
        }
        if (self.delete_count >= limits.accounts_max) return error.AccountLimit;
        self.deleted[self.delete_count] = address;
        self.delete_count += 1;
    }

    fn destroy_deleted(self: *Vm) !void {
        var index: u32 = 0;
        while (index < self.delete_count) : (index += 1) {
            try self.world.destroy_account(self.deleted[index]);
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
    disable_precompiles: bool = false,
    out_offset: u32,
    out_size: u32,
    should_transfer: bool,
    value: u256,
};

fn memory_gas_delta(old_size: u32, new_size: u32) u64 {
    return gas_mod.memory_expansion_gas(old_size, new_size);
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
    const a = try frame.stack.pop();
    const b = try frame.stack.pop();
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
    const a = try frame.stack.pop();
    const b = try frame.stack.pop();
    const modulus = try frame.stack.pop();
    try frame.stack.push(word.addmod(a, b, modulus));
    return frame.pc + 1;
}

fn exec_mulmod(frame: *Frame) !u32 {
    const a = try frame.stack.pop();
    const b = try frame.stack.pop();
    const modulus = try frame.stack.pop();
    try frame.stack.push(word.mulmod(a, b, modulus));
    return frame.pc + 1;
}

fn exec_exp(frame: *Frame) !u32 {
    const base = try frame.stack.pop();
    const exponent = try frame.stack.pop();
    const exp_bytes = word.exponent_byte_size(exponent);
    try frame.gas.consume(exp_bytes * gas_mod.gas_exp_byte);
    try frame.stack.push(word.exp(base, exponent));
    return frame.pc + 1;
}

fn exec_signextend(frame: *Frame) !u32 {
    const byte_index = try frame.stack.pop();
    const value = try frame.stack.pop();
    try frame.stack.push(word.signextend(byte_index, value));
    return frame.pc + 1;
}

fn exec_byte(frame: *Frame) !u32 {
    const index = try frame.stack.pop();
    const value = try frame.stack.pop();
    try frame.stack.push(word.byte(value, index));
    return frame.pc + 1;
}

fn exec_cmp(frame: *Frame, cmp: *const fn (u256, u256) bool) !u32 {
    const a = try frame.stack.pop();
    const b = try frame.stack.pop();
    try frame.stack.push(if (cmp(a, b)) 1 else 0);
    return frame.pc + 1;
}

fn exec_sgt(frame: *Frame) !u32 {
    const a = try frame.stack.pop();
    const b = try frame.stack.pop();
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
    const dest = try frame.stack.pop();
    const src = try frame.stack.pop();
    const length = try frame.stack.pop();
    try frame.gas.consume(try gas_mod.copy_words_gas(length));
    const old_size = frame.memory.size();
    const new_size = try memory_mod.expansion_end(old_size, dest, src, length);
    try frame.gas.consume_memory(old_size, new_size);
    if (new_size > frame.memory.bytes.len) return error.MemoryOverflow;
    if (length == 0) return frame.pc + 1;
    try frame.memory.copy(try word.to_u32(dest), try word.to_u32(src), try word.to_u32(length));
    return frame.pc + 1;
}

fn exec_blobhash(frame: *Frame) !u32 {
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
