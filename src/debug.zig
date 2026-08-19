//! LLM-queryable debugger: compact trace plus replay for stack/memory.

const std = @import("std");
const artifact = @import("artifact.zig");
const forge_test = @import("forge_test.zig");
const interpreter = @import("interpreter.zig");
const limits = @import("limits.zig");
const memory_mod = @import("memory.zig");
const opcode_mod = @import("opcode.zig");
const stack_mod = @import("stack.zig");
const state_mod = @import("state.zig");
const trace_mod = @import("trace.zig");
const word = @import("u256.zig");
const world_mod = @import("world.zig");

pub const Params = struct {
    step: u32 = 0,
    step_a: u32 = 0,
    step_b: u32 = 0,
    pc: u32 = 0,
    has_pc: bool = false,
    opcode: []const u8 = "",
    call: u32 = 0,
    has_call: bool = false,
    step_idx: u32 = 0,
    start: u32 = 0,
    count: u32 = 0,
};

pub fn parse_params(pairs: []const [:0]const u8) !Params {
    var params = Params{};
    for (pairs) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse return error.InvalidQueryParam;
        const key = pair[0..eq];
        const value = pair[eq + 1 ..];
        if (std.mem.eql(u8, key, "step")) {
            params.step = try parse_u32(value);
        } else if (std.mem.eql(u8, key, "step_a")) {
            params.step_a = try parse_u32(value);
        } else if (std.mem.eql(u8, key, "step_b")) {
            params.step_b = try parse_u32(value);
        } else if (std.mem.eql(u8, key, "pc")) {
            params.pc = try parse_u32(value);
            params.has_pc = true;
        } else if (std.mem.eql(u8, key, "opcode")) {
            params.opcode = value;
        } else if (std.mem.eql(u8, key, "call")) {
            params.call = try parse_u32(value);
            params.has_call = true;
        } else if (std.mem.eql(u8, key, "step_idx")) {
            params.step_idx = try parse_u32(value);
        } else if (std.mem.eql(u8, key, "start")) {
            params.start = try parse_u32(value);
        } else if (std.mem.eql(u8, key, "count")) {
            params.count = try parse_u32(value);
        } else {
            return error.UnknownQueryParam;
        }
    }
    return params;
}

pub fn is_command(text: []const u8) bool {
    const names = [_][]const u8{
        "overview", "call-tree", "storage-diff", "pc", "opcode", "trace",
        "state",    "step",      "explain",      "diff", "source", "watch-memory",
    };
    for (names) |name| {
        if (std.mem.eql(u8, text, name)) return true;
    }
    return false;
}

pub fn run_query(
    allocator: std.mem.Allocator,
    code: []const u8,
    calldata: []const u8,
    gas_limit: u64,
    fork: opcode_mod.Fork,
    command: []const u8,
    params: Params,
    writer: *std.Io.Writer,
) !void {
    var session = try Session.init_bytecode(allocator, code, calldata, gas_limit, fork);
    defer session.deinit();
    try dispatch(writer, &session, command, params);
}

pub fn run_query_forge(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    test_filter: []const u8,
    contract_filter: []const u8,
    fork: opcode_mod.Fork,
    command: []const u8,
    params: Params,
    writer: *std.Io.Writer,
) !void {
    const store = try allocator.create(artifact.Store);
    defer allocator.destroy(store);
    store.init();
    try store.load(allocator, io, dir);
    var matched = forge_test.match_test(allocator, io, dir, test_filter, contract_filter) catch |err| {
        return switch (err) {
            error.NoMatchingTest => write_err(writer, "no matching test"),
            error.AmbiguousTest => write_err(writer, "ambiguous test; pass --match-contract"),
            error.FuzzTest => write_err(writer, "fuzz tests are not debuggable"),
            error.FileNotFound => write_err(writer, "forge artifact directory not found"),
            else => err,
        };
    };
    defer matched.deinit();
    var session = Session.init_forge(allocator, &matched, fork, store) catch |err| {
        return switch (err) {
            error.CreateFailed => write_err(writer, "contract create failed"),
            else => err,
        };
    };
    defer session.deinit();
    try dispatch(writer, &session, command, params);
}

fn dispatch(
    writer: *std.Io.Writer,
    session: *Session,
    command: []const u8,
    params: Params,
) !void {
    if (std.mem.eql(u8, command, "overview")) return write_overview(writer, session, params);
    if (std.mem.eql(u8, command, "call-tree")) return write_call_tree(writer, session, params);
    if (std.mem.eql(u8, command, "storage-diff")) return write_storage_diff(writer, session, params);
    if (std.mem.eql(u8, command, "pc")) return write_pc(writer, session, params);
    if (std.mem.eql(u8, command, "opcode")) return write_opcode(writer, session, params);
    if (std.mem.eql(u8, command, "trace")) return write_trace(writer, session, params);
    if (std.mem.eql(u8, command, "state")) return write_state_query(writer, session, params);
    if (std.mem.eql(u8, command, "step")) return write_step_query(writer, session, params);
    if (std.mem.eql(u8, command, "explain")) return write_explain_query(writer, session, params);
    if (std.mem.eql(u8, command, "diff")) return write_diff_query(writer, session, params);
    if (std.mem.eql(u8, command, "source")) return write_err(writer, "source mapping is not available");
    if (std.mem.eql(u8, command, "watch-memory")) return write_err(writer, "watch-memory is not available");
    return write_err(writer, "unknown command");
}

const BytecodeSpec = struct {
    code: []const u8,
    calldata: []const u8,
    gas_limit: u64,
    context: state_mod.ExecutionContext,
};

const ForgeSpec = struct {
    bytecode: []const u8,
    selector: [4]u8,
    setup: ?[4]u8,
    contract: []const u8,
    test_name: []const u8,
};

const ReplaySpec = union(enum) {
    bytecode: BytecodeSpec,
    forge: ForgeSpec,
};

const Session = struct {
    allocator: std.mem.Allocator,
    vm: *interpreter.Vm,
    trace: *trace_mod.Trace,
    fork: opcode_mod.Fork,
    spec: ReplaySpec,
    artifacts: ?*const artifact.Store,
    run_error: ?[]const u8,

    fn init_bytecode(
        allocator: std.mem.Allocator,
        code: []const u8,
        calldata: []const u8,
        gas_limit: u64,
        fork: opcode_mod.Fork,
    ) !Session {
        std.debug.assert(gas_limit > 0);
        const vm, const tr = try alloc_vm_trace(allocator);
        errdefer {
            allocator.destroy(tr);
            allocator.destroy(vm);
        }
        var context = state_mod.ExecutionContext.default();
        context.address = 0xdeadbeef;
        try vm.init(code, calldata, gas_limit, context, fork);
        vm.trace = tr;
        const frame = vm.current();
        tr.open_root(frame.context.address, frame.code_address, frame.kind == .create, frame.gas.limit);
        var run_error: ?[]const u8 = null;
        vm.run() catch |err| {
            run_error = @errorName(err);
        };
        return .{
            .allocator = allocator,
            .vm = vm,
            .trace = tr,
            .fork = fork,
            .spec = .{ .bytecode = .{
                .code = code,
                .calldata = calldata,
                .gas_limit = gas_limit,
                .context = context,
            } },
            .artifacts = null,
            .run_error = run_error,
        };
    }

    fn init_forge(
        allocator: std.mem.Allocator,
        matched: *const forge_test.MatchedTest,
        fork: opcode_mod.Fork,
        artifacts: ?*const artifact.Store,
    ) !Session {
        const vm, const tr = try alloc_vm_trace(allocator);
        errdefer {
            allocator.destroy(tr);
            allocator.destroy(vm);
        }
        const case = matched.case();
        const spec = ForgeSpec{
            .bytecode = matched.suite.bytecode,
            .selector = case.selector,
            .setup = matched.suite.setup,
            .contract = matched.contract,
            .test_name = case.name,
        };
        const prepared = try deploy_forge(vm, fork, spec, artifacts);
        const run_error = run_forge_traced(vm, spec, prepared, tr);
        return .{
            .allocator = allocator,
            .vm = vm,
            .trace = tr,
            .fork = fork,
            .spec = .{ .forge = spec },
            .artifacts = artifacts,
            .run_error = run_error,
        };
    }

    fn deinit(self: *Session) void {
        self.allocator.destroy(self.trace);
        self.allocator.destroy(self.vm);
    }

    fn replay(self: *const Session, stop_at: u32) !Replay {
        return Replay.init(self, stop_at);
    }
};

fn alloc_vm_trace(allocator: std.mem.Allocator) !struct { *interpreter.Vm, *trace_mod.Trace } {
    const vm = try allocator.create(interpreter.Vm);
    errdefer allocator.destroy(vm);
    const tr = try allocator.create(trace_mod.Trace);
    errdefer allocator.destroy(tr);
    tr.reset();
    return .{ vm, tr };
}

const PreparedForge = struct {
    addr: u256,
    ctx: state_mod.ExecutionContext,
};

fn deploy_forge(
    vm: *interpreter.Vm,
    fork: opcode_mod.Fork,
    spec: ForgeSpec,
    artifacts: ?*const artifact.Store,
) !PreparedForge {
    try vm.init_session(fork);
    vm.cheats.artifacts = artifacts;
    try vm.world.set_balance(forge_test.default_sender, forge_test.default_balance);
    var ctx = state_mod.ExecutionContext.default();
    ctx.caller = forge_test.default_sender;
    ctx.origin = forge_test.default_sender;
    const addr = try vm.apply_create(spec.bytecode, forge_test.tx_gas, 0, ctx);
    if (addr == 0) return error.CreateFailed;
    return .{ .addr = addr, .ctx = ctx };
}

/// setUp first (cheatcodes live there), then the test. One Trace across both txs.
fn run_forge_traced(
    vm: *interpreter.Vm,
    spec: ForgeSpec,
    prepared: PreparedForge,
    tr: *trace_mod.Trace,
) ?[]const u8 {
    vm.trace = tr;
    if (spec.setup) |sel| {
        const status = vm.apply_call(prepared.addr, &sel, forge_test.tx_gas, prepared.ctx) catch |err| {
            return @errorName(err);
        };
        if (tr.paused) return null;
        if (status != .returned and status != .stopped) return null;
    }
    _ = vm.apply_call(prepared.addr, &spec.selector, forge_test.tx_gas, prepared.ctx) catch |err| {
        return @errorName(err);
    };
    return null;
}

const Replay = struct {
    allocator: std.mem.Allocator,
    vm: *interpreter.Vm,
    trace: *trace_mod.Trace,

    fn init(session: *const Session, stop_at: u32) !Replay {
        const vm, const tr = try alloc_vm_trace(session.allocator);
        errdefer {
            session.allocator.destroy(tr);
            session.allocator.destroy(vm);
        }
        tr.stop_at = stop_at;
        switch (session.spec) {
            .bytecode => |spec| {
                try vm.init(spec.code, spec.calldata, spec.gas_limit, spec.context, session.fork);
                vm.trace = tr;
                const frame = vm.current();
                tr.open_root(frame.context.address, frame.code_address, frame.kind == .create, frame.gas.limit);
                vm.run() catch {};
            },
            .forge => |spec| {
                const prepared = try deploy_forge(vm, session.fork, spec, session.artifacts);
                _ = run_forge_traced(vm, spec, prepared, tr);
            },
        }
        return .{ .allocator = session.allocator, .vm = vm, .trace = tr };
    }

    fn deinit(self: *Replay) void {
        self.allocator.destroy(self.trace);
        self.allocator.destroy(self.vm);
    }
};

fn query_count(params: Params) u32 {
    if (params.count == 0) return limits.debug_query_cap;
    return params.count;
}

fn write_overview(writer: *std.Io.Writer, session: *const Session, params: Params) !void {
    const tr = session.trace;
    const count = query_count(params);
    const start = params.start;
    const shown = slice_len(tr.call_count, start, count);
    try writer.writeAll("{\"total_steps\":");
    try write_u32(writer, tr.step_count);
    try writer.writeAll(",\"total_calls\":");
    try write_u32(writer, tr.call_count);
    try writer.writeAll(",\"truncated\":");
    try write_bool(writer, tr.truncated);
    try writer.writeAll(",\"paused\":");
    try write_bool(writer, tr.paused);
    try writer.writeAll(",\"status\":\"");
    try writer.writeAll(status_name(session.vm));
    try writer.writeAll("\",\"gas_used\":");
    try write_u64(writer, session.vm.current().gas.used);
    try writer.writeAll(",\"error\":");
    try write_opt_str(writer, session.run_error);
    try writer.writeAll(",\"mode\":\"");
    try writer.writeAll(switch (session.spec) {
        .bytecode => "bytecode",
        .forge => "forge",
    });
    try writer.writeAll("\"");
    switch (session.spec) {
        .bytecode => {},
        .forge => |spec| {
            try writer.writeAll(",\"contract\":\"");
            try writer.writeAll(spec.contract);
            try writer.writeAll("\",\"test\":\"");
            try writer.writeAll(spec.test_name);
            try writer.writeAll("\"");
        },
    }
    try writer.writeAll(",\"has_more\":");
    try write_bool(writer, start + shown < tr.call_count);
    try writer.writeAll(",\"calls\":[");
    var i: u32 = 0;
    while (i < shown) : (i += 1) {
        if (i != 0) try writer.writeAll(",");
        try write_call(writer, tr, start + i);
    }
    try writer.writeAll("]}");
}

fn write_call_tree(writer: *std.Io.Writer, session: *const Session, params: Params) !void {
    const tr = session.trace;
    const count = query_count(params);
    const start = params.start;
    const shown = slice_len(tr.call_count, start, count);
    try writer.writeAll("{\"total\":");
    try write_u32(writer, tr.call_count);
    try writer.writeAll(",\"has_more\":");
    try write_bool(writer, start + shown < tr.call_count);
    try writer.writeAll(",\"calls\":[");
    var i: u32 = 0;
    while (i < shown) : (i += 1) {
        if (i != 0) try writer.writeAll(",");
        try write_call(writer, tr, start + i);
    }
    try writer.writeAll("]}");
}

fn write_call(writer: *std.Io.Writer, tr: *const trace_mod.Trace, index: u32) !void {
    std.debug.assert(index < tr.call_count);
    const call = tr.calls[index];
    const ended = tr.ended(call);
    const steps: u32 = if (ended >= call.step_start) ended - call.step_start + 1 else 0;
    try writer.writeAll("{\"call_index\":");
    try write_u32(writer, index);
    try writer.writeAll(",\"parent_call_index\":");
    if (call.parent == trace_mod.no_parent) {
        try writer.writeAll("null");
    } else {
        try write_u32(writer, call.parent);
    }
    try writer.writeAll(",\"depth\":");
    try write_u32(writer, call.depth);
    try writer.writeAll(",\"address\":");
    try write_addr(writer, call.address);
    try writer.writeAll(",\"code_address\":");
    try write_addr(writer, call.code_address);
    try writer.writeAll(",\"kind\":\"");
    try writer.writeAll(if (call.is_create) "create" else "call");
    try writer.writeAll("\",\"step_start\":");
    try write_u32(writer, call.step_start);
    try writer.writeAll(",\"step_end\":");
    try write_u32(writer, ended);
    try writer.writeAll(",\"step_count\":");
    try write_u32(writer, steps);
    try writer.writeAll(",\"gas_limit\":");
    try write_u64(writer, call.gas_limit);
    try writer.writeAll("}");
}

fn write_storage_diff(writer: *std.Io.Writer, session: *const Session, params: Params) !void {
    var diffs: [256]world_mod.World.SlotDiff = undefined;
    const total = session.vm.world.collect_slot_diffs(&diffs);
    const count = query_count(params);
    const start = params.start;
    const shown = slice_len(total, start, count);
    try writer.writeAll("{\"total\":");
    try write_u32(writer, total);
    try writer.writeAll(",\"has_more\":");
    try write_bool(writer, start + shown < total);
    try writer.writeAll(",\"persistent\":[");
    var written: u32 = 0;
    var i: u32 = 0;
    while (i < total) : (i += 1) {
        if (diffs[i].transient) continue;
        if (i < start) continue;
        if (written >= shown) break;
        if (written != 0) try writer.writeAll(",");
        try write_slot_diff(writer, diffs[i]);
        written += 1;
    }
    try writer.writeAll("],\"transient\":[");
    written = 0;
    i = 0;
    while (i < total) : (i += 1) {
        if (!diffs[i].transient) continue;
        if (written != 0) try writer.writeAll(",");
        try write_slot_diff(writer, diffs[i]);
        written += 1;
    }
    try writer.writeAll("]}");
}

fn write_slot_diff(writer: *std.Io.Writer, diff: world_mod.World.SlotDiff) !void {
    try writer.writeAll("{\"address\":");
    try write_addr(writer, diff.address);
    try writer.writeAll(",\"slot\":");
    try write_word(writer, diff.key);
    try writer.writeAll(",\"before\":");
    try write_word(writer, diff.before);
    try writer.writeAll(",\"after\":");
    try write_word(writer, diff.after);
    try writer.writeAll(",\"op\":\"");
    try writer.writeAll(if (diff.transient) "TSTORE" else "SSTORE");
    try writer.writeAll("\"}");
}

fn write_pc(writer: *std.Io.Writer, session: *const Session, params: Params) !void {
    if (!params.has_pc) return write_err(writer, "pc requires pc=");
    try write_matches(writer, session, params, .pc);
}

fn write_opcode(writer: *std.Io.Writer, session: *const Session, params: Params) !void {
    if (params.opcode.len == 0) return write_err(writer, "opcode requires opcode=");
    try write_matches(writer, session, params, .opcode);
}

fn write_trace(writer: *std.Io.Writer, session: *const Session, params: Params) !void {
    try write_matches(writer, session, params, .all);
}

const MatchKind = enum { pc, opcode, all };

fn write_matches(
    writer: *std.Io.Writer,
    session: *const Session,
    params: Params,
    kind: MatchKind,
) !void {
    const tr = session.trace;
    const count = query_count(params);
    var total: u32 = 0;
    var shown: u32 = 0;
    var skipped: u32 = 0;
    try writer.writeAll("{\"steps\":[");
    var i: u32 = 0;
    while (i < tr.step_count) : (i += 1) {
        const step = tr.steps[i];
        if (!step_matches(step, params, kind)) continue;
        total += 1;
        if (skipped < params.start) {
            skipped += 1;
            continue;
        }
        if (shown >= count) continue;
        if (shown != 0) try writer.writeAll(",");
        try write_step_brief(writer, i + 1, step);
        shown += 1;
    }
    try writer.writeAll("],\"total\":");
    try write_u32(writer, total);
    try writer.writeAll(",\"has_more\":");
    try write_bool(writer, params.start + shown < total);
    try writer.writeAll("}");
}

fn step_matches(step: trace_mod.Step, params: Params, kind: MatchKind) bool {
    if (params.has_call and step.call_index != params.call) return false;
    return switch (kind) {
        .all => true,
        .pc => step.pc == params.pc,
        .opcode => opcode_matches(step.opcode, params.opcode),
    };
}

fn write_state_query(writer: *std.Io.Writer, session: *const Session, params: Params) !void {
    const step = params.step;
    if (!step_in_range(session.trace, step)) return write_range_err(writer, session.trace.step_count);
    var replay = try session.replay(step);
    defer replay.deinit();
    try write_state(writer, session, replay.vm, step);
}

fn write_step_query(writer: *std.Io.Writer, session: *const Session, params: Params) !void {
    const global = resolve_call_step(session.trace, params) orelse {
        return write_err(writer, "call/step_idx out of range");
    };
    var replay = try session.replay(global);
    defer replay.deinit();
    try write_state(writer, session, replay.vm, global);
}

fn write_explain_query(writer: *std.Io.Writer, session: *const Session, params: Params) !void {
    const step = if (params.step == 0) @as(u32, 1) else params.step;
    if (!step_in_range(session.trace, step)) return write_range_err(writer, session.trace.step_count);
    var replay = try session.replay(step);
    defer replay.deinit();
    try write_explain(writer, session, replay.vm, step);
}

fn write_diff_query(writer: *std.Io.Writer, session: *const Session, params: Params) !void {
    if (params.step_a == 0 or params.step_b == 0) return write_err(writer, "diff requires step_a= and step_b=");
    if (!step_in_range(session.trace, params.step_a) or !step_in_range(session.trace, params.step_b)) {
        return write_range_err(writer, session.trace.step_count);
    }
    var replay_a = try session.replay(params.step_a);
    defer replay_a.deinit();
    var replay_b = try session.replay(params.step_b);
    defer replay_b.deinit();
    try write_diff(writer, replay_a.vm, replay_b.vm, params);
}

fn step_in_range(tr: *const trace_mod.Trace, step: u32) bool {
    if (step == 0) return false;
    if (step <= tr.step_count) return true;
    return tr.truncated;
}

fn resolve_call_step(tr: *const trace_mod.Trace, params: Params) ?u32 {
    if (!params.has_call) return null;
    if (params.call >= tr.call_count) return null;
    const call = tr.calls[params.call];
    const ended = tr.ended(call);
    if (call.step_start == 0 or ended < call.step_start) return null;
    const global = call.step_start + params.step_idx;
    if (global < call.step_start or global > ended) return null;
    return global;
}

fn write_state(
    writer: *std.Io.Writer,
    session: *const Session,
    vm: *interpreter.Vm,
    global_step: u32,
) !void {
    const frame = vm.current();
    const rec = step_record(session.trace, global_step);
    try writer.writeAll("{\"global_step\":");
    try write_u32(writer, global_step);
    try writer.writeAll(",\"call_index\":");
    try write_u32(writer, rec.call_index);
    try writer.writeAll(",\"step\":{");
    try writer.writeAll("\"pc\":");
    try write_u32(writer, frame.pc);
    try writer.writeAll(",\"opcode\":\"");
    try writer.writeAll(opcode_mod.Opcode.mnemonic(rec.opcode));
    try writer.writeAll("\",\"opcode_byte\":");
    try write_u32(writer, @as(u32, rec.opcode));
    try writer.writeAll(",\"gas_remaining\":");
    try write_u64(writer, frame.gas.remaining());
    try writer.writeAll(",\"gas_used\":");
    try write_u64(writer, frame.gas.used);
    try writer.writeAll(",\"status\":\"");
    try writer.writeAll(@tagName(frame.status));
    try writer.writeAll("\"},\"call\":{");
    try writer.writeAll("\"address\":");
    try write_addr(writer, frame.context.address);
    try writer.writeAll(",\"code_address\":");
    try write_addr(writer, frame.code_address);
    try writer.writeAll(",\"caller\":");
    try write_addr(writer, frame.context.caller);
    try writer.writeAll(",\"value\":");
    try write_word(writer, frame.context.call_value);
    try writer.writeAll(",\"kind\":\"");
    try writer.writeAll(if (frame.kind == .create) "create" else "call");
    try writer.writeAll("\",\"depth\":");
    try write_u32(writer, frame.depth);
    try writer.writeAll(",\"is_static\":");
    try write_bool(writer, frame.is_static);
    try writer.writeAll("},\"stack\":");
    try write_stack(writer, &frame.stack);
    try writer.writeAll(",\"memory\":");
    try write_memory(writer, &frame.memory);
    try writer.writeAll(",\"storage\":");
    try write_storage(writer, &vm.world, false);
    try writer.writeAll(",\"transient\":");
    try write_storage(writer, &vm.world, true);
    try writer.writeAll(",\"call_path\":");
    try write_call_path(writer, session.trace, rec.call_index);
    try writer.writeAll("}");
}

fn write_explain(
    writer: *std.Io.Writer,
    session: *const Session,
    vm: *interpreter.Vm,
    global_step: u32,
) !void {
    const frame = vm.current();
    const rec = step_record(session.trace, global_step);
    const info = explain_info(rec.opcode);
    try writer.writeAll("{\"global_step\":");
    try write_u32(writer, global_step);
    try writer.writeAll(",\"pc\":");
    try write_u32(writer, rec.pc);
    try writer.writeAll(",\"opcode\":\"");
    try writer.writeAll(opcode_mod.Opcode.mnemonic(rec.opcode));
    try writer.writeAll("\",\"category\":\"");
    try writer.writeAll(info.category);
    try writer.writeAll("\",\"description\":\"");
    try writer.writeAll(info.summary);
    try writer.writeAll("\",\"stack_inputs\":[");
    var i: u32 = 0;
    while (i < info.pop_count) : (i += 1) {
        if (i != 0) try writer.writeAll(",");
        try writer.writeAll("{\"name\":\"");
        try writer.writeAll(info.pops[i]);
        try writer.writeAll("\",\"value\":");
        if (i < frame.stack.depth) {
            try write_word(writer, try frame.stack.peek(i));
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll("}");
    }
    try writer.writeAll("],\"call_path\":");
    try write_call_path(writer, session.trace, rec.call_index);
    try writer.writeAll("}");
}

fn write_diff(
    writer: *std.Io.Writer,
    vm_a: *interpreter.Vm,
    vm_b: *interpreter.Vm,
    params: Params,
) !void {
    const a = vm_a.current();
    const b = vm_b.current();
    try writer.writeAll("{\"step_a\":");
    try write_u32(writer, params.step_a);
    try writer.writeAll(",\"step_b\":");
    try write_u32(writer, params.step_b);
    try writer.writeAll(",\"stack_depth_a\":");
    try write_u32(writer, a.stack.depth);
    try writer.writeAll(",\"stack_depth_b\":");
    try write_u32(writer, b.stack.depth);
    try writer.writeAll(",\"memory_bytes_a\":");
    try write_u32(writer, a.memory.active_bytes);
    try writer.writeAll(",\"memory_bytes_b\":");
    try write_u32(writer, b.memory.active_bytes);
    try writer.writeAll(",\"stack_changed\":[");
    try write_stack_delta(writer, &a.stack, &b.stack);
    try writer.writeAll("],\"memory_changed\":[");
    try write_memory_changed(writer, &a.memory, &b.memory);
    try writer.writeAll("],\"storage_changed\":[");
    try write_storage_changed(writer, &vm_a.world, &vm_b.world);
    try writer.writeAll("]}");
}

fn step_record(tr: *const trace_mod.Trace, global_step: u32) trace_mod.Step {
    std.debug.assert(global_step > 0);
    if (global_step <= tr.step_count) return tr.steps[global_step - 1];
    return tr.steps[tr.step_count - 1];
}

fn write_stack(writer: *std.Io.Writer, stack: *const stack_mod.Stack) !void {
    const depth = stack.depth;
    const n = @min(depth, limits.debug_stack_dump_max);
    try writer.writeAll("{\"depth\":");
    try write_u32(writer, depth);
    try writer.writeAll(",\"has_more\":");
    try write_bool(writer, n < depth);
    try writer.writeAll(",\"top_first\":[");
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        if (i != 0) try writer.writeAll(",");
        try write_word(writer, try stack.peek(i));
    }
    try writer.writeAll("]}");
}

fn write_memory(writer: *std.Io.Writer, memory: *const memory_mod.Memory) !void {
    const size = memory.active_bytes;
    const n = @min(size, limits.debug_memory_hex_max);
    try writer.writeAll("{\"size\":");
    try write_u32(writer, size);
    try writer.writeAll(",\"has_more\":");
    try write_bool(writer, n < size);
    try writer.writeAll(",\"hex\":\"0x");
    try write_hex(writer, memory.bytes[0..n]);
    try writer.writeAll("\"}");
}

fn write_storage(writer: *std.Io.Writer, world: *const world_mod.World, transient: bool) !void {
    const slots = if (transient) world.transient[0..world.transient_count] else world.slots[0..world.slot_count];
    const n = @min(@as(u32, @intCast(slots.len)), limits.debug_query_cap);
    try writer.writeAll("[");
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        if (i != 0) try writer.writeAll(",");
        try writer.writeAll("{\"address\":");
        try write_addr(writer, slots[i].address);
        try writer.writeAll(",\"slot\":");
        try write_word(writer, slots[i].key);
        try writer.writeAll(",\"value\":");
        try write_word(writer, slots[i].value);
        try writer.writeAll("}");
    }
    try writer.writeAll("]");
}

fn write_call_path(writer: *std.Io.Writer, tr: *const trace_mod.Trace, call_index: u32) !void {
    var chain: [limits.call_frames_max]u32 = undefined;
    var len: u32 = 0;
    var current = call_index;
    while (len < limits.call_frames_max) {
        if (current >= tr.call_count) break;
        chain[len] = current;
        len += 1;
        const parent = tr.calls[current].parent;
        if (parent == trace_mod.no_parent) break;
        current = parent;
    }
    try writer.writeAll("[");
    var i: u32 = len;
    var first = true;
    while (i > 0) {
        i -= 1;
        if (!first) try writer.writeAll(",");
        first = false;
        const idx = chain[i];
        const call = tr.calls[idx];
        try writer.writeAll("{\"call_index\":");
        try write_u32(writer, idx);
        try writer.writeAll(",\"address\":");
        try write_addr(writer, call.address);
        try writer.writeAll(",\"kind\":\"");
        try writer.writeAll(if (call.is_create) "create" else "call");
        try writer.writeAll("\",\"global_step_start\":");
        try write_u32(writer, call.step_start);
        try writer.writeAll(",\"global_step_end\":");
        try write_u32(writer, tr.ended(call));
        try writer.writeAll("}");
    }
    try writer.writeAll("]");
}

fn write_stack_delta(
    writer: *std.Io.Writer,
    a: *const stack_mod.Stack,
    b: *const stack_mod.Stack,
) !void {
    const n = @min(@max(a.depth, b.depth), limits.debug_query_cap);
    var written: u32 = 0;
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        const va: ?u256 = if (i < a.depth) try a.peek(i) else null;
        const vb: ?u256 = if (i < b.depth) try b.peek(i) else null;
        const same = if (va) |x| if (vb) |y| x == y else false else false;
        if (same) continue;
        if (written != 0) try writer.writeAll(",");
        try writer.writeAll("{\"index\":");
        try write_u32(writer, i);
        try writer.writeAll(",\"old\":");
        if (va) |v| try write_word(writer, v) else try writer.writeAll("null");
        try writer.writeAll(",\"new\":");
        if (vb) |v| try write_word(writer, v) else try writer.writeAll("null");
        try writer.writeAll("}");
        written += 1;
    }
}

fn write_memory_changed(
    writer: *std.Io.Writer,
    a: *const memory_mod.Memory,
    b: *const memory_mod.Memory,
) !void {
    const max_size = @max(a.active_bytes, b.active_bytes);
    var offset: u32 = 0;
    var written: u32 = 0;
    while (offset < max_size and written < limits.debug_query_cap) : (offset += 32) {
        const wa = memory_word(a, offset);
        const wb = memory_word(b, offset);
        if (wa == wb) continue;
        if (written != 0) try writer.writeAll(",");
        try writer.writeAll("{\"offset\":");
        try write_u32(writer, offset);
        try writer.writeAll(",\"old\":");
        try write_word(writer, wa);
        try writer.writeAll(",\"new\":");
        try write_word(writer, wb);
        try writer.writeAll("}");
        written += 1;
    }
}

fn memory_word(memory: *const memory_mod.Memory, offset: u32) u256 {
    if (offset >= memory.active_bytes) return 0;
    var bytes: [32]u8 = @splat(0);
    const avail = @min(@as(u32, 32), memory.active_bytes - offset);
    @memcpy(bytes[0..avail], memory.bytes[offset .. offset + avail]);
    return word.from_bytes_be(&bytes);
}

fn write_storage_changed(writer: *std.Io.Writer, a: *const world_mod.World, b: *const world_mod.World) !void {
    var diffs_b: [256]world_mod.World.SlotDiff = undefined;
    const nb = b.collect_slot_diffs(&diffs_b);
    var written: u32 = 0;
    var i: u32 = 0;
    while (i < nb and written < limits.debug_query_cap) : (i += 1) {
        const now = diffs_b[i];
        if (now.transient) continue;
        const old = a.load(now.address, now.key);
        if (old == now.after) continue;
        if (written != 0) try writer.writeAll(",");
        try writer.writeAll("{\"address\":");
        try write_addr(writer, now.address);
        try writer.writeAll(",\"slot\":");
        try write_word(writer, now.key);
        try writer.writeAll(",\"old\":");
        try write_word(writer, old);
        try writer.writeAll(",\"new\":");
        try write_word(writer, now.after);
        try writer.writeAll("}");
        written += 1;
    }
}

const Explain = struct {
    category: []const u8,
    summary: []const u8,
    pops: [7][]const u8,
    pop_count: u32,
};

fn explain_info(byte: u8) Explain {
    const op = opcode_mod.Opcode.from_byte(byte);
    if (opcode_mod.Opcode.is_push(op)) return make_explain("stack", "Push immediate onto the stack", &.{});
    if (opcode_mod.Opcode.is_dup(op)) return make_explain("stack", "Duplicate a stack item", &.{});
    if (opcode_mod.Opcode.is_swap(op)) return make_explain("stack", "Swap stack items", &.{});
    return switch (byte) {
        0x00 => make_explain("halt", "Halt execution", &.{}),
        0x01 => make_explain("arithmetic", "Add a and b", &.{ "a", "b" }),
        0x02 => make_explain("arithmetic", "Multiply a and b", &.{ "a", "b" }),
        0x03 => make_explain("arithmetic", "Subtract b from a", &.{ "a", "b" }),
        0x04 => make_explain("arithmetic", "Divide a by b", &.{ "a", "b" }),
        0x05 => make_explain("arithmetic", "Signed divide a by b", &.{ "a", "b" }),
        0x06 => make_explain("arithmetic", "Modulo a by b", &.{ "a", "b" }),
        0x10 => make_explain("comparison", "Unsigned less-than", &.{ "a", "b" }),
        0x11 => make_explain("comparison", "Unsigned greater-than", &.{ "a", "b" }),
        0x14 => make_explain("comparison", "Equality", &.{ "a", "b" }),
        0x15 => make_explain("comparison", "True if a is zero", &.{"a"}),
        0x16 => make_explain("bitwise", "Bitwise AND", &.{ "a", "b" }),
        0x17 => make_explain("bitwise", "Bitwise OR", &.{ "a", "b" }),
        0x18 => make_explain("bitwise", "Bitwise XOR", &.{ "a", "b" }),
        0x19 => make_explain("bitwise", "Bitwise NOT", &.{"a"}),
        0x1e => make_explain("bitwise", "Count leading zeros", &.{"a"}),
        0x20 => make_explain("keccak", "Keccak-256 hash of memory", &.{ "offset", "size" }),
        0x50 => make_explain("stack", "Pop the top stack item", &.{"a"}),
        0x51 => make_explain("memory", "Load a word from memory", &.{"offset"}),
        0x52 => make_explain("memory", "Store a word to memory", &.{ "offset", "value" }),
        0x54 => make_explain("storage", "Load from persistent storage", &.{"slot"}),
        0x55 => make_explain("storage", "Store to persistent storage", &.{ "slot", "value" }),
        0x56 => make_explain("control", "Jump to dest if it is a JUMPDEST", &.{"dest"}),
        0x57 => make_explain("control", "Jump to dest when cond is nonzero", &.{ "dest", "cond" }),
        0x5c => make_explain("storage", "Load from transient storage", &.{"slot"}),
        0x5d => make_explain("storage", "Store to transient storage", &.{ "slot", "value" }),
        0xf0 => make_explain("call", "Create a contract", &.{ "value", "offset", "size" }),
        0xf1 => make_explain("call", "Message call", &.{ "gas", "address", "value", "in_offset", "in_size", "out_offset", "out_size" }),
        0xf3 => make_explain("halt", "Return output data", &.{ "offset", "size" }),
        0xf4 => make_explain("call", "Delegate call", &.{ "gas", "address", "in_offset", "in_size", "out_offset", "out_size" }),
        0xf5 => make_explain("call", "Create a contract with salt", &.{ "value", "offset", "size", "salt" }),
        0xfa => make_explain("call", "Static call", &.{ "gas", "address", "in_offset", "in_size", "out_offset", "out_size" }),
        0xfd => make_explain("halt", "Revert with output data", &.{ "offset", "size" }),
        0xff => make_explain("halt", "Self-destruct", &.{"beneficiary"}),
        else => make_explain("other", "Execute opcode", &.{}),
    };
}

fn make_explain(category: []const u8, summary: []const u8, pops: []const []const u8) Explain {
    var info = Explain{
        .category = category,
        .summary = summary,
        .pops = .{ "", "", "", "", "", "", "" },
        .pop_count = @intCast(pops.len),
    };
    std.debug.assert(pops.len <= 7);
    var i: u32 = 0;
    while (i < pops.len) : (i += 1) info.pops[i] = pops[i];
    return info;
}

fn write_step_brief(writer: *std.Io.Writer, global_step: u32, step: trace_mod.Step) !void {
    try writer.writeAll("{\"global_step\":");
    try write_u32(writer, global_step);
    try writer.writeAll(",\"pc\":");
    try write_u32(writer, step.pc);
    try writer.writeAll(",\"opcode\":\"");
    try writer.writeAll(opcode_mod.Opcode.mnemonic(step.opcode));
    try writer.writeAll("\",\"gas_remaining\":");
    try write_u64(writer, step.gas_remaining);
    try writer.writeAll(",\"depth\":");
    try write_u32(writer, step.depth);
    try writer.writeAll(",\"stack_depth\":");
    try write_u32(writer, step.stack_depth);
    try writer.writeAll(",\"call_index\":");
    try write_u32(writer, step.call_index);
    try writer.writeAll("}");
}

fn opcode_matches(byte: u8, query: []const u8) bool {
    if (query.len == 0) return false;
    if (std.ascii.eqlIgnoreCase(opcode_mod.Opcode.mnemonic(byte), query)) return true;
    const parsed = parse_opcode_byte(query) orelse return false;
    return parsed == byte;
}

fn parse_opcode_byte(text: []const u8) ?u8 {
    var trimmed = text;
    if (trimmed.len >= 2 and trimmed[0] == '0' and (trimmed[1] == 'x' or trimmed[1] == 'X')) {
        trimmed = trimmed[2..];
        return std.fmt.parseInt(u8, trimmed, 16) catch null;
    }
    var i: usize = 0;
    while (i < trimmed.len) : (i += 1) {
        if (!std.ascii.isDigit(trimmed[i])) return null;
    }
    return std.fmt.parseInt(u8, trimmed, 10) catch null;
}

fn status_name(vm: *interpreter.Vm) []const u8 {
    if (vm.frame_count == 0) return "empty";
    return @tagName(vm.current().status);
}

fn slice_len(total: u32, start: u32, count: u32) u32 {
    if (start >= total) return 0;
    return @min(count, total - start);
}

fn parse_u32(text: []const u8) !u32 {
    if (text.len >= 2 and text[0] == '0' and (text[1] == 'x' or text[1] == 'X')) {
        return std.fmt.parseInt(u32, text[2..], 16);
    }
    return std.fmt.parseInt(u32, text, 10);
}

fn write_err(writer: *std.Io.Writer, msg: []const u8) !void {
    try writer.writeAll("{\"error\":\"");
    try writer.writeAll(msg);
    try writer.writeAll("\"}");
}

fn write_range_err(writer: *std.Io.Writer, total: u32) !void {
    try writer.writeAll("{\"error\":\"step out of range\",\"total_steps\":");
    try write_u32(writer, total);
    try writer.writeAll("}");
}

fn write_opt_str(writer: *std.Io.Writer, text: ?[]const u8) !void {
    if (text) |s| {
        try writer.writeAll("\"");
        try writer.writeAll(s);
        try writer.writeAll("\"");
    } else {
        try writer.writeAll("null");
    }
}

fn write_bool(writer: *std.Io.Writer, value: bool) !void {
    try writer.writeAll(if (value) "true" else "false");
}

fn write_u32(writer: *std.Io.Writer, value: u32) !void {
    try writer.print("{d}", .{value});
}

fn write_u64(writer: *std.Io.Writer, value: u64) !void {
    try writer.print("{d}", .{value});
}

fn write_word(writer: *std.Io.Writer, value: u256) !void {
    try writer.print("\"0x{x}\"", .{value});
}

fn write_addr(writer: *std.Io.Writer, value: u256) !void {
    var bytes: [32]u8 = undefined;
    word.to_bytes_be(value, &bytes);
    try writer.writeAll("\"0x");
    try write_hex(writer, bytes[12..]);
    try writer.writeAll("\"");
}

fn write_hex(writer: *std.Io.Writer, bytes: []const u8) !void {
    const digits = "0123456789abcdef";
    for (bytes) |byte| {
        try writer.writeByte(digits[byte >> 4]);
        try writer.writeByte(digits[byte & 0xf]);
    }
}

test "debug ADD is pre-opcode at step 3" {
    const code = [_]u8{ 0x60, 0x02, 0x60, 0x03, 0x01, 0x00 };
    const allocator = std.testing.allocator;
    var session = try Session.init_bytecode(allocator, &code, &.{}, 1_000_000, .osaka);
    defer session.deinit();
    try std.testing.expectEqual(@as(u32, 4), session.trace.step_count);
    try std.testing.expectEqual(@as(u8, 0x01), session.trace.steps[2].opcode);
    var replay = try session.replay(3);
    defer replay.deinit();
    const stack = &replay.vm.current().stack;
    try std.testing.expectEqual(@as(u32, 2), stack.depth);
    try std.testing.expectEqual(@as(u256, 3), try stack.peek(0));
    try std.testing.expectEqual(@as(u256, 2), try stack.peek(1));
}

test "debug overview and opcode json" {
    const code = [_]u8{ 0x60, 0x02, 0x60, 0x03, 0x01, 0x00 };
    var buf: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try run_query(std.testing.allocator, &code, &.{}, 1_000_000, .osaka, "opcode", .{ .opcode = "ADD" }, &writer);
    const out = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "\"opcode\":\"ADD\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"global_step\":3") != null);
}

test "debug sstore storage-diff" {
    const code = [_]u8{ 0x60, 0x01, 0x60, 0x00, 0x55, 0x00 };
    var buf: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try run_query(std.testing.allocator, &code, &.{}, 1_000_000, .osaka, "storage-diff", .{}, &writer);
    const out = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "\"op\":\"SSTORE\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"after\":\"0x1\"") != null);
}

test "debug forge traces setUp then the test call" {
    const allocator = std.testing.allocator;
    const runtime = [_]u8{ 0x60, 0x02, 0x60, 0x03, 0x01, 0x00 };
    var buf: [32]u8 = undefined;
    const init_code = forge_test.wrap_runtime(&runtime, &buf);
    const bytecode = try allocator.dupe(u8, init_code);
    const name = try allocator.dupe(u8, "testAdd");
    const cases = try allocator.alloc(forge_test.Case, 1);
    cases[0] = .{
        .name = name,
        .selector = forge_test.selector_of("testAdd()"),
        .kind = .unit,
    };
    const contract = try allocator.dupe(u8, "Add.t.sol");
    var matched = forge_test.MatchedTest{
        .suite = .{
            .bytecode = bytecode,
            .setup = forge_test.selector_of("setUp()"),
            .failed = null,
            .cases = cases,
        },
        .case_index = 0,
        .contract = contract,
        .allocator = allocator,
    };
    defer matched.deinit();
    var session = try Session.init_forge(allocator, &matched, .osaka, null);
    defer session.deinit();
    try std.testing.expectEqual(@as(u32, 2), session.trace.call_count);
    try std.testing.expectEqual(@as(u32, 8), session.trace.step_count);
    try std.testing.expectEqual(@as(u8, 0x01), session.trace.steps[2].opcode);
    try std.testing.expectEqual(@as(u32, 0), session.trace.steps[2].call_index);
    try std.testing.expectEqual(@as(u8, 0x01), session.trace.steps[6].opcode);
    try std.testing.expectEqual(@as(u32, 1), session.trace.steps[6].call_index);
    var replay = try session.replay(7);
    defer replay.deinit();
    try std.testing.expectEqual(@as(u256, 3), try replay.vm.current().stack.peek(0));
    try std.testing.expectEqual(@as(u256, 2), try replay.vm.current().stack.peek(1));
}
