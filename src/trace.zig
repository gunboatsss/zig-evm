//! Compact execution trace for the LLM debugger. No stack or memory snapshots.
//! Full state is recovered by replaying with `stop_at`.

const std = @import("std");
const limits = @import("limits.zig");

pub const no_parent: u32 = std.math.maxInt(u32);

pub const Step = struct {
    pc: u32,
    opcode: u8,
    gas_remaining: u64,
    depth: u32,
    stack_depth: u32,
    call_index: u32,
};

pub const CallSeg = struct {
    parent: u32,
    depth: u32,
    address: u256,
    code_address: u256,
    is_create: bool,
    step_start: u32,
    step_end: u32,
    gas_limit: u64,
};

pub const Trace = struct {
    steps: [limits.debug_trace_steps_max]Step,
    step_count: u32,
    calls: [limits.debug_call_segments_max]CallSeg,
    call_count: u32,
    frame_call: [limits.call_frames_max]u32,
    stop_at: u32,
    paused: bool,
    truncated: bool,

    pub fn reset(self: *Trace) void {
        self.step_count = 0;
        self.call_count = 0;
        self.stop_at = 0;
        self.paused = false;
        self.truncated = false;
    }

    pub fn call_of_frame(self: *const Trace, frame_index: u32) u32 {
        std.debug.assert(frame_index < limits.call_frames_max);
        if (self.call_count == 0) return 0;
        return self.frame_call[frame_index];
    }

    pub fn open_root(
        self: *Trace,
        address: u256,
        code_address: u256,
        is_create: bool,
        gas_limit: u64,
    ) void {
        self.open_call(0, no_parent, 0, address, code_address, is_create, gas_limit);
    }

    pub fn open_call(
        self: *Trace,
        frame_index: u32,
        parent: u32,
        depth: u32,
        address: u256,
        code_address: u256,
        is_create: bool,
        gas_limit: u64,
    ) void {
        std.debug.assert(frame_index < limits.call_frames_max);
        if (self.call_count >= limits.debug_call_segments_max) {
            self.truncated = true;
            return;
        }
        const index = self.call_count;
        self.calls[index] = .{
            .parent = parent,
            .depth = depth,
            .address = address,
            .code_address = code_address,
            .is_create = is_create,
            .step_start = self.step_count + 1,
            .step_end = 0,
            .gas_limit = gas_limit,
        };
        self.frame_call[frame_index] = index;
        self.call_count += 1;
        std.debug.assert(self.call_count <= limits.debug_call_segments_max);
    }

    pub fn close_call(self: *Trace, frame_index: u32) void {
        std.debug.assert(frame_index < limits.call_frames_max);
        if (self.call_count == 0) return;
        const index = self.frame_call[frame_index];
        if (index >= self.call_count) return;
        self.calls[index].step_end = self.step_count;
    }

    pub fn record_step(self: *Trace, step: Step) void {
        if (self.step_count >= limits.debug_trace_steps_max) {
            self.truncated = true;
            return;
        }
        self.steps[self.step_count] = step;
        self.step_count += 1;
        std.debug.assert(self.step_count <= limits.debug_trace_steps_max);
    }

    pub fn ended(self: *const Trace, call: CallSeg) u32 {
        if (call.step_end != 0) return call.step_end;
        return self.step_count;
    }
};

test "trace records until cap" {
    const tr = try std.testing.allocator.create(Trace);
    defer std.testing.allocator.destroy(tr);
    tr.reset();
    tr.record_step(.{
        .pc = 0,
        .opcode = 0x00,
        .gas_remaining = 1,
        .depth = 0,
        .stack_depth = 0,
        .call_index = 0,
    });
    try std.testing.expectEqual(@as(u32, 1), tr.step_count);
}
