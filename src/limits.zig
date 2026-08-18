//! Explicit bounds for every EVM resource. Tiger Style: put a limit on everything.

const std = @import("std");

/// Yellow Paper / EELS `STACK_DEPTH_LIMIT`. A child is rejected when
/// `message.depth + 1 > call_depth_limit`. Depths `0..=1024` are valid, so
/// the frame array is `call_depth_limit + 1`.
pub const call_depth_limit: u32 = 1024;
pub const call_frames_max: u32 = call_depth_limit + 1;

pub const stack_depth_max: u32 = 1024;
pub const memory_bytes_max: u32 = 1_048_576;
/// Shared bump pool for every frame's memory and calldata copies.
pub const memory_pool_bytes_max: u32 = 64 * 1024 * 1024;
pub const code_bytes_max: u32 = 24 * 1024;
pub const init_code_bytes_max: u32 = 2 * code_bytes_max;
pub const code_pool_bytes_max: u32 = 2 * 1024 * 1024;
pub const calldata_bytes_max: u32 = 128 * 1024;
pub const returndata_bytes_max: u32 = 32 * 1024;
pub const log_topics_max: u32 = 4;
pub const log_data_bytes_max: u32 = 32 * 1024;
pub const logs_max: u32 = 1024;
pub const log_data_pool_bytes_max: u32 = 256 * 1024;
/// Sized for EIP-7702 `test_many_delegations` (thousands of new authorities).
pub const accounts_max: u32 = 8_192;
pub const storage_slots_max: u32 = 4096;
pub const journal_entries_max: u32 = 65_536;
pub const accessed_addresses_max: u32 = 8_192;
pub const accessed_storage_max: u32 = 4096;
/// EIP-7702 authorization tuples on one type-4 transaction.
pub const authorizations_max: u32 = 8_192;
pub const jumpdest_table_max: u32 = 8192;
pub const trace_steps_max: u32 = 10_000_000;
pub const forge_artifact_bytes_max: u32 = 32 * 1024 * 1024;
pub const jsontest_bytes_max: u32 = 64 * 1024 * 1024;
pub const forge_sig_bytes_max: u32 = 256;
pub const cheat_mocks_max: u32 = 32;
pub const cheat_mock_data_bytes_max: u32 = 16 * 1024;
pub const cheat_snapshots_max: u32 = 16;
pub const cheat_expect_bytes_max: u32 = 1024;

comptime {
    std.debug.assert(call_depth_limit == 1024);
    std.debug.assert(call_frames_max == 1025);
    std.debug.assert(stack_depth_max > 0);
    std.debug.assert(stack_depth_max <= 1024);
    std.debug.assert(memory_bytes_max % 32 == 0);
    std.debug.assert(memory_pool_bytes_max >= memory_bytes_max);
    std.debug.assert(code_bytes_max > 0);
    std.debug.assert(init_code_bytes_max == 49_152);
    std.debug.assert(accounts_max > 0);
    std.debug.assert(authorizations_max <= accounts_max);
    std.debug.assert(authorizations_max <= accessed_addresses_max);
    std.debug.assert(logs_max > 0);
    std.debug.assert(log_data_pool_bytes_max > 0);
    std.debug.assert(jsontest_bytes_max > 0);
    std.debug.assert(authorizations_max > 0);
}
