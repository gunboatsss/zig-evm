//! Explicit bounds for every EVM resource. Tiger Style: put a limit on everything.

const std = @import("std");

/// Yellow Paper / EELS `STACK_DEPTH_LIMIT`. A child is rejected when
/// `message.depth + 1 > call_depth_limit`. Depths `0..=1024` are valid, so
/// the frame array is `call_depth_limit + 1`.
pub const call_depth_limit: u32 = 1024;
pub const call_frames_max: u32 = call_depth_limit + 1;

pub const stack_depth_max: u32 = 1024;
/// Per-frame cap. Expansion past this is `MemoryOverflow` (then OutOfGas).
pub const memory_bytes_max: u32 = 16 * 1024 * 1024;
/// Shared bump pool for every frame's memory and calldata copies.
pub const memory_pool_bytes_max: u32 = 128 * 1024 * 1024;
pub const code_bytes_max: u32 = 24 * 1024;
pub const init_code_bytes_max: u32 = 2 * code_bytes_max;
/// Foundry test contracts often exceed EIP-170 / EIP-3860.
pub const forge_code_bytes_max: u32 = 64 * 1024;
pub const forge_init_code_bytes_max: u32 = 64 * 1024;
pub const code_pool_bytes_max: u32 = 2 * 1024 * 1024;
pub const calldata_bytes_max: u32 = 128 * 1024;
/// EIP-7823: each MODEXP length field is at most 1024 bytes.
pub const modexp_len_bytes_max: u32 = 1024;
/// Scratch for `std.math.big` during MODEXP (base/exp/mod + mul/div).
pub const modexp_scratch_bytes_max: u32 = 64 * 1024;
/// EIP-7951 `P256VERIFY` input is exactly 160 bytes.
pub const p256verify_input_bytes: u32 = 160;
pub const returndata_bytes_max: u32 = 64 * 1024;
pub const log_topics_max: u32 = 4;
pub const log_data_bytes_max: u32 = 32 * 1024;
pub const logs_max: u32 = 1024;
pub const log_data_pool_bytes_max: u32 = 256 * 1024;
/// Sized for EIP-7702 `test_many_delegations` (thousands of new authorities).
pub const accounts_max: u32 = 8_192;
pub const storage_slots_max: u32 = 4096;
pub const journal_entries_max: u32 = 65_536;
pub const accessed_addresses_max: u32 = 8_192;
/// EIP-7825 tx gas cap is 2^24; access-list keys cost 1900, so a padded list
/// can hold ~8817 unique keys. Warm-slot tracking must fit that list.
pub const accessed_storage_max: u32 = 16_384;
/// EIP-7702 authorization tuples on one type-4 transaction.
pub const authorizations_max: u32 = 8_192;
pub const jumpdest_table_max: u32 = 8192;
pub const trace_steps_max: u32 = 10_000_000;
/// Compact debugger steps (not a full stack/memory snapshot per step).
pub const debug_trace_steps_max: u32 = 65_536;
pub const debug_call_segments_max: u32 = 8_192;
pub const debug_query_cap: u32 = 25;
pub const debug_stack_dump_max: u32 = 64;
pub const debug_memory_hex_max: u32 = 512;
pub const forge_artifact_bytes_max: u32 = 32 * 1024 * 1024;
pub const forge_artifacts_max: u32 = 512;
pub const forge_name_pool_bytes_max: u32 = 256 * 1024;
pub const forge_code_pool_bytes_max: u32 = 16 * 1024 * 1024;
pub const jsontest_bytes_max: u32 = 64 * 1024 * 1024;
pub const forge_sig_bytes_max: u32 = 256;
pub const cheat_mocks_max: u32 = 32;
pub const cheat_mock_data_bytes_max: u32 = 16 * 1024;
pub const cheat_snapshots_max: u32 = 16;
pub const cheat_expect_bytes_max: u32 = 1024;
/// Yellow Paper BLOCKHASH window.
pub const block_hashes_max: u32 = 256;
pub const header_extra_bytes_max: u32 = 512;
pub const header_rlp_bytes_max: u32 = 2048;
pub const trie_nibble_max: u32 = 64;
pub const trie_leaves_max: u32 = accounts_max + storage_slots_max;
pub const trie_nodes_max: u32 = trie_leaves_max * 4;
pub const trie_value_bytes_max: u32 = accounts_max * 160 + storage_slots_max * 48;
pub const trie_account_bytes_max: u32 = 160;
pub const trie_node_bytes_max: u32 = 1024;
pub const trie_empty_child: u32 = 0;

comptime {
    std.debug.assert(call_depth_limit == 1024);
    std.debug.assert(call_frames_max == 1025);
    std.debug.assert(stack_depth_max > 0);
    std.debug.assert(stack_depth_max <= 1024);
    std.debug.assert(memory_bytes_max % 32 == 0);
    std.debug.assert(memory_pool_bytes_max >= memory_bytes_max);
    std.debug.assert(code_bytes_max > 0);
    std.debug.assert(init_code_bytes_max == 49_152);
    std.debug.assert(forge_code_bytes_max >= code_bytes_max);
    std.debug.assert(forge_init_code_bytes_max >= init_code_bytes_max);
    std.debug.assert(accounts_max > 0);
    std.debug.assert(accessed_storage_max >= 8_817);
    std.debug.assert(authorizations_max <= accounts_max);
    std.debug.assert(authorizations_max <= accessed_addresses_max);
    std.debug.assert(logs_max > 0);
    std.debug.assert(log_data_pool_bytes_max > 0);
    std.debug.assert(jsontest_bytes_max > 0);
    std.debug.assert(modexp_len_bytes_max == 1024);
    std.debug.assert(modexp_scratch_bytes_max >= 16 * 1024);
    std.debug.assert(p256verify_input_bytes == 160);
    std.debug.assert(authorizations_max > 0);
    std.debug.assert(debug_trace_steps_max > 0);
    std.debug.assert(debug_trace_steps_max <= trace_steps_max);
    std.debug.assert(debug_call_segments_max > 0);
    std.debug.assert(debug_query_cap > 0);
    std.debug.assert(debug_stack_dump_max > 0);
    std.debug.assert(debug_memory_hex_max > 0);
    std.debug.assert(debug_memory_hex_max % 32 == 0);
    std.debug.assert(forge_artifacts_max > 0);
    std.debug.assert(forge_name_pool_bytes_max > 0);
    std.debug.assert(forge_code_pool_bytes_max > 0);
    std.debug.assert(block_hashes_max == 256);
    std.debug.assert(header_extra_bytes_max > 0);
    std.debug.assert(header_rlp_bytes_max >= 512 + header_extra_bytes_max);
    std.debug.assert(trie_nibble_max == 64);
    std.debug.assert(trie_leaves_max >= accounts_max);
    std.debug.assert(trie_nodes_max >= trie_leaves_max);
    std.debug.assert(trie_empty_child == 0);
}
