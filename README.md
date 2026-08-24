# zig-evm

A statically allocated Ethereum Virtual Machine (EVM) written in [Zig](https://ziglang.org/), following [Tiger Style](docs/TIGER_STYLE.md) — the safety-first coding methodology from [TigerBeetle](https://tigerbeetle.com/).

Design goals, in order:

1. **Safety** — assertions everywhere, explicit limits, no heap allocation after init
2. **Performance** — hot interpreter loop, batch-friendly memory layout
3. **Developer experience** — small modules, snake_case, readable control flow

## Quick start

```bash
zig build
zig build test
./zig-out/bin/zig-evm test-bytecode
./zig-out/bin/zig-evm run 0x60016002016003019060045500
```

## Execution spec tests

Filled [ethereum/execution-spec-tests](https://github.com/ethereum/execution-spec-tests) fixtures (v5.4.0, Osaka develop set):

```bash
scripts/fetch_eest_fixtures.sh                 # every state_test, including EIP-6780
scripts/fetch_eest_fixtures.sh --smoke         # PUSH0, TSTORE, MCOPY, CLZ, 7702, 6780
scripts/fetch_eest_fixtures.sh --blockchain    # blockchain_tests (valid Osaka blocks)
zig build jsontest                             # or: zig-evm jsontest tests/eest/state_tests
zig build chaintest                            # or: zig-evm chaintest tests/eest/blockchain_tests
```

Fixtures live in `tests/eest/` (gitignored). `post.state` is compared account-by-account, including sender and coinbase balances. A 32-byte `post.hash` is compared to a check-time Merkle Patricia state root. EIP-6780 is the Osaka `SELFDESTRUCT` rule (same-tx only); Shanghai and earlier posts for those tests are skipped. `zig build jsontest -Djsontest-path=path` runs a single file or directory. `chaintest` applies each valid block (`apply_block`), checks `gasUsed` / `stateRoot`, hashes the header, and pushes it onto the 256-block `BLOCKHASH` window. Invalid blocks, uncles, blobs, and withdrawals are skipped until those paths exist.

## Architecture

```
src/
  limits.zig      # hard caps on every resource
  u256.zig        # EVM wrapping rules on native u256
  stack.zig       # 1024-word operand stack
  memory.zig      # linear byte memory with 32-byte expansion
  gas.zig         # gas metering
  state.zig       # storage + execution context
  opcode.zig      # Osaka + Amsterdam opcode table
  fork.zig        # osaka baseline, amsterdam additive
  world.zig       # accounts, storage, revert journal
  rlp.zig         # CREATE / CREATE2 addresses
  header.zig      # keccak256(rlp(header)) and the BLOCKHASH window
  trie.zig        # check-time Merkle Patricia state root
  interpreter.zig # iterative call stack, depth cap 1024, apply_block
  evm.zig         # public execute() API
  main.zig        # CLI
```

The interpreter is a loop over a bounded call stack. Nested calls never recurse in Zig — a child frame is pushed, the loop continues, and the parent resumes after `exit_child`.

## Supported opcodes

Opcode metadata follows [`ethereum/execution-specs`](https://github.com/ethereum/execution-specs). **Osaka** is the default (`CLZ`, plus Cancun ops `TLOAD`/`TSTORE`, `MCOPY`, `BLOBHASH`/`BLOBBASEFEE`). **Amsterdam** is opt-in (`--fork amsterdam`) and adds `SLOTNUM` and EIP-8024 `DUPN`/`SWAPN`/`EXCHANGE`. Prague remains selectable as an older fork. `BREAKPOINT` (`0xCC`) is opt-in via `--fork prague_breakpoint` / `osaka_breakpoint` / `amsterdam_breakpoint`; Prague, Osaka, and Amsterdam treat it as `InvalidOpcode`.

External calls (`CALL`, `DELEGATECALL`, `STATICCALL`, `CREATE`, `CREATE2`) run on an iterative stack of at most **1025 frames** (`depth + 1 > 1024` is rejected, matching [execution-specs](https://github.com/ethereum/execution-specs)). `LOG0`–`LOG4` and `SELFDESTRUCT` (EIP-6780) are implemented. Precompiles: `ecrecover` (`0x01`), `sha256` (`0x02`), `identity` (`0x04`), `modexp` (`0x05`), and Osaka `p256verify` (`0x100`). `BLOCKHASH` reads a 256-header window of `keccak256(rlp(header))`. `BLOBHASH` returns 0. Frame memory is capped at 16 MiB (shared 128 MiB pool); expansion past that is OutOfGas. State tests compare account dumps and, when `post.hash` is 32 bytes, a check-time Merkle Patricia state root. Blockchain tests run Osaka system contracts (EIP-4788, EIP-2935, EIP-7002, EIP-7251), then check `gasUsed`, `stateRoot`, and the header hash.

## Tiger Style highlights

- **Static allocation**: call frames, memory pool, accounts, and storage are fixed-size arrays in `limits.zig`
- **Assertions**: pre/postconditions on stack depth, memory bounds, gas remaining
- **Explicit types**: `u32` for sizes and offsets, `u64` for gas — no `usize` in hot paths
- **70-line functions**: interpreter ops split into small helpers
- **Pair assertions**: memory expand checks both caller offset and internal active size

See [docs/TIGER_STYLE.md](docs/TIGER_STYLE.md) for the full style reference.

## License

MIT
