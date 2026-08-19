---
name: zig-evm-debug
description: Query zig-evm execution traces as JSON (overview, state, opcode, explain, storage-diff). Use when debugging this EVM, inspecting bytecode, tracing opcodes, debugging a forge test with zig-evm, or when the user asks to debug a contract/call with zig-evm.
---

# zig-evm LLM debugger

`zig-evm debug` runs bytecode in this VM and prints JSON on stdout. No dump file, no sourcemaps. Prefer this over Foundry `debugger-llm` when the code under test is zig-evm itself.

## Command

```bash
zig build
./zig-out/bin/zig-evm debug [--fork osaka] [--gas 1000000] <code-hex> [0xcalldata] <cmd> [k=v...]
./zig-out/bin/zig-evm debug --match-test testFoo [out-dir] <cmd> [k=v...]
./zig-out/bin/zig-evm debug --match-test testFoo --match-contract Foo [out-dir] <cmd> [k=v...]
```

Calldata is accepted only with a `0x` prefix. Anything else after bytecode is the command.

`--match-test` walks `forge build` artifacts (default dir `out`), deploys, then traces `setUp` and the test call with hevm cheatcodes. Cheatcodes in `setUp` show up as steps. The constructor is not in the trace. Fuzz tests are rejected. If several tests match, pass `--match-contract`.

Default address for raw bytecode is `0xdeadbeef`. Default gas is `1000000`. Default fork is Osaka. Forge tests use the forge-test sender and 30M gas.

## Workflow

1. `overview` — calls, step counts, status.
2. `opcode opcode=REVERT` / `opcode opcode=SSTORE` — find interesting steps (compact listings).
3. `state step=N` / `explain step=N` — replay to that step (pre-opcode stack/memory).
4. `storage-diff` — persistent and transient slot writes.
5. `diff step_a=N step_b=M` — stack/memory/storage delta.

Steps are 1-based. `state step=3` is the third opcode, before it executes. Stack is top-first.

## Commands

| cmd | params | result |
|---|---|---|
| `overview` | `start`, `count` | calls, totals, status |
| `call-tree` | `start`, `count` | parent/depth per call |
| `state` | `step` | full stack/memory/storage at step |
| `step` | `call`, `step_idx` | same as state, call-local index (0-based) |
| `pc` | `pc`, optional `call`, `start`, `count` | compact steps at that PC |
| `opcode` | `opcode=ADD` (or `0x01`), optional `call` | compact matching steps |
| `trace` | `start`, `count` | compact step window |
| `storage-diff` | | SSTORE/TSTORE before/after |
| `explain` | `step` | category, description, named stack inputs |
| `diff` | `step_a`, `step_b` | stack/memory/storage changes |

`source` and `watch-memory` are not implemented.

Listings cap at 25 (`count=N` to raise). Responses include `has_more` / `total`. Compact queries (`pc`, `opcode`, `trace`) do not replay full stack; use `state` for that.

## Example

```bash
./zig-out/bin/zig-evm debug 0x600160020100 overview
./zig-out/bin/zig-evm debug 0x600160020100 state step=3
./zig-out/bin/zig-evm debug 0x600160020100 opcode opcode=ADD
./zig-out/bin/zig-evm debug --match-test testFoo overview
./zig-out/bin/zig-evm debug --match-test testFoo state step=3
```
