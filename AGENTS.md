# AGENTS.md

## Cursor Cloud specific instructions

This is a single-binary Zig CLI (`zig-evm`), a statically allocated EVM. There is
no server or GUI — all development and testing happens through `zig` and the
compiled binary. Standard commands live in `README.md` (Quick start / Execution
spec tests) and `build.zig`.

### Toolchain

- Requires **Zig `0.16.0`** exactly. The code uses the post-"Writergate" APIs
  (`pub fn main(init: std.process.Init)`, `std.Io.File.stdout().writer(...)`),
  which do **not** compile on Zig 0.15 or earlier, and the master 0.17-dev API
  has since drifted. Repo-managed Cloud Agents get Zig from `.cursor/Dockerfile`;
  `zig version` should print `0.16.0`.
- `build.zig.zon` has no package-manager deps. POINT_EVALUATION (`0x0a`) and
  BLS12-381 (`0x0b`–`0x11`) link vendored [c-kzg-4844](https://github.com/ethereum/c-kzg-4844)
  + blst under `vendor/` (see `vendor/ORIGIN.txt`). A Tiger Style Zig rewrite is not in yet.

### Build / test / lint / run

- Build: `zig build` → binary at `zig-out/bin/zig-evm`.
- Unit tests: `zig build test` (aggregated via `src/root.zig`).
- Lint / format check: `zig fmt --check src/ build.zig`. Note: this currently
  reports `src/debug.zig`, `src/evm.zig`, `src/jsontest.zig`, and
  `src/precompile.zig` as unformatted. That is a **pre-existing** condition in
  the repo, not caused by a fresh setup — do not treat it as a regression.
- Run bytecode: `./zig-out/bin/zig-evm run 0x<bytecode> [0x<calldata>]`.
- LLM trace/debugger: `./zig-out/bin/zig-evm debug 0x<bytecode> <cmd>` (see
  `.cursor/skills/zig-evm-debug/SKILL.md`). `0xCC` is zig-evm `BREAKPOINT`:
  opt in with `--fork osaka_breakpoint` (or `prague_breakpoint` /
  `amsterdam_breakpoint`). Prague / Osaka / Amsterdam still treat it as invalid.

### Execution-spec (EEST) tests — gotchas

- Fixtures are **not** committed (`tests/eest/` is gitignored). Fetch them first
  with `scripts/fetch_eest_fixtures.sh` (full set) or
  `scripts/fetch_eest_fixtures.sh --smoke` (small subset). The script downloads
  a release tarball from GitHub, so it needs network egress.
- `zig build jsontest` runs the **default Debug build**, and each test case
  heap-allocates a ~100MB VM. Running the whole (even smoke) fixture set this way
  is very slow (many minutes). For quick iteration, run the already-built binary
  against a single fixture directory, e.g.
  `./zig-out/bin/zig-evm jsontest tests/eest/state_tests/shanghai/eip3855_push0`,
  or build with `-Doptimize=ReleaseFast` before large runs.
- Cases with only a post state-root are skipped (no MPT); pre-Cancun posts for
  EIP-6780 SELFDESTRUCT tests are skipped by design.
