# Tiger Style, applied to zig-evm

Safety, performance, then developer experience. In that order.

This project follows [TigerBeetle's Tiger Style](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md). The rules that matter most here:

## Safety

- Put a limit on everything. Caps live in `src/limits.zig`.
- Assert arguments, return values, and invariants. Crash on programmer error.
- Pair assertions: check the same property on both sides of a boundary (push/pop, expand/load).
- Use explicit widths (`u32`, `u64`). Avoid `usize` on the data plane.
- Allocate the VM once at startup (`call_frames_max` frames). Do not allocate during opcode execution.
- No recursion. Nested `CALL`/`CREATE` use an iterative frame stack with `call_depth_limit = 1024`.

## Performance

- Keep the interpreter as a tight loop over a flat `Frame`.
- Centralize control flow in `Frame.execute`; keep leaf helpers branch-light.
- Batch memory expansion instead of growing a byte at a time.

## Developer experience

- `snake_case` for functions, variables, and files.
- Names carry units: `gas_limit`, `active_bytes`, `jumpdest_count`.
- Functions stay short. Push `if`s up, `for`s down.
- Always say why, in comments and assertions.
