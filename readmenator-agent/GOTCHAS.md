# Gotchas

## God Nodes (high connectivity)

These files have the most connections. Changes here have high blast radius.

- `gen_loader.sh` (score: 0.10)
- `gen_loader2.sh` (score: 0.10)
- `gen_loader_win_infect.sh` (score: 0.10)
- `app.py` (score: 0.00)
- `gen_txt.sh` (score: 0.00)
- `gen_xor.sh` (score: 0.00)
- `install.sh` (score: 0.00)
- `main.sh` (score: 0.00)

## Hotspots (complexity + centrality)

- `app.py` -- complexity: 0.0, centrality: 1.0, combined: 0.6
- `gen_loader.sh` -- complexity: 1.0, centrality: 0.0, combined: 0.4
- `gen_loader2.sh` -- complexity: 1.0, centrality: 0.0, combined: 0.4
- `gen_loader_win_infect.sh` -- complexity: 1.0, centrality: 0.0, combined: 0.4
- `gen_txt.sh` -- complexity: 0.0, centrality: 0.0, combined: 0.0
- `gen_xor.sh` -- complexity: 0.0, centrality: 0.0, combined: 0.0
- `install.sh` -- complexity: 0.0, centrality: 0.0, combined: 0.0
- `main.sh` -- complexity: 0.0, centrality: 0.0, combined: 0.0

## Dataflow Issues (INFERRED, review each lead)

- `gen_loader.sh:253` `usage` [UNCHECKED_ALLOC] `sc`: Result of allocator stored in `sc` is never checked against NULL.
- `gen_loader.sh:318` `usage` [UNCHECKED_ALLOC] `sock`: Result of allocator stored in `sock` is never checked against NULL.
- `gen_loader2.sh:352` `usage` [DEAD_STORE] `path_len`: `path_len` assigned at line 352 but never read afterwards.
- `gen_loader2.sh:124` `usage` [UNCHECKED_ALLOC] `shellcode`: Result of allocator stored in `shellcode` is never checked against NULL.
- `gen_loader2.sh:303` `usage` [UNCHECKED_ALLOC] `sc`: Result of allocator stored in `sc` is never checked against NULL.
- `gen_loader2.sh:366` `usage` [UNCHECKED_ALLOC] `sock`: Result of allocator stored in `sock` is never checked against NULL.
- `gen_loader_win_infect.sh:254` `usage` [DEAD_STORE] `path_len`: `path_len` assigned at line 254 but never read afterwards.
- `gen_loader_win_infect.sh:199` `usage` [UNCHECKED_ALLOC] `sc`: Result of allocator stored in `sc` is never checked against NULL.
- `gen_loader_win_infect.sh:269` `usage` [UNCHECKED_ALLOC] `sock`: Result of allocator stored in `sock` is never checked against NULL.
