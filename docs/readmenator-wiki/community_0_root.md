# root

*Community 0 | 8 files | cohesion 1.00*

## Definition

This community groups 8 file(s) rooted at `root` with dominant language sh (cohesion 1.00). Central symbols: `usage`. Core file: `gen_loader.sh` (1 symbols). Documented purpose: Autor: Gris Iscomeback Correo electrónico: grisiscomeback[at]gmail[dot]com Fecha de creación: xx/xx/xxxx Licencia: GPL v3  Descripción:.

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `app.py` | py | utility | 0 | yes |
| `gen_loader.sh` | sh | utility | 1 | no |
| `gen_loader2.sh` | sh | utility | 1 | no |
| `gen_loader_win_infect.sh` | sh | utility | 1 | no |
| `gen_txt.sh` | sh | utility | 0 | yes |
| `gen_xor.sh` | sh | utility | 0 | yes |
| `install.sh` | sh | utility | 0 | no |
| `main.sh` | sh | utility | 0 | yes |

## Key Symbols

- `usage` (function, `gen_loader.sh:9`)
- `usage` (function, `gen_loader2.sh:10`)
- `usage` (function, `gen_loader_win_infect.sh:11`)

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 0
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- No cross-community bridges recorded. This community is self-contained.

## Risks

- [dataflow UNCHECKED_ALLOC] `gen_loader.sh:253` `usage` `sc`: Result of allocator stored in `sc` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `gen_loader.sh:318` `usage` `sock`: Result of allocator stored in `sock` is never checked against NULL.
- [dataflow DEAD_STORE] `gen_loader2.sh:352` `usage` `path_len`: `path_len` assigned at line 352 but never read afterwards.
- [dataflow UNCHECKED_ALLOC] `gen_loader2.sh:124` `usage` `shellcode`: Result of allocator stored in `shellcode` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `gen_loader2.sh:303` `usage` `sc`: Result of allocator stored in `sc` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `gen_loader2.sh:366` `usage` `sock`: Result of allocator stored in `sock` is never checked against NULL.
- [dataflow DEAD_STORE] `gen_loader_win_infect.sh:254` `usage` `path_len`: `path_len` assigned at line 254 but never read afterwards.
- [dataflow UNCHECKED_ALLOC] `gen_loader_win_infect.sh:199` `usage` `sc`: Result of allocator stored in `sc` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `gen_loader_win_infect.sh:269` `usage` `sock`: Result of allocator stored in `sock` is never checked against NULL.

## Open Questions

- Why do 4 file(s) lack file-level docs (e.g. `gen_loader.sh`)? What purpose do they serve?
- What would break if the most connected file in root changed?
- Should root be split, given cohesion 1.00?

## Sources

- `app.py`
- `gen_loader.sh`
- `gen_loader2.sh`
- `gen_loader_win_infect.sh`
- `gen_txt.sh`
- `gen_xor.sh`
- `install.sh`
- `main.sh`
