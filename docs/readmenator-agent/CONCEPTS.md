# Concepts

Nouns map atomically to file sets (EXTRACTED); verbs aggregate structural edges (INFERRED).

- `gen` | files=5 | mentions=14 | `gen_loader.sh`, `gen_loader2.sh`, `gen_loader_win_infect.sh`, `gen_txt.sh`, `gen_xor.sh`
- `usage` | files=3 | mentions=3 | `gen_loader.sh`, `gen_loader2.sh`, `gen_loader_win_infect.sh`
- `txt` | files=2 | mentions=6 | `gen_txt.sh`, `gen_xor.sh`
- `xor` | files=2 | mentions=6 | `gen_xor.sh`, `main.sh`
- `loader` | files=2 | mentions=4 | `gen_loader.sh`, `gen_loader_win_infect.sh`
- `bin` | files=2 | mentions=3 | `gen_txt.sh`, `gen_xor.sh`
- `linux` | files=2 | mentions=3 | `gen_txt.sh`, `main.sh`
- `shellcode` | files=2 | mentions=3 | `gen_txt.sh`, `gen_xor.sh`
- `windows` | files=2 | mentions=3 | `gen_txt.sh`, `main.sh`
- `lhost` | files=2 | mentions=2 | `gen_txt.sh`, `main.sh`
- `lport` | files=2 | mentions=2 | `gen_txt.sh`, `main.sh`
- `uso` | files=2 | mentions=2 | `gen_txt.sh`, `main.sh`

## Dialectic

- Thesis: `bin` centralizes 2 files; Antithesis: `gen` pulls 5 files with 2 shared (Jaccard 0.40); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `bin` centralizes 2 files; Antithesis: `shellcode` pulls 2 files with 2 shared (Jaccard 1.00); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `bin` centralizes 2 files; Antithesis: `txt` pulls 2 files with 2 shared (Jaccard 1.00); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `gen` centralizes 5 files; Antithesis: `loader` pulls 2 files with 2 shared (Jaccard 0.40); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `gen` centralizes 5 files; Antithesis: `shellcode` pulls 2 files with 2 shared (Jaccard 0.40); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `gen` centralizes 5 files; Antithesis: `txt` pulls 2 files with 2 shared (Jaccard 0.40); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `gen` centralizes 5 files; Antithesis: `usage` pulls 3 files with 3 shared (Jaccard 0.60); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `lhost` centralizes 2 files; Antithesis: `linux` pulls 2 files with 2 shared (Jaccard 1.00); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `lhost` centralizes 2 files; Antithesis: `lport` pulls 2 files with 2 shared (Jaccard 1.00); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `lhost` centralizes 2 files; Antithesis: `uso` pulls 2 files with 2 shared (Jaccard 1.00); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
