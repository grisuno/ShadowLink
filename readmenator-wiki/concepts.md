# Concepts

Second-brain semantic layer: nouns map atomically to file sets (EXTRACTED); verbs aggregate structural edges (INFERRED).

| Concept | Files | Mentions | Top Files |
|---------|-------|----------|-----------|
| `gen` | 5 | 14 | `gen_loader.sh`, `gen_loader2.sh`, `gen_loader_win_infect.sh`, `gen_txt.sh`, `gen_xor.sh` |
| `usage` | 3 | 3 | `gen_loader.sh`, `gen_loader2.sh`, `gen_loader_win_infect.sh` |
| `txt` | 2 | 6 | `gen_txt.sh`, `gen_xor.sh` |
| `xor` | 2 | 6 | `gen_xor.sh`, `main.sh` |
| `loader` | 2 | 4 | `gen_loader.sh`, `gen_loader_win_infect.sh` |
| `bin` | 2 | 3 | `gen_txt.sh`, `gen_xor.sh` |
| `linux` | 2 | 3 | `gen_txt.sh`, `main.sh` |
| `shellcode` | 2 | 3 | `gen_txt.sh`, `gen_xor.sh` |
| `windows` | 2 | 3 | `gen_txt.sh`, `main.sh` |
| `lhost` | 2 | 2 | `gen_txt.sh`, `main.sh` |
| `lport` | 2 | 2 | `gen_txt.sh`, `main.sh` |
| `uso` | 2 | 2 | `gen_txt.sh`, `main.sh` |

## Dialectic Prompts

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
