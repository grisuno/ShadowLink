# Polyglot Codebase Knowledge Graph

> Generated offline by **readmenator**. Supports C, C++, Python, Go, Rust, JS/TS, Java, C#, Shell, PHP, Dart, GDScript, Nim, ASM, Ruby, Swift, Kotlin, Scala, Lua, Elixir.
> No LLMs. No tokens. Pure static analysis. See more [here](https://github.com/grisuno/ReadMenator)

**Total Files Parsed:** 8 | **Total Symbols Extracted:** 3 | **Total Imports:** 1

<!-- ranking_model: v1.0 | weights: {ppr:0.45,auth:0.2,test:0.15,doc:0.1,fresh:0.1} | alpha:0.85 | commit:e63a2e6 | date:2026-07-18 -->


## Table of Contents

1. [Statistics Dashboard](#statistics-dashboard)
2. [Architectural Layers](#architectural-layers)
3. [Ranked Context](#ranked-context)
4. [God Nodes](#god-nodes)
5. [Suggested Questions](#suggested-questions)
6. [Hotspot Analysis](#hotspot-analysis)
7. [Change Impact Analysis](#change-impact-analysis)
8. [Suggested Linting Rules](#suggested-linting-rules)
9. [Orphans](#orphans)
10. [Query Recipes](#query-recipes)
11. [Structural Knowledge Map](#structural-knowledge-map)
12. [Code Property Graph](#code-property-graph)
13. [Architecture Reference](#architecture-reference)
    - [PY (1 files)](#py-1-files)
    - [SH (7 files)](#sh-7-files)

---

## Statistics Dashboard

| Metric | Value |
|--------|-------|
| Total Files | 8 |
| Total Symbols | 3 |
| Total Imports | 1 |
| Call Edges | 0 |
| Inheritance Edges | 0 |
| Languages | 2 |
| Avg Symbols/File | 0.4 |
| Avg Imports/File | 0.1 |

### Top Files by Import Count (Fan-Out)

| File | Imports | Symbols | Language |
|------|---------|---------|----------|
| `app.py` | 1 | 0 | py |

---

## Architectural Layers

Auto-detected from path patterns, naming conventions, and imported frameworks.

| Layer | Files |
|-------|-------|
| utility | 8 |

### utility

- `app.py` (py, 0 symbols)
- `gen_loader.sh` (sh, 1 symbols)
- `gen_loader2.sh` (sh, 1 symbols)
- `gen_loader_win_infect.sh` (sh, 1 symbols)
- `gen_txt.sh` (sh, 0 symbols)
- `gen_xor.sh` (sh, 0 symbols)
- `install.sh` (sh, 0 symbols)
- `main.sh` (sh, 0 symbols)

---

## Ranked Context

Files ranked by composite score for the current query context. The ranking combines Personalized PageRank (query relevance), global authority, test coverage, documentation coverage, and code freshness. Model: v1.0.

| Rank | File | Composite | PPR | Authority | Test | Doc |
|------|------|-----------|-----|-----------|------|-----|
| 1 | `app.py` | 0.1000 | 0.0000 | 0.0000 | 0.00 | 1.00 |
| 2 | `gen_txt.sh` | 0.1000 | 0.0000 | 0.0000 | 0.00 | 1.00 |
| 3 | `gen_xor.sh` | 0.1000 | 0.0000 | 0.0000 | 0.00 | 1.00 |
| 4 | `main.sh` | 0.1000 | 0.0000 | 0.0000 | 0.00 | 1.00 |
| 5 | `gen_loader.sh` | 0.0000 | 0.0000 | 0.0000 | 0.00 | 0.00 |
| 6 | `gen_loader2.sh` | 0.0000 | 0.0000 | 0.0000 | 0.00 | 0.00 |
| 7 | `gen_loader_win_infect.sh` | 0.0000 | 0.0000 | 0.0000 | 0.00 | 0.00 |
| 8 | `install.sh` | 0.0000 | 0.0000 | 0.0000 | 0.00 | 0.00 |

---

## God Nodes

Most architecturally central files ranked by combined import/export degree and symbol richness.

| File | Score | Connections | PageRank |
|------|-------|-------------|----------|
| `gen_loader.sh` | 0.1 | | 0.0000 |
| `gen_loader2.sh` | 0.1 | | 0.0000 |
| `gen_loader_win_infect.sh` | 0.1 | | 0.0000 |
| `app.py` | 0.0 | | 0.0000 |
| `gen_txt.sh` | 0.0 | | 0.0000 |
| `gen_xor.sh` | 0.0 | | 0.0000 |
| `install.sh` | 0.0 | | 0.0000 |
| `main.sh` | 0.0 | | 0.0000 |

---

## Suggested Questions

Auto-generated exploration prompts based on graph structure:

- What does gen_loader.sh depend on, and what depends on it? (0 connections)
- What does gen_loader2.sh depend on, and what depends on it? (0 connections)
- What does gen_loader_win_infect.sh depend on, and what depends on it? (0 connections)
- What is the overall architecture of this codebase?

---

## Hotspot Analysis

Files ranked by combined complexity (symbol count) and centrality (connection count). High-scoring files are architecturally critical and may need refactoring attention.

| File | Complexity | Centrality | Combined | Symbols | Connections |
|------|-----------|------------|----------|---------|-------------|
| `app.py` | 0.000 | 1.000 | 0.600 | 0 | 1 |
| `gen_txt.sh` | 0.000 | 0.000 | 0.000 | 0 | 0 |
| `gen_xor.sh` | 0.000 | 0.000 | 0.000 | 0 | 0 |
| `main.sh` | 0.000 | 0.000 | 0.000 | 0 | 0 |
| `gen_loader.sh` | 1.000 | 0.000 | 0.400 | 1 | 0 |
| `gen_loader2.sh` | 1.000 | 0.000 | 0.400 | 1 | 0 |
| `gen_loader_win_infect.sh` | 1.000 | 0.000 | 0.400 | 1 | 0 |
| `install.sh` | 0.000 | 0.000 | 0.000 | 0 | 0 |

---

## Change Impact Analysis

Files sorted by how many other files would be affected if they changed. High-impact files should be changed with caution.

| File | Direct Dependents | Transitive Dependents | Total Impact |
|------|------------------|----------------------|--------------|
| `app.py` | 0 | 0 | 0 |
| `gen_loader.sh` | 0 | 0 | 0 |
| `gen_loader2.sh` | 0 | 0 | 0 |
| `gen_loader_win_infect.sh` | 0 | 0 | 0 |
| `gen_txt.sh` | 0 | 0 | 0 |
| `gen_xor.sh` | 0 | 0 | 0 |
| `install.sh` | 0 | 0 | 0 |
| `main.sh` | 0 | 0 | 0 |

---

## Suggested Linting Rules

Automatically suggested linting and security rules based on patterns detected in the codebase. These can be exported as Semgrep rules using the `--export-rules` flag.

| Rule ID | Severity | Description | Language | Matches |
|---------|----------|-------------|----------|---------|
| `RM001` | info | Large number of functions in sh: 3 total | sh | 3 |

---

## Orphans

Files with no documentation or low connectivity. These are candidates for documentation investment or cleanup.

- `gen_loader.sh` (1 symbols, no doc)
- `gen_loader2.sh` (1 symbols, no doc)
- `gen_loader_win_infect.sh` (1 symbols, no doc)
- `install.sh` (0 symbols, no doc)

---

## Query Recipes

Example queries you can run against this knowledge base using the ranking engine:

```
# Find files most relevant to a concept
readmenator query "Where is the import resolver implemented?"

# Rank files by relevance to a topic
readmenator query "How does documentation generation work?"

# Explain why a file ranks highly
readmenator query "explain readmenator/_documentation.py"

# Trace dependency paths with ranked context
readmenator query "path from CLI to exporter"
```

The ranking model uses the following signals:

- **Personalized PageRank** (45% weight): query-specific relevance via seed propagation
- **Global Authority** (20% weight): structural importance via standard PageRank
- **Test Coverage** (15% weight): fraction of symbols referenced in test files
- **Doc Coverage** (10% weight): presence of docstrings and file-level docs
- **Freshness** (10% weight): recent modification activity

Results include score decomposition and justification paths for each ranked item.

---

## Structural Knowledge Map

```mermaid
graph TD
    classDef mod fill:#1e1e1e,stroke:#ff6666,stroke-width:2px,color:#fff;
    classDef cls fill:#2d2d2d,stroke:#4ec9b0,stroke-width:2px,color:#fff;
    classDef fn fill:#333,stroke:#dcdcaa,stroke-width:1px,color:#dcdcaa;
    classDef ext fill:#111,stroke:#666,stroke-dasharray:5 5,color:#aaa;
    app_py["app.py (py)"]
    class app_py mod;
    gen_loader_sh["gen_loader.sh (sh)"]
    class gen_loader_sh mod;
    gen_loader_sh_usage["usage"]
    class gen_loader_sh_usage fn;
    gen_loader_sh --> gen_loader_sh_usage
    gen_loader2_sh["gen_loader2.sh (sh)"]
    class gen_loader2_sh mod;
    gen_loader2_sh_usage["usage"]
    class gen_loader2_sh_usage fn;
    gen_loader2_sh --> gen_loader2_sh_usage
    gen_loader_win_infect_sh["gen_loader_win_infect.sh (sh)"]
    class gen_loader_win_infect_sh mod;
    gen_loader_win_infect_sh_usage["usage"]
    class gen_loader_win_infect_sh_usage fn;
    gen_loader_win_infect_sh --> gen_loader_win_infect_sh_usage
    gen_txt_sh["gen_txt.sh (sh)"]
    class gen_txt_sh mod;
    gen_xor_sh["gen_xor.sh (sh)"]
    class gen_xor_sh mod;
    install_sh["install.sh (sh)"]
    class install_sh mod;
    main_sh["main.sh (sh)"]
    class main_sh mod;
    ext_os["os"]
    class ext_os ext;
    app_py -.->|imports| ext_os
```

---

## Code Property Graph

Machine-readable Code Property Graph (CPG) in JSON-LD format. This block allows AI agents to parse the full structural graph without additional file reads. Compatible with GraphRAG pipelines.

```json
{"@context": "https://readmenator.dev/cpg/v1", "analysis": {"communities": [], "god_nodes": [{"node_id": "gen_loader.sh", "score": 0.1}, {"node_id": "gen_loader2.sh", "score": 0.1}, {"node_id": "gen_loader_win_infect.sh", "score": 0.1}, {"node_id": "app.py", "score": 0.0}, {"node_id": "gen_txt.sh", "score": 0.0}, {"node_id": "gen_xor.sh", "score": 0.0}, {"node_id": "install.sh", "score": 0.0}, {"node_id": "main.sh", "score": 0.0}], "surprising_connections": []}, "edges": [{"confidence": "EXTRACTED", "relation": "imports", "source": "app.py", "target": "os"}], "generator": "readmenator", "metadata": {"edge_count": 1, "file_count": 8, "language_count": 2, "symbol_count": 3}, "nodes": [{"doc": "_*_ coding: utf8 _*_", "id": "app.py", "kind": "module", "label": "app.py", "language": "py", "sha256": "57b21bdb023585b8", "symbol_count": 0, "symbols": []}, {"id": "gen_loader.sh", "kind": "module", "label": "gen_loader.sh", "language": "sh", "sha256": "a1ccf523ffb0c1e9", "symbol_count": 1, "symbols": [{"kind": "function", "line": 9, "name": "usage"}]}, {"id": "gen_loader2.sh", "kind": "module", "label": "gen_loader2.sh", "language": "sh", "sha256": "3b4dc0c55cdb496e", "symbol_count": 1, "symbols": [{"kind": "function", "line": 10, "name": "usage"}]}, {"id": "gen_loader_win_infect.sh", "kind": "module", "label": "gen_loader_win_infect.sh", "language": "sh", "sha256": "3252d2046db3963c", "symbol_count": 1, "symbols": [{"kind": "function", "line": 11, "name": "usage"}]}, {"doc": "gen_text.sh - Script paramétrico para generar shellcode (Linux/Windows) con configuración personalizable Uso: ./gen_txt.sh <OS> <LHOST> [LPORT] [OUTPUT_BIN] [OUTPUT_ENC] Ejemplo: ./gen_txt.sh linux 10.10.14.11 5555 shell.bin shellcode_test.txt    Valores por defecto", "id": "gen_txt.sh", "kind": "module", "label": "gen_txt.sh", "language": "sh", "sha256": "7057c7da4b51e9d4", "symbol_count": 0, "symbols": []}, {"doc": "gen_xor.sh <input.bin> > shellcode.txt", "id": "gen_xor.sh", "kind": "module", "label": "gen_xor.sh", "language": "sh", "sha256": "1fffe586a8bceaf0", "symbol_count": 0, "symbols": []}, {"id": "install.sh", "kind": "module", "label": "install.sh", "language": "sh", "sha256": "c907d80fd6734993", "symbol_count": 0, "symbols": []}, {"doc": "=== main.sh === Uso: ./main.sh <OS> <LHOST> [LPORT] [xor] [KEY] [PROCESS_NAME] Ejemplos: ./main.sh linux 10.10.14.11 5555 ./main.sh windows 10.10.14.11 4444 xor 0x42 ./main.sh windows 10.10.14.11 4444 xor 0x42 notepad.exe", "id": "main.sh", "kind": "module", "label": "main.sh", "language": "sh", "sha256": "4584ec6693d39913", "symbol_count": 0, "symbols": []}], "type": "CodePropertyGraph", "version": "1.0"}
```

---

## Architecture Reference

### PY (1 files)

#### `app.py`
**Path:** `app.py`
**File Doc:** *_*_ coding: utf8 _*_*

*No symbols extracted*

### SH (7 files)

#### `gen_loader.sh`
**Path:** `gen_loader.sh`

**Functions:**
- `usage` (line 9)

#### `gen_loader2.sh`
**Path:** `gen_loader2.sh`

**Functions:**
- `usage` (line 10)

#### `gen_loader_win_infect.sh`
**Path:** `gen_loader_win_infect.sh`

**Functions:**
- `usage` (line 11)

#### `gen_txt.sh`
**Path:** `gen_txt.sh`
**File Doc:** *gen_text.sh - Script paramétrico para generar shellcode (Linux/Windows) con configuración personalizable Uso: ./gen_txt.sh <OS> <LHOST> [LPORT] [OUTPUT_BIN] [OUTPUT_ENC] Ejemplo: ./gen_txt.sh linux 10.10.14.11 5555 shell.bin shellcode_test.txt    Valores por defecto*

*No symbols extracted*

#### `gen_xor.sh`
**Path:** `gen_xor.sh`
**File Doc:** *gen_xor.sh <input.bin> > shellcode.txt*

*No symbols extracted*

#### `install.sh`
**Path:** `install.sh`

*No symbols extracted*

#### `main.sh`
**Path:** `main.sh`
**File Doc:** *=== main.sh === Uso: ./main.sh <OS> <LHOST> [LPORT] [xor] [KEY] [PROCESS_NAME] Ejemplos: ./main.sh linux 10.10.14.11 5555 ./main.sh windows 10.10.14.11 4444 xor 0x42 ./main.sh windows 10.10.14.11 4444 xor 0x42 notepad.exe*

*No symbols extracted*
