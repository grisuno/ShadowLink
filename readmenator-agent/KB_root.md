# Subsystem: root

## app.py
- Layer: utility
- Doc: _*_ coding: utf8 _*_
- Language: py

## gen_loader.sh
- Layer: utility
- Language: sh
- Symbols:
  - `usage` (function, line 9)

## gen_loader2.sh
- Layer: utility
- Language: sh
- Symbols:
  - `usage` (function, line 10)

## gen_loader_win_infect.sh
- Layer: utility
- Language: sh
- Symbols:
  - `usage` (function, line 11)

## gen_txt.sh
- Layer: utility
- Doc: gen_text.sh - Script paramétrico para generar shellcode (Linux/Windows) con configuración personalizable Uso: ./gen_txt.
- Language: sh

## gen_xor.sh
- Layer: utility
- Doc: gen_xor.sh <input.bin> > shellcode.txt
- Language: sh

## install.sh
- Layer: utility
- Language: sh

## main.sh
- Layer: utility
- Doc: === main.sh === Uso: ./main.sh <OS> <LHOST> [LPORT] [xor] [KEY] [PROCESS_NAME] Ejemplos: ./main.sh linux 10.10.14.11 555
- Language: sh
