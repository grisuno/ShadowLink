#!/bin/bash
# gen_xor.sh <input.bin> > shellcode.txt
if [ $# -ne 2 ]; then
    echo "Uso: $0 <archivo_binario> <clave_xor>"
    exit 1
fi

INPUT_FILE="$1"
KEY=$2
TMP_FILE="/tmp/hex_$$"

# Generar hex sin saltos de línea
xxd -p -c 20000 "$1" | tr -d '\n' > "$TMP_FILE"

# Procesar con Python: aplicar XOR y generar \xNN\xNN...
python3 -c "
key = $KEY
with open('$TMP_FILE', 'r') as f:
    hex_str = f.read().strip()
# Dividir en bytes de 2 caracteres
bytes_list = [hex_str[i:i+2] for i in range(0, len(hex_str), 2) if i+1 < len(hex_str)]
for b in bytes_list:
    val = int(b, 16)
    xor_val = val ^ key
    print(f'\\\\x{xor_val:02x}', end='')
print()
"

# Limpiar
rm -f "$TMP_FILE" 
