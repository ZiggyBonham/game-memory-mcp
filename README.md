# 🎮 Game Memory Editor MCP Server

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-3776AB.svg?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![MCP Protocol](https://img.shields.io/badge/MCP-Protocol-blueviolet.svg?style=flat)](https://modelcontextprotocol.io/)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64%20%7C%20x86-0078D6.svg?style=flat&logo=windows&logoColor=white)](https://microsoft.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat)](https://opensource.org/licenses/MIT)

A high-performance **Model Context Protocol (MCP)** server that equips **Antigravity** and LLM agents with native, real-time memory inspection, multi-stage value scanning, pointer chain traversal, Cheat Engine Table (`.CT`) execution, Lua scripting, reflective manual mapping, and stealth low-footprint operations for single-player games on Windows.

---

## 🏛️ Architecture Overview

```
                               ┌────────────────────────────────────────────────────────┐
                               │                      Antigravity                       │
                               │                (AI Coding Assistant)                   │
                               └───────────────────────────┬────────────────────────────┘
                                                           │  MCP Tool Call (JSON-RPC)
                                                           ▼
┌───────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                           Game Memory Editor MCP Server                                           │
├───────────────────────────────┬───────────────────────────────┬───────────────────────────────┬───────────────────┤
│        Memory Engine          │        Stealth Engine         │       Modding & Tables        │   Manual Mapper   │
│  • Fast Regex AOB Scanner     │  • Direct NTDLL Syscalls      │  • Cheat Table (.CT) Parser   │  • PE Mapper      │
│  • Multi-stage Value Scanner  │  • Ephemeral Handle Lifecycle │  • LuaJIT Runtime (CE Globals)│  • Base Relocs    │
│  • Multilevel Pointer Chains  │  • Smart Adaptive Freezing    │  • Script Obfuscation (XOR)   │  • IAT Resolution │
│  • Memory Protection Restore  │  • Jittered Polling Delays    │  • Standard DLL Injector      │  • Wiped Headers  │
└───────────────────────────────┴───────────────┬───────────────┴───────────────────────────────┴───────────────────┘
                                                │  Win32 / Native NT Syscalls
                                                ▼
                               ┌────────────────────────────────────────────────────────┐
                               │               Single-Player Game Process               │
                               │                   (x64 / x86 Virtual Memory)           │
                               └────────────────────────────────────────────────────────┘
```

---

## ⚡ Key Capabilities

### 1. 🔍 High-Performance Memory Scanner
* **Regex-Accelerated AOB Pattern Scanner**: Compiled regular expressions scan committed memory pages in 2MB chunks with wildcards (`??`), executing up to **100x faster** than naive loops.
* **Multi-Stage Value Filtering**: Supports `first_scan` and `next_scan` with exact value, increased, decreased, changed, and unchanged modes.
* **Precision Floating-Point Support**: Accurate float (`f32`) and double (`f64`) comparisons using `math.isclose` to eliminate IEEE-754 rounding discrepancies.
* **Multilevel Pointer Chains**: Resolves nested pointer offsets (`base + off1 -> [ptr] + off2 -> [ptr] + ...`).

### 2. 🥷 Stealth & Low-Footprint Operations
* **Direct NT Syscalls**: Calls `NtReadVirtualMemory`, `NtWriteVirtualMemory`, and `NtProtectVirtualMemory` directly, bypassing user-mode hooks placed on `kernel32.dll`.
* **Ephemeral Handle Lifecycle**: Opens handles on demand with minimal required access rights (`PROCESS_VM_READ | PROCESS_VM_WRITE`) and closes them immediately, leaving no persistent open handle signatures.
* **Smart Adaptive Freezing (Write-on-Change)**: Reads memory before writing and **only issues a write when the value changes in-game** (e.g., 40 checks resulted in only 1 actual write in tests).
* **Timing Jitter**: Introduces randomized micro-delays (e.g. 40ms–120ms) to disrupt static polling frequency heuristics.
* **Memory Protection Restoration**: Automatically elevates page protections to `PAGE_EXECUTE_READWRITE` before writing and restores the original page protection immediately afterward.

### 3. 📜 Cheat Engine Table (`.CT`) Integration
* **Native XML Parser**: Parses Cheat Engine tables, resolving module-relative addresses (`"game.exe"+01A2B3C0`), negative offsets (`"game.exe"-0x50`), and deep pointer chains.
* **Direct Value Manipulation**: Read, write, and freeze individual table entries without launching the Cheat Engine GUI.

### 4. 🌙 Embedded Lua Scripting Runtime
* **Cheat Engine API Compatibility**: Provides built-in functions:
  ```lua
  readInteger(addr), writeInteger(addr, value)
  readFloat(addr),   writeFloat(addr, value)
  readDouble(addr),  writeDouble(addr, value)
  readString(addr),  writeString(addr, value)
  freeze(addr, type, value), unfreeze(addr)
  getModuleBase(name), print(...)
  ```
* **Script Obfuscation**: Encrypts scripts using multi-byte rolling XOR keys and outputs standalone self-decrypting Lua stubs that execute in-memory.

### 5. 💉 Reflective Manual Mapping & DLL Injection
* **PE Manual Mapper**: Maps DLLs directly into process memory without `LoadLibraryW`:
  - Maps `.text`, `.rdata`, `.data` sections to their virtual addresses.
  - Applies Base Relocations (`IMAGE_DIRECTORY_ENTRY_BASERELOC`).
  - Resolves Import Address Tables (IAT) (`IMAGE_DIRECTORY_ENTRY_IMPORT`).
  - Executes `DllMain` via an ABI-compliant assembly trampoline.
  - Wipes PE headers from target memory to hide from memory scanners.
* **Standard Win32 Injector**: `CreateRemoteThread` injection with thread exit code validation.

---

## 🛠️ MCP Tools Reference

### Process & Memory Management
| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| `list_processes` | `filter_name?: str` | List running Windows processes with PID and executable name. |
| `attach_process` | `target: str \| int` | Attach to a target process by PID or executable name (e.g. `game.exe`). |
| `list_modules` | *(none)* | Enumerate loaded modules and base addresses (useful for ASLR calculations). |
| `read_memory` | `address: str \| int`, `data_type?: str`, `offsets?: int[]` | Read typed values (`int32`, `int64`, `float`, `double`, `string`) from address or pointer chain. |
| `write_memory` | `address: str \| int`, `data_type: str`, `value: Any`, `offsets?: int[]` | Write typed value to address or pointer chain. |
| `freeze_value` | `address: str \| int`, `data_type: str`, `value: Any`, `interval_ms?: int` | Continuously enforce a memory value (God Mode, Infinite Ammo). |
| `unfreeze_value` | `address: str \| int` | Release a frozen address. |
| `list_frozen` | *(none)* | List all currently frozen addresses. |

### Memory Scanning
| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| `first_scan` | `scan_id: str`, `data_type: str`, `value: float \| int \| str`, `max_results?: int` | Scan committed memory pages for an initial value. |
| `next_scan` | `scan_id: str`, `scan_type?: str`, `value?: float \| int` | Filter matches: `exact`, `increased`, `decreased`, `changed`, `unchanged`. |
| `pattern_scan` | `pattern: str`, `module_name?: str` | High-speed AOB regex scan with `??` wildcards (e.g. `48 8B 05 ?? ?? ?? ?? 48 85 C0`). |

### Stealth & Low-Footprint
| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| `set_stealth_config` | `use_ephemeral_handles?: bool`, `jitter_min_ms?: int`, `jitter_max_ms?: int` | Configure stealth handle lifecycle and timing jitter. |
| `stealth_write` | `address: str \| int`, `data_type: str`, `value: Any`, `restore_protection?: bool` | Direct `NtWriteVirtualMemory` with automatic protection restoration. |
| `smart_freeze` | `address: str \| int`, `data_type: str`, `value: Any`, `min_interval_ms?: int`, `max_interval_ms?: int` | Low-footprint write-on-change freezing with jitter. |
| `smart_unfreeze` | `address: str \| int` | Stop smart adaptive freeze on an address. |
| `obfuscate_script` | `script_text: str`, `key_seed?: int` | Multi-byte XOR encrypt script and generate self-decrypting stub. |
| `manual_map_inject`| `dll_path: str`, `wipe_headers?: bool` | Reflective manual PE mapping without `LoadLibraryW`. |

### Cheat Tables & Scripting
| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| `load_cheat_table` | `table_id: str`, `file_path_or_xml: str` | Parse a Cheat Engine `.CT` file or raw XML string. |
| `list_cheat_table_entries` | `table_id: str` | List all table entries with resolved addresses and live values. |
| `set_cheat_table_entry` | `table_id: str`, `entry_id: str`, `value: Any`, `freeze?: bool` | Overwrite or freeze value for a table entry. |
| `execute_lua` | `script: str` | Execute Lua script with Cheat Engine compatibility functions. |
| `inject_dll` | `dll_path: str` | Inject a native DLL via standard `CreateRemoteThread`. |

---

## 🚀 Quickstart

### 1. Installation
Clone repository and install dependencies:
```powershell
git clone https://github.com/ZiggyBonham/game-memory-mcp.git
cd game-memory-mcp
pip install -r requirements.txt
```

### 2. Antigravity MCP Registration
Add the server to your `~/.gemini/config/mcp_config.json`:
```json
{
  "mcpServers": {
    "game-memory": {
      "command": "python",
      "args": [
        "C:\\Users\\Ziggy\\mcp-servers\\game-memory\\server.py"
      ]
    }
  }
}
```

### 3. Example Agent Conversations

**Memory Scanning Flow:**
> **User**: "Attach to `hades.exe` and search for my health which is currently 250."  
> **Antigravity**: *Calls `attach_process("hades.exe")`, then `first_scan("hp", "int32", 250)`.*  
> **User**: "I took damage, health is now 215. Filter the scan."  
> **Antigravity**: *Calls `next_scan("hp", "exact", 215)`.*  
> **User**: "Set health to 5000 and smart-freeze it."  
> **Antigravity**: *Calls `smart_freeze("0x140A2C48", "int32", 5000)`.*

**Cheat Table Flow:**
> **User**: "Load `EldenRing.CT` and show me the player stats."  
> **Antigravity**: *Calls `load_cheat_table("er", "C:\\Cheats\\EldenRing.CT")`, then `list_cheat_table_entries("er")`.*  
> **User**: "Freeze Runes to 9999999."  
> **Antigravity**: *Calls `set_cheat_table_entry("er", "entry_runes", 9999999, freeze=True)`.*

---

## 🧪 Automated Test Suites

Run the complete verification battery:
```powershell
# Core memory engine (Attach, Scan, Read, Write, Freeze, Unfreeze)
python test_suite.py

# Modding features (Lua Scripting, Cheat Tables)
python test_extended_features.py

# Stealth features (Direct NT Syscalls, Smart Freeze, Protection Restore, Obfuscator)
python test_stealth.py

# High-speed optimizations (parse_address, Float Scanning, Regex AOB Scan)
python test_optimizations.py
```

---

## 🛡️ Requirements & Safety Notice

1. **Windows Administrator Privileges**: Modifying virtual memory of external processes (`PROCESS_VM_WRITE`, `PROCESS_VM_READ`) requires running your terminal / IDE with Administrator rights.
2. **Single-Player Games Only**: This tool is designed strictly for offline single-player games and reverse-engineering research. Games utilizing active anti-cheat engines (Easy Anti-Cheat, BattlEye, Vanguard) must be launched offline with anti-cheat disabled.

---

## 📄 License

Distributed under the [MIT License](LICENSE). Copyright (c) 2026 Ziggy.
