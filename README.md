# Antigravity Game Memory Editor MCP Server

A Model Context Protocol (MCP) server that empowers Antigravity to act as an automated Cheat Engine / Memory Editor for singleplayer games on Windows with **stealth operations, low footprint memory access, and payload obfuscation**.

## Features

- **Process Discovery & Attachment**: Find games by name or PID.
- **Low-Footprint Memory Operations (Direct NT Syscalls)**:
  - Uses direct `ntdll.dll` API calls (`NtReadVirtualMemory`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory`).
  - Ephemeral minimal-access handle management (opens on-demand, closes immediately).
- **Smart Adaptive Freezing**:
  - Event-driven: only writes when in-game values deviate from target.
  - Randomized millisecond timing jitter to avoid static polling signatures.
- **Automatic Page Protection Restoration**:
  - Automatically elevates protection to `PAGE_EXECUTE_READWRITE` and restores original page protection immediately after write.
- **Reflective Manual-Map DLL Injection**:
  - Injects native DLLs without calling `LoadLibraryW` and wipes PE headers to remain hidden from module scans.
- **Payload & Script Obfuscation**:
  - Multi-byte rolling XOR encryption with self-decrypting Lua execution wrappers.
- **Memory Scanning Engine**:
  - `first_scan` / `next_scan` supporting `exact`, `increased`, `decreased`, `changed`, `unchanged`.
- **Pointer Resolution**: Multi-level pointer chain traversal (`base + offset1 -> offset2`).
- **Signature / AOB Scanning**: Array-of-Bytes wildcard pattern scanning.
- **Lua Scripting Runtime**: Run scripts with Cheat Engine-compatible API globals.
- **Cheat Table (.CT) Support**: Load, parse, read, and modify Cheat Engine tables.

---

## MCP Tools Exposed to Antigravity

### Stealth & Low-Footprint Tools
| Tool Name | Description |
| :--- | :--- |
| `set_stealth_config` | Configure ephemeral handle usage and jitter intervals (ms). |
| `stealth_write` | Write memory via direct `NtWriteVirtualMemory` with automatic protection restoration. |
| `smart_freeze` | Low-footprint event-driven address freeze with randomized jitter. |
| `smart_unfreeze` | Stop smart freeze on an address. |
| `obfuscate_script` | Encrypt Lua scripts with rolling XOR and generate self-decrypting stubs. |
| `manual_map_inject` | Reflectively map a DLL into target process without `LoadLibraryW` and wipe PE headers. |

### Memory & Process Tools
| Tool Name | Description |
| :--- | :--- |
| `list_processes` | Search running Windows processes by name filter. |
| `attach_process` | Attach to game process by executable name or PID. |
| `list_modules` | List loaded modules and base addresses (useful for ASLR calculations). |
| `first_scan` | Perform initial value scan across committed writable memory pages. |
| `next_scan` | Filter previous scan results as in-game values change. |
| `read_memory` | Read typed values from specific addresses or pointer chains. |
| `write_memory` | Overwrite values at specific addresses or pointer chains. |
| `pattern_scan` | Scan memory for Array-of-Bytes (AOB) signatures. |
| `freeze_value` | Standard continuous value freezer. |
| `unfreeze_value` | Stop standard freezing. |
| `list_frozen` | Inspect currently locked memory addresses. |

### Lua, Cheat Table & DLL Tools
| Tool Name | Description |
| :--- | :--- |
| `execute_lua` | Execute Lua scripts with Cheat Engine memory bindings (`readInteger`, `writeInteger`, etc.). |
| `inject_game_lua` | Run Lua scripts directly inside games with an embedded Lua runtime (`lua51.dll`, `luajit.dll`). |
| `load_cheat_table` | Load and parse Cheat Engine `.CT` files or XML content. |
| `list_cheat_table_entries` | View all variables, pointers, and resolved values in a loaded `.CT` table. |
| `set_cheat_table_entry` | Modify or freeze values for specific entries in a Cheat Table. |
| `inject_dll` | Standard `CreateRemoteThread` DLL injector. |

---

## Verification Tests

Run all test suites:
```powershell
python test_suite.py
python test_extended_features.py
python test_stealth.py
```
