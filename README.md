# Antigravity Game Memory Editor MCP Server

A Model Context Protocol (MCP) server that empowers Antigravity to act as an automated Cheat Engine / Memory Editor for singleplayer games on Windows.

## Features

- **Process Discovery & Attachment**: Find games by name or PID and attach with Win32 `OpenProcess`.
- **Memory Scanning Engine**:
  - `first_scan`: Initial search for int32, int64, float, double, byte, string.
  - `next_scan`: Filter candidates by `exact`, `increased`, `decreased`, `changed`, `unchanged`.
- **Pointer Resolution**: Resolve multi-level pointer chains (`base_address + offset1 -> offset2`).
- **Signature / AOB Scanning**: Find static offsets and code hooks using pattern wildcards (`48 8B 05 ?? ?? ?? ??`).
- **Direct Memory R/W**: Safely read and write primitive types.
- **Value Freezing**: Background worker thread that constantly locks values to maintain God Mode / Infinite Ammo / Unlimited Gold.
- **Lua Scripting Engine**: Run Lua scripts with Cheat Engine-compatible globals (`readInteger`, `writeInteger`, `readFloat`, `writeFloat`, `freeze`, `unfreeze`).
- **Remote In-Game Lua Injection**: Execute Lua code inside games with embedded Lua states (`lua51.dll`, `luajit.dll`).
- **Cheat Table (.CT) Support**: Load, parse, read, and activate Cheat Engine tables directly.
- **DLL Injection**: Inject custom mod / trainer DLLs into game processes via Win32 `CreateRemoteThread`.

---

## MCP Tools Exposed to Antigravity

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
| `freeze_value` | Lock an address to a fixed value at regular intervals. |
| `unfreeze_value` | Stop freezing an address. |
| `list_frozen` | Inspect currently locked memory addresses. |

### Lua, Cheat Table & DLL Tools
| Tool Name | Description |
| :--- | :--- |
| `execute_lua` | Execute Lua scripts with Cheat Engine memory bindings (`readInteger`, `writeInteger`, etc.). |
| `inject_game_lua` | Run Lua scripts directly inside games with an embedded Lua runtime (`lua51.dll`, `luajit.dll`). |
| `load_cheat_table` | Load and parse Cheat Engine `.CT` files or XML content. |
| `list_cheat_table_entries` | View all variables, pointers, and resolved values in a loaded `.CT` table. |
| `set_cheat_table_entry` | Modify or freeze values for specific entries in a Cheat Table. |
| `inject_dll` | Inject any DLL into the attached game process using `CreateRemoteThread`. |

---

## Example Lua Usage

```lua
local hp_addr = "0x7FF712345678"
local current_hp = readInteger(hp_addr)
print("Current HP:", current_hp)

-- Set HP and freeze
writeInteger(hp_addr, 99999)
freeze(hp_addr, "int32", 99999)
```

---

## Testing / Verification

Run the test suite against a simulated target game:
```powershell
python test_extended_features.py
```
