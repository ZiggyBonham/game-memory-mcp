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

---

## MCP Tools Exposed to Antigravity

| Tool Name | Description |
| :--- | :--- |
| `list_processes` | Search running Windows processes by name filter. |
| `attach_process` | Attach to game process by executable name (e.g. `witcher3.exe`) or PID. |
| `list_modules` | List loaded modules and base addresses (useful for ASLR calculations). |
| `first_scan` | Perform initial value scan across committed writable memory pages. |
| `next_scan` | Filter previous scan results as in-game values change. |
| `read_memory` | Read typed values from specific addresses or pointer chains. |
| `write_memory` | Overwrite values at specific addresses or pointer chains. |
| `pattern_scan` | Scan memory for Array-of-Bytes (AOB) signatures. |
| `freeze_value` | Lock an address to a fixed value at regular intervals. |
| `unfreeze_value` | Stop freezing an address. |
| `list_frozen` | Inspect currently locked memory addresses. |

---

## How to Use in Chat with Antigravity

Once connected, you can simply instruct Antigravity in plain English:

1. *"Attach to Hades.exe and find my current health of 250."*
2. *(Take some damage in-game to 220)* -> *"My health is now 220, filter the scan."*
3. *"Set my health to 9999 and freeze it."*
4. *"Find the base address for player ammo using the pointer offsets `[0x48, 0x10, 0x18]`."*

---

## Testing / Verification

Run the test suite against a simulated target game:
```powershell
python test_suite.py
```
