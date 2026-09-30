from mcp.server.fastmcp import FastMCP
from typing import Optional, List, Any
import sys
import os

sys.path.append(os.path.dirname(__file__))

from game_memory_engine import GameMemoryEngine
from dll_injector import inject_dll_to_process
from cheat_table import CheatTableParser
from lua_engine import LuaEngine

mcp = FastMCP(
    name="GameMemoryEditor",
    description="Advanced Game Memory Editor with Cheat Engine table (.CT) parsing, Lua scripting, DLL injection, pointer resolution, and memory freezing."
)

engine = GameMemoryEngine()
ct_parser = CheatTableParser(engine)
lua_engine = LuaEngine(engine)

@mcp.tool()
def list_processes(filter_name: Optional[str] = None) -> list:
    """Lists running Windows processes with their PID and process name."""
    return engine.list_processes(filter_name)

@mcp.tool()
def attach_process(target: str) -> dict:
    """Attaches to a target process by PID or process executable name (e.g. 'game.exe')."""
    return engine.attach(target)

@mcp.tool()
def list_modules() -> list:
    """Lists loaded modules and base addresses in the attached process."""
    return engine.list_modules()

@mcp.tool()
def first_scan(scan_id: str, data_type: str, value: float, max_results: int = 20000) -> dict:
    """Performs an initial memory scan across committed writable memory pages."""
    return engine.first_scan(scan_id, data_type, value, max_matches=max_results)

@mcp.tool()
def next_scan(scan_id: str, scan_type: str = "exact", value: Optional[float] = None) -> dict:
    """Filters previous scan results (exact, increased, decreased, changed, unchanged)."""
    return engine.next_scan(scan_id, scan_type, value)

@mcp.tool()
def read_memory(address: str, data_type: str = "int32", offsets: Optional[List[int]] = None) -> dict:
    """Reads a value from a memory address or pointer chain."""
    addr_int = int(address, 16) if isinstance(address, str) and address.startswith(('0x', '0X')) else int(address)
    return engine.read_memory(addr_int, data_type, offsets)

@mcp.tool()
def write_memory(address: str, data_type: str, value: Any, offsets: Optional[List[int]] = None) -> dict:
    """Writes a value to a memory address or pointer chain."""
    addr_int = int(address, 16) if isinstance(address, str) and address.startswith(('0x', '0X')) else int(address)
    return engine.write_memory(addr_int, data_type, value, offsets)

@mcp.tool()
def pattern_scan(pattern: str, module_name: Optional[str] = None) -> dict:
    """Finds addresses matching an AOB byte pattern (e.g. '48 8B 05 ?? ?? ?? ?? 48 85 C0')."""
    return engine.pattern_scan(pattern, module_name)

@mcp.tool()
def freeze_value(address: str, data_type: str, value: Any, interval_ms: int = 50) -> dict:
    """Freezes a memory address to a specific value constantly."""
    addr_int = int(address, 16) if isinstance(address, str) and address.startswith(('0x', '0X')) else int(address)
    return engine.freeze_value(addr_int, data_type, value, interval_ms)

@mcp.tool()
def unfreeze_value(address: str) -> dict:
    """Unfreezes a previously locked memory address."""
    addr_int = int(address, 16) if isinstance(address, str) and address.startswith(('0x', '0X')) else int(address)
    return engine.unfreeze_value(addr_int)

@mcp.tool()
def list_frozen() -> list:
    """Lists all currently frozen memory addresses."""
    return engine.list_frozen()

# --- DLL Injection ---

@mcp.tool()
def inject_dll(dll_path: str) -> dict:
    """
    Injects a DLL into the currently attached process using standard Win32 CreateRemoteThread.
    Args:
        dll_path: Absolute or relative path to the DLL file.
    """
    if not engine.process_handle:
        return {"success": False, "error": "No process attached. Call attach_process first."}
    return inject_dll_to_process(engine.process_handle, dll_path)

# --- Cheat Table (.CT) Management ---

@mcp.tool()
def load_cheat_table(table_id: str, file_path_or_xml: str) -> dict:
    """
    Loads and parses a Cheat Engine Cheat Table (.CT file or raw XML string).
    Args:
        table_id: An arbitrary name for this table (e.g. 'hades_table').
        file_path_or_xml: File path to .CT file or raw XML content.
    """
    return ct_parser.parse_ct(table_id, file_path_or_xml)

@mcp.tool()
def list_cheat_table_entries(table_id: str) -> list:
    """Lists all variables, pointers, and scripts in a loaded Cheat Table with resolved addresses and current values."""
    return ct_parser.list_entries(table_id)

@mcp.tool()
def set_cheat_table_entry(table_id: str, entry_id: str, value: Any, freeze: bool = False) -> dict:
    """
    Overwrites or freezes the value for a specific Cheat Table entry.
    Args:
        table_id: The loaded table identifier.
        entry_id: Entry ID (from list_cheat_table_entries).
        value: New value to write.
        freeze: Set to true to continuously lock the value.
    """
    return ct_parser.set_entry_value(table_id, entry_id, value, freeze)

# --- Lua Engine ---

@mcp.tool()
def execute_lua(script: str) -> dict:
    """
    Executes a Lua script with Cheat Engine compatibility functions:
    Functions: readInteger(addr), writeInteger(addr, val), readFloat(addr), writeFloat(addr, val),
               readString(addr), writeString(addr, val), freeze(addr, type, val), unfreeze(addr), print(...)
    """
    return lua_engine.execute_script(script)

@mcp.tool()
def inject_game_lua(script: str, lua_module: str = "lua51.dll") -> dict:
    """
    Executes a Lua script inside games with an embedded Lua runtime (e.g. Total War, Payday 2, Baldur's Gate).
    Args:
        script: Lua code to run inside the game engine.
        lua_module: The DLL name hosting Lua in the game (default: 'lua51.dll', 'luajit.dll', etc.).
    """
    return lua_engine.inject_remote_lua(script, lua_module)

if __name__ == "__main__":
    mcp.run()
