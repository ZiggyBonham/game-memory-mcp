from mcp.server.fastmcp import FastMCP
from typing import Optional, List, Any
import sys
import os

sys.path.append(os.path.dirname(__file__))

from game_memory_engine import GameMemoryEngine
from dll_injector import inject_dll_to_process
from cheat_table import CheatTableParser
from lua_engine import LuaEngine
from stealth_engine import StealthEngine
from manual_mapper import ManualMapper

mcp = FastMCP(
    name="GameMemoryEditor",
    description="Advanced Game Memory Editor with stealth operations, direct NT syscalls, smart adaptive freezing, script obfuscation, manual-map DLL injection, Cheat Tables (.CT), and Lua scripting."
)

engine = GameMemoryEngine()
ct_parser = CheatTableParser(engine)
lua_engine = LuaEngine(engine)
stealth = StealthEngine(engine)
mapper = ManualMapper(engine)

# --- Standard Process & Memory Tools ---

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

# --- Stealth & Low-Footprint Tools ---

@mcp.tool()
def set_stealth_config(use_ephemeral_handles: bool = True, jitter_min_ms: int = 40, jitter_max_ms: int = 120) -> dict:
    """
    Configures stealth parameters:
    - use_ephemeral_handles: Open handles on-demand with minimal rights and close immediately.
    - jitter_min_ms / jitter_max_ms: Randomized delay range to disrupt static polling timing signatures.
    """
    stealth.use_ephemeral_handles = use_ephemeral_handles
    stealth.jitter_min_ms = jitter_min_ms
    stealth.jitter_max_ms = jitter_max_ms
    return {
        "success": True,
        "ephemeral_handles": use_ephemeral_handles,
        "jitter_range_ms": f"{jitter_min_ms}-{jitter_max_ms}ms"
    }

@mcp.tool()
def stealth_write(address: str, data_type: str, value: Any, restore_protection: bool = True) -> dict:
    """
    Performs a low-footprint memory write using direct NtWriteVirtualMemory.
    Automatically elevates page protection to RWX and immediately restores original protection.
    """
    addr_int = int(address, 16) if isinstance(address, str) and address.startswith(('0x', '0X')) else int(address)
    return stealth.stealth_write(addr_int, data_type, value, restore_protection)

@mcp.tool()
def smart_freeze(address: str, data_type: str, value: Any, min_interval_ms: int = 40, max_interval_ms: int = 120) -> dict:
    """
    Freezes a value with minimal syscall footprint:
    - Reads memory with NtReadVirtualMemory and only issues a write if the in-game value changed.
    - Applies randomized jitter sleep between checks.
    """
    addr_int = int(address, 16) if isinstance(address, str) and address.startswith(('0x', '0X')) else int(address)
    return stealth.smart_freeze(addr_int, data_type, value, min_interval_ms, max_interval_ms)

@mcp.tool()
def smart_unfreeze(address: str) -> dict:
    """Stops smart adaptive freezing on a specific address."""
    addr_int = int(address, 16) if isinstance(address, str) and address.startswith(('0x', '0X')) else int(address)
    return stealth.smart_unfreeze(addr_int)

@mcp.tool()
def obfuscate_script(script_text: str, key_seed: Optional[int] = None) -> dict:
    """
    Encrypts a Lua/payload script with rolling multi-byte XOR cipher and generates a self-decrypting Lua stub.
    """
    return StealthEngine.obfuscate_script(script_text, key_seed)

@mcp.tool()
def manual_map_inject(dll_path: str, wipe_headers: bool = True) -> dict:
    """
    Reflectively manual-maps a DLL into the target process without using LoadLibraryW.
    Invisible in PEB InLoadOrderModuleList and wipes PE headers from target memory.
    """
    return mapper.map_dll(dll_path, wipe_headers)

# --- DLL Injection ---

@mcp.tool()
def inject_dll(dll_path: str) -> dict:
    """Injects a DLL into the attached process using standard Win32 CreateRemoteThread."""
    if not engine.process_handle:
        return {"success": False, "error": "No process attached. Call attach_process first."}
    return inject_dll_to_process(engine.process_handle, dll_path)

# --- Cheat Table (.CT) Management ---

@mcp.tool()
def load_cheat_table(table_id: str, file_path_or_xml: str) -> dict:
    """Loads and parses a Cheat Engine Cheat Table (.CT file or raw XML string)."""
    return ct_parser.parse_ct(table_id, file_path_or_xml)

@mcp.tool()
def list_cheat_table_entries(table_id: str) -> list:
    """Lists all variables, pointers, and scripts in a loaded Cheat Table with resolved addresses and current values."""
    return ct_parser.list_entries(table_id)

@mcp.tool()
def set_cheat_table_entry(table_id: str, entry_id: str, value: Any, freeze: bool = False) -> dict:
    """Overwrites or freezes the value for a specific Cheat Table entry."""
    return ct_parser.set_entry_value(table_id, entry_id, value, freeze)

# --- Lua Engine ---

@mcp.tool()
def execute_lua(script: str) -> dict:
    """Executes a Lua script with Cheat Engine compatibility functions."""
    return lua_engine.execute_script(script)

@mcp.tool()
def inject_game_lua(script: str, lua_module: str = "lua51.dll") -> dict:
    """Executes a Lua script inside games with an embedded Lua runtime."""
    return lua_engine.inject_remote_lua(script, lua_module)

if __name__ == "__main__":
    mcp.run()
