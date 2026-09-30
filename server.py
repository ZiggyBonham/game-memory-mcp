from mcp.server.fastmcp import FastMCP
from typing import Optional, List, Any
import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(__file__))

from game_memory_engine import GameMemoryEngine

# Initialize FastMCP Server
mcp = FastMCP(
    name="GameMemoryEditor",
    description="Provides real-time process memory inspection, search, pointer resolution, and read/write/freeze capabilities for singleplayer games."
)

engine = GameMemoryEngine()

@mcp.tool()
def list_processes(filter_name: Optional[str] = None) -> list:
    """
    Lists running Windows processes with their PID and process name.
    Args:
        filter_name: Optional substring to filter processes (e.g. 'game', 'elden', 'unity').
    """
    return engine.list_processes(filter_name)

@mcp.tool()
def attach_process(target: str) -> dict:
    """
    Attaches to a target process by PID (e.g. '1234') or process executable name (e.g. 'game.exe').
    Args:
        target: PID or process executable name.
    """
    return engine.attach(target)

@mcp.tool()
def list_modules() -> list:
    """
    Lists loaded modules and their base addresses in the attached process.
    Useful for finding base offsets (e.g. 'game.exe + 0x1A2B3C').
    """
    return engine.list_modules()

@mcp.tool()
def first_scan(scan_id: str, data_type: str, value: float, max_results: int = 20000) -> dict:
    """
    Performs an initial memory scan across committed writable memory pages for a specific value.
    Args:
        scan_id: An arbitrary identifier for this scan session (e.g. 'health_scan', 'gold_scan').
        data_type: 'int32', 'int64', 'float', 'double', 'int16', or 'byte'.
        value: The target value to search for.
        max_results: Max candidate matches to store.
    """
    return engine.first_scan(scan_id, data_type, value, max_matches=max_results)

@mcp.tool()
def next_scan(scan_id: str, scan_type: str = "exact", value: Optional[float] = None) -> dict:
    """
    Filters down previous scan results after the in-game value changes.
    Args:
        scan_id: Identifier of the active scan session.
        scan_type: 'exact' (matches specific new value), 'increased', 'decreased', 'changed', or 'unchanged'.
        value: New target value if scan_type is 'exact' or delta amount.
    """
    return engine.next_scan(scan_id, scan_type, value)

@mcp.tool()
def read_memory(address: str, data_type: str = "int32", offsets: Optional[List[int]] = None) -> dict:
    """
    Reads a value from a specified memory address or pointer chain.
    Args:
        address: Hex address string (e.g. '0x7FF712345678' or '0x00A1B2C0') or integer.
        data_type: 'int32', 'int64', 'float', 'double', 'int16', 'byte', or 'string'.
        offsets: Optional list of integer/hex pointer offsets to traverse (e.g. [0x48, 0x10, 0x0]).
    """
    addr_int = int(address, 16) if isinstance(address, str) and address.startswith(('0x', '0X')) else int(address)
    return engine.read_memory(addr_int, data_type, offsets)

@mcp.tool()
def write_memory(address: str, data_type: str, value: Any, offsets: Optional[List[int]] = None) -> dict:
    """
    Writes a value to a memory address or pointer chain.
    Args:
        address: Hex address string (e.g. '0x7FF712345678') or integer.
        data_type: 'int32', 'int64', 'float', 'double', 'int16', 'byte', or 'string'.
        value: The new value to write.
        offsets: Optional list of integer pointer offsets.
    """
    addr_int = int(address, 16) if isinstance(address, str) and address.startswith(('0x', '0X')) else int(address)
    return engine.write_memory(addr_int, data_type, value, offsets)

@mcp.tool()
def pattern_scan(pattern: str, module_name: Optional[str] = None) -> dict:
    """
    Finds addresses matching an Array-of-Bytes (AOB) signature with wildcards (e.g. '48 8B 05 ?? ?? ?? ?? 48 85 C0').
    Args:
        pattern: Space-delimited hex byte string with '??' wildcards.
        module_name: Optional module/dll name to restrict scan to (e.g. 'game.exe', 'mono-2.0-bdwgc.dll').
    """
    return engine.pattern_scan(pattern, module_name)

@mcp.tool()
def freeze_value(address: str, data_type: str, value: Any, interval_ms: int = 50) -> dict:
    """
    Freezes a memory address to a specific value by constantly rewriting it (e.g. God Mode / Infinite Ammo).
    Args:
        address: Hex address string.
        data_type: 'int32', 'int64', 'float', etc.
        value: The value to keep locked.
        interval_ms: Rewrite interval in milliseconds (default: 50ms).
    """
    addr_int = int(address, 16) if isinstance(address, str) and address.startswith(('0x', '0X')) else int(address)
    return engine.freeze_value(addr_int, data_type, value, interval_ms)

@mcp.tool()
def unfreeze_value(address: str) -> dict:
    """
    Unfreezes a previously locked memory address.
    Args:
        address: Hex address string.
    """
    addr_int = int(address, 16) if isinstance(address, str) and address.startswith(('0x', '0X')) else int(address)
    return engine.unfreeze_value(addr_int)

@mcp.tool()
def list_frozen() -> list:
    """Lists all currently frozen memory addresses and their target values."""
    return engine.list_frozen()

if __name__ == "__main__":
    mcp.run()
