"""High-Level Game Trainer Helper.

Simplifies the multi-step Cheat Engine scanning workflow (first scan -> in-game change -> next scan -> write/freeze)
into clean, foolproof high-level methods for LLMs and automated scripts.
"""
from typing import Dict, Any, Optional, List, Union
import sys
import os

sys.path.append(os.path.dirname(__file__))

from win32_api import parse_address
from game_memory_engine import GameMemoryEngine
from stealth_engine import StealthEngine

class GameTrainer:
    """Manages active game memory sessions, multi-step stat scans, and value modifications."""

    def __init__(self, process_name_or_pid: Optional[Union[str, int]] = None):
        self.engine = GameMemoryEngine()
        self.stealth = StealthEngine(self.engine)
        self.tracked_stats: Dict[str, Dict[str, Any]] = {}
        if process_name_or_pid:
            self.attach(process_name_or_pid)

    def attach(self, process_name_or_pid: Union[str, int]) -> str:
        """Attaches to a game process."""
        res = self.engine.attach(process_name_or_pid)
        if res.get("success"):
            return f"Successfully attached to {res['name']} (PID: {res['pid']}, Arch: {res['architecture']})."
        return f"Failed to attach: {res.get('error')}"

    def scan_stat(self, stat_name: str, value: Union[float, int], data_type: str = "float") -> str:
        """Step 1: Starts a new scan for an in-game stat (e.g. damage=3.5, health=100, gold=50)."""
        if not self.engine.process_handle:
            return "Error: Not attached to any game. Call attach('game.exe') first."

        scan_id = f"stat_{stat_name.lower()}"
        res = self.engine.first_scan(scan_id, data_type, value)

        if not res.get("success"):
            return f"Scan failed: {res.get('error')}"

        count = res["total_matches"]
        self.tracked_stats[stat_name.lower()] = {
            "scan_id": scan_id,
            "data_type": data_type,
            "last_value": value,
            "matches_count": count,
            "resolved_address": None
        }

        if count == 0:
            return f"No memory addresses found matching {value} as {data_type}. Check if the value or data type is correct."
        elif count == 1:
            addr = res["sample_addresses"][0]
            self.tracked_stats[stat_name.lower()]["resolved_address"] = addr
            return f"Found exact unique address for '{stat_name}': {addr}! Ready to modify or freeze."
        else:
            return (
                f"Found {count} candidate addresses for '{stat_name}' = {value}.\n"
                f"-> ACTION REQUIRED: Change the value of '{stat_name}' in-game, then call filter_stat('{stat_name}', new_value)."
            )

    def filter_stat(self, stat_name: str, new_value: Union[float, int], scan_type: str = "exact") -> str:
        """Step 2: Filters down candidate addresses after the in-game value has changed."""
        key = stat_name.lower()
        if key not in self.tracked_stats:
            return f"Error: No active scan found for '{stat_name}'. Call scan_stat first."

        meta = self.tracked_stats[key]
        res = self.engine.next_scan(meta["scan_id"], scan_type, new_value)

        if not res.get("success"):
            return f"Filter failed: {res.get('error')}"

        count = res["total_matches"]
        meta["matches_count"] = count
        meta["last_value"] = new_value

        if count == 0:
            return f"All matches eliminated. The value might be encrypted, stored differently, or changed unexpectedly."
        elif count == 1:
            addr = res["sample_results"][0]["address"]
            meta["resolved_address"] = addr
            return f"SUCCESS: Narrowed down to the exact address for '{stat_name}': {addr} (Current: {new_value}). Ready to modify or freeze!"
        elif count <= 5:
            addrs = [r["address"] for r in res["sample_results"]]
            meta["resolved_address"] = addrs[0]  # candidate primary
            return (
                f"Narrowed down to {count} addresses: {', '.join(addrs)}.\n"
                f"You can filter once more to be 100% sure, or modify them now."
            )
        else:
            return (
                f"Filtered down to {count} matches (down from previous scan).\n"
                f"-> ACTION REQUIRED: Change '{stat_name}' in-game again and call filter_stat('{stat_name}', new_value)."
            )

    def set_stat(self, stat_name: str, new_value: Union[float, int]) -> str:
        """Step 3: Modifies the stat in memory once the address is found."""
        key = stat_name.lower()
        if key not in self.tracked_stats or not self.tracked_stats[key].get("resolved_address"):
            return f"Error: Address for '{stat_name}' is not yet resolved. Complete the scan/filter steps first."

        meta = self.tracked_stats[key]
        addr_int = parse_address(meta["resolved_address"])
        res = self.engine.write_memory(addr_int, meta["data_type"], new_value)

        if res.get("success"):
            return f"Successfully set '{stat_name}' at {meta['resolved_address']} to {new_value}!"
        return f"Failed to write memory: {res.get('error')}"

    def freeze_stat(self, stat_name: str, value: Union[float, int], stealth_mode: bool = True) -> str:
        """Locks/freezes the stat so it never changes in-game (e.g. God Mode, Infinite Ammo)."""
        key = stat_name.lower()
        if key not in self.tracked_stats or not self.tracked_stats[key].get("resolved_address"):
            return f"Error: Address for '{stat_name}' is not yet resolved. Complete the scan/filter steps first."

        meta = self.tracked_stats[key]
        addr_int = parse_address(meta["resolved_address"])

        if stealth_mode:
            res = self.stealth.smart_freeze(addr_int, meta["data_type"], value)
            mode_str = "smart adaptive freeze (stealth)"
        else:
            res = self.engine.freeze_value(addr_int, meta["data_type"], value)
            mode_str = "standard freeze"

        if res.get("success"):
            return f"Successfully locked '{stat_name}' to {value} using {mode_str} at {meta['resolved_address']}!"
        return f"Failed to freeze: {res.get('error')}"

    def unfreeze_stat(self, stat_name: str) -> str:
        """Releases a frozen stat."""
        key = stat_name.lower()
        if key not in self.tracked_stats or not self.tracked_stats[key].get("resolved_address"):
            return f"Error: '{stat_name}' is not tracked."

        addr_int = parse_address(self.tracked_stats[key]["resolved_address"])
        self.stealth.smart_unfreeze(addr_int)
        self.engine.unfreeze_value(addr_int)
        return f"Unfroze '{stat_name}'."
