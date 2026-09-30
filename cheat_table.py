"""Cheat Engine .CT table parser, address resolver, and value activator."""
import xml.etree.ElementTree as ET
import os
import re
from typing import Dict, List, Any, Optional

from win32_api import parse_address

class CheatEntry:
    def __init__(self):
        self.id: str = ""
        self.description: str = ""
        self.var_type: str = "4 Bytes"
        self.address_expr: str = ""
        self.offsets: List[int] = []
        self.script: Optional[str] = None
        self.is_script: bool = False
        self.active: bool = False
        self.resolved_address: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "variable_type": self.var_type,
            "address_expression": self.address_expr,
            "offsets": [hex(o) if o >= 0 else f"-{hex(-o)}" for o in self.offsets],
            "is_script": self.is_script,
            "active": self.active,
            "resolved_address": hex(self.resolved_address) if self.resolved_address else None
        }


class CheatTableParser:
    """Parses Cheat Engine XML (.CT) files, resolves pointers, and manipulates values."""

    def __init__(self, memory_engine):
        self.engine = memory_engine
        self.tables: Dict[str, Dict[str, Any]] = {}

    def _map_ce_type(self, ce_type: str) -> str:
        """Maps Cheat Engine variable types to memory engine types."""
        t = (ce_type or "").lower().strip()
        if "4 byte" in t or "dword" in t or "int32" in t:
            return "int32"
        elif "8 byte" in t or "qword" in t or "int64" in t:
            return "int64"
        elif "2 byte" in t or "word" in t or "int16" in t:
            return "int16"
        elif "float" in t or "single" in t:
            return "float"
        elif "double" in t:
            return "double"
        elif "string" in t or "text" in t:
            return "string"
        elif "byte" in t or "uint8" in t:
            return "byte"
        return "int32"

    def parse_ct(self, table_id: str, file_path_or_xml: str) -> Dict[str, Any]:
        """Parses a Cheat Engine .CT XML file or string."""
        xml_content = file_path_or_xml
        if os.path.exists(file_path_or_xml):
            with open(file_path_or_xml, "r", encoding="utf-8", errors="ignore") as f:
                xml_content = f.read()

        try:
            root = ET.fromstring(xml_content)
        except Exception as e:
            return {"success": False, "error": f"XML parse error: {e}"}

        entries: Dict[str, CheatEntry] = {}
        lua_script = None

        # Check for global LuaScript tag
        lua_elem = root.find("LuaScript")
        if lua_elem is not None and lua_elem.text:
            lua_script = lua_elem.text.strip()

        # Parse CheatEntries
        idx_counter = 1
        for ce_elem in root.iter("CheatEntry"):
            entry = CheatEntry()

            id_elem = ce_elem.find("ID")
            if id_elem is not None and id_elem.text:
                entry.id = id_elem.text.strip()
            else:
                entry.id = str(idx_counter)
            idx_counter += 1

            desc_elem = ce_elem.find("Description")
            if desc_elem is not None and desc_elem.text:
                entry.description = desc_elem.text.strip('"')

            vt_elem = ce_elem.find("VariableType")
            if vt_elem is not None and vt_elem.text:
                entry.var_type = vt_elem.text.strip()

            if "script" in entry.var_type.lower():
                entry.is_script = True
                script_elem = ce_elem.find("AssemblerScript")
                if script_elem is not None and script_elem.text:
                    entry.script = script_elem.text

            addr_elem = ce_elem.find("Address")
            if addr_elem is not None and addr_elem.text:
                entry.address_expr = addr_elem.text.strip()

            # Parse Offsets (Cheat Engine lists offsets bottom-level to top-level)
            offsets_elem = ce_elem.find("Offsets")
            if offsets_elem is not None:
                offset_list = []
                for off in offsets_elem.findall("Offset"):
                    if off.text:
                        val_str = off.text.strip()
                        try:
                            if val_str.startswith('-'):
                                val = -int(val_str[1:], 16)
                            else:
                                val = int(val_str, 16)
                            offset_list.append(val)
                        except ValueError:
                            pass
                entry.offsets = list(reversed(offset_list))

            entries[entry.id] = entry

        self.tables[table_id] = {
            "entries": entries,
            "lua_script": lua_script
        }

        return {
            "success": True,
            "table_id": table_id,
            "total_entries": len(entries),
            "has_lua_script": bool(lua_script)
        }

    def resolve_entry_address(self, entry: CheatEntry) -> Optional[int]:
        """Resolves module-relative and hex address expressions with pointer chains."""
        if not entry.address_expr or entry.is_script:
            return None

        expr = entry.address_expr.strip()

        # Handle module relative (e.g. "game.exe"+1234, "game.exe"-50, "UnityPlayer.dll"+5678)
        mod_match = re.match(r'^["\']?([^"\'+-]+)["\']?\s*([+-])\s*([0-9a-fA-F]+)$', expr)
        if mod_match:
            mod_name, sign, offset_hex = mod_match.groups()
            base = self.engine.get_module_base(mod_name)
            if base is None:
                return None
            off_val = int(offset_hex, 16)
            base_addr = (base + off_val) if sign == '+' else (base - off_val)
        else:
            try:
                base_addr = parse_address(expr)
            except Exception:
                return None

        if entry.offsets:
            return self.engine.resolve_pointer(base_addr, entry.offsets)
        return base_addr

    def list_entries(self, table_id: str) -> List[Dict[str, Any]]:
        """Lists all cheat entries with their live resolved addresses and current memory values."""
        if table_id not in self.tables:
            return []
        res = []
        for entry in self.tables[table_id]["entries"].values():
            entry.resolved_address = self.resolve_entry_address(entry)
            d = entry.to_dict()
            if entry.resolved_address and not entry.is_script:
                dtype = self._map_ce_type(entry.var_type)
                val_res = self.engine.read_memory(entry.resolved_address, dtype)
                d["current_value"] = val_res.get("value")
            res.append(d)
        return res

    def set_entry_value(self, table_id: str, entry_id: str, value: Any, freeze: bool = False) -> Dict[str, Any]:
        """Sets or freezes value for a cheat table entry."""
        if table_id not in self.tables or entry_id not in self.tables[table_id]["entries"]:
            return {"success": False, "error": f"Entry '{entry_id}' not found in table '{table_id}'"}

        entry = self.tables[table_id]["entries"][entry_id]
        addr = self.resolve_entry_address(entry)
        if addr is None:
            return {"success": False, "error": f"Could not resolve address for {entry.description}"}

        dtype = self._map_ce_type(entry.var_type)

        if freeze:
            res = self.engine.freeze_value(addr, dtype, value)
            entry.active = True
            return {"success": True, "action": "frozen", "address": hex(addr), "value": value}
        else:
            res = self.engine.write_memory(addr, dtype, value)
            return {"success": res.get("success", False), "action": "written", "address": hex(addr), "written_value": value}
