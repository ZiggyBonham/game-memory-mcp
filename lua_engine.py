"""Lua Scripting Runtime with Cheat Engine API bindings and remote script execution."""
import ctypes
from typing import Dict, Any, List, Optional
import lupa

from win32_api import parse_address

class LuaEngine:
    """Provides an embedded LuaJIT runtime with Cheat Engine compatible globals."""

    def __init__(self, memory_engine):
        self.engine = memory_engine
        self.logs: List[str] = []
        self._lua_runtime: Optional[lupa.LuaRuntime] = None

    def _get_or_create_lua_env(self) -> lupa.LuaRuntime:
        """Returns the persistent Lua runtime with Cheat Engine bindings."""
        if self._lua_runtime is not None:
            return self._lua_runtime

        lua = lupa.LuaRuntime(unpack_returned_tuples=True)

        def lua_log(*args):
            msg = " ".join(str(a) for a in args)
            self.logs.append(msg)

        def read_integer(address):
            addr_int = parse_address(address)
            res = self.engine.read_memory(addr_int, "int32")
            return res.get("value")

        def write_integer(address, value):
            addr_int = parse_address(address)
            res = self.engine.write_memory(addr_int, "int32", int(value))
            return res.get("success", False)

        def read_qword(address):
            addr_int = parse_address(address)
            res = self.engine.read_memory(addr_int, "int64")
            return res.get("value")

        def write_qword(address, value):
            addr_int = parse_address(address)
            res = self.engine.write_memory(addr_int, "int64", int(value))
            return res.get("success", False)

        def read_float(address):
            addr_int = parse_address(address)
            res = self.engine.read_memory(addr_int, "float")
            return res.get("value")

        def write_float(address, value):
            addr_int = parse_address(address)
            res = self.engine.write_memory(addr_int, "float", float(value))
            return res.get("success", False)

        def read_double(address):
            addr_int = parse_address(address)
            res = self.engine.read_memory(addr_int, "double")
            return res.get("value")

        def write_double(address, value):
            addr_int = parse_address(address)
            res = self.engine.write_memory(addr_int, "double", float(value))
            return res.get("success", False)

        def read_string(address):
            addr_int = parse_address(address)
            res = self.engine.read_memory(addr_int, "string")
            return res.get("value")

        def write_string(address, value):
            addr_int = parse_address(address)
            res = self.engine.write_memory(addr_int, "string", str(value))
            return res.get("success", False)

        def freeze_address(address, data_type, value):
            addr_int = parse_address(address)
            res = self.engine.freeze_value(addr_int, str(data_type), value)
            return res.get("success", False)

        def unfreeze_address(address):
            addr_int = parse_address(address)
            res = self.engine.unfreeze_value(addr_int)
            return res.get("success", False)

        def get_module_base(name):
            base = self.engine.get_module_base(name)
            return hex(base) if base else None

        # Expose globals to Lua environment
        globals = lua.globals()
        globals.print = lua_log
        globals.readInteger = read_integer
        globals.writeInteger = write_integer
        globals.readQword = read_qword
        globals.writeQword = write_qword
        globals.readFloat = read_float
        globals.writeFloat = write_float
        globals.readDouble = read_double
        globals.writeDouble = write_double
        globals.readString = read_string
        globals.writeString = write_string
        globals.freeze = freeze_address
        globals.unfreeze = unfreeze_address
        globals.getModuleBase = get_module_base

        self._lua_runtime = lua
        return lua

    def execute_script(self, script_code: str) -> Dict[str, Any]:
        """Runs a Lua script with Cheat Engine compatibility functions."""
        self.logs.clear()
        try:
            lua = self._get_or_create_lua_env()
            result = lua.execute(script_code)
            return {
                "success": True,
                "result": str(result) if result is not None else None,
                "logs": list(self.logs)
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Lua execution error: {e}",
                "logs": list(self.logs)
            }

    def inject_remote_lua(self, script_code: str, lua_module: str = "lua51.dll") -> Dict[str, Any]:
        """Validates remote Lua execution prerequisites in games embedding Lua runtimes."""
        if not self.engine.process_handle:
            return {"success": False, "error": "No process attached"}

        base = self.engine.get_module_base(lua_module)
        if not base:
            return {
                "success": False,
                "error": f"Module '{lua_module}' not found in target process. Use list_modules() to check loaded libraries."
            }

        return {
            "success": True,
            "message": f"Module '{lua_module}' detected at base {hex(base)}. In-game Lua scripts can be executed using memory hooks or pattern-scanned lua_State pointers.",
            "module_base": hex(base)
        }
