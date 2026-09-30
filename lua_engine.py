import ctypes
from ctypes import wintypes
import os
from typing import Dict, Any, List, Optional
import lupa

from dll_injector import (
    VirtualAllocEx, VirtualFreeEx, CreateRemoteThread, WaitForSingleObject,
    GetProcAddress, GetModuleHandleW, CloseHandle,
    MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, PAGE_READWRITE
)

class LuaEngine:
    def __init__(self, memory_engine):
        self.engine = memory_engine
        self.logs: List[str] = []

    def _create_lua_env(self) -> lupa.LuaRuntime:
        lua = lupa.LuaRuntime(unpack_returned_tuples=True)
        self.logs = []

        # Helper to parse hex/int addr
        def to_addr(addr):
            if isinstance(addr, str):
                return int(addr, 16) if addr.startswith(('0x', '0X')) else int(addr)
            return int(addr)

        # CE Compatibility Functions
        def lua_log(*args):
            msg = " ".join(str(a) for a in args)
            self.logs.append(msg)

        def read_integer(address):
            res = self.engine.read_memory(to_addr(address), "int32")
            return res.get("value")

        def write_integer(address, value):
            res = self.engine.write_memory(to_addr(address), "int32", value)
            return res.get("success", False)

        def read_qword(address):
            res = self.engine.read_memory(to_addr(address), "int64")
            return res.get("value")

        def write_qword(address, value):
            res = self.engine.write_memory(to_addr(address), "int64", value)
            return res.get("success", False)

        def read_float(address):
            res = self.engine.read_memory(to_addr(address), "float")
            return res.get("value")

        def write_float(address, value):
            res = self.engine.write_memory(to_addr(address), "float", value)
            return res.get("success", False)

        def read_double(address):
            res = self.engine.read_memory(to_addr(address), "double")
            return res.get("value")

        def write_double(address, value):
            res = self.engine.write_memory(to_addr(address), "double", value)
            return res.get("success", False)

        def read_string(address):
            res = self.engine.read_memory(to_addr(address), "string")
            return res.get("value")

        def write_string(address, value):
            res = self.engine.write_memory(to_addr(address), "string", value)
            return res.get("success", False)

        def freeze_address(address, data_type, value):
            res = self.engine.freeze_value(to_addr(address), str(data_type), value)
            return res.get("success", False)

        def unfreeze_address(address):
            res = self.engine.unfreeze_value(to_addr(address))
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

        return lua

    def execute_script(self, script_code: str) -> Dict[str, Any]:
        """Runs a Lua script with game memory and Cheat Engine bindings."""
        try:
            lua = self._create_lua_env()
            result = lua.execute(script_code)
            return {
                "success": True,
                "result": str(result) if result is not None else None,
                "logs": self.logs
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Lua execution error: {e}",
                "logs": self.logs
            }

    def inject_remote_lua(self, script_code: str, lua_module: str = "lua51.dll") -> Dict[str, Any]:
        """
        Executes Lua code inside target games that embed a Lua runtime (e.g. lua51.dll, luajit.dll).
        Uses luaL_dostring in the remote process.
        """
        if not self.engine.process_handle:
            return {"success": False, "error": "No process attached"}

        # Find module
        base = self.engine.get_module_base(lua_module)
        if not base:
            return {"success": False, "error": f"Module '{lua_module}' not found in target process"}

        script_bytes = script_code.encode('utf-8') + b'\x00'
        script_len = len(script_bytes)

        # Allocate memory for script in target
        remote_mem = VirtualAllocEx(
            self.engine.process_handle,
            None,
            script_len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        )

        if not remote_mem:
            return {"success": False, "error": "Failed to allocate memory in target process"}

        try:
            from game_memory_engine import WriteProcessMemory
            bytes_written = ctypes.c_size_t(0)
            buffer = (ctypes.c_char * script_len).from_buffer_copy(script_bytes)
            WriteProcessMemory(
                self.engine.process_handle,
                remote_mem,
                buffer,
                script_len,
                ctypes.byref(bytes_written)
            )

            # Locate exported luaL_dostring function in remote module
            # We load the module locally to locate export offset
            h_local = ctypes.windll.kernel32.LoadLibraryW(lua_module)
            if not h_local:
                return {"success": False, "error": f"Could not inspect {lua_module} export table"}

            dostring_addr = GetProcAddress(h_local, b"luaL_dostring")
            if not dostring_addr:
                dostring_addr = GetProcAddress(h_local, b"luaL_loadstring")

            if not dostring_addr:
                return {"success": False, "error": "Could not find luaL_dostring export"}

            # Calculate remote function address
            offset = dostring_addr - h_local
            remote_fn = base + offset

            # Execute remote thread
            thread_id = wintypes.DWORD(0)
            h_thread = CreateRemoteThread(
                self.engine.process_handle,
                None,
                0,
                ctypes.c_void_p(remote_fn),
                remote_mem,
                0,
                ctypes.byref(thread_id)
            )

            if not h_thread:
                err = ctypes.get_last_error()
                return {"success": False, "error": f"CreateRemoteThread failed (Error {err})"}

            WaitForSingleObject(h_thread, 3000)
            CloseHandle(h_thread)

            return {
                "success": True,
                "message": f"Injected and executed Lua script via {lua_module}!luaL_dostring"
            }

        finally:
            VirtualFreeEx(self.engine.process_handle, remote_mem, 0, MEM_RELEASE)
