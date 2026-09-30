"""Stealth memory engine — direct NT syscalls, ephemeral handles,
smart adaptive freezing, automatic page protection restoration, and script obfuscation.
"""
import ctypes
from ctypes import wintypes
import random
import struct
import threading
import time
from typing import Dict, Any, List, Optional, Tuple

from win32_api import (
    kernel32, ntdll,
    NtReadVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory,
    OpenProcess, CloseHandle,
    PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_VM_OPERATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PAGE_EXECUTE_READWRITE, STATUS_SUCCESS,
    PVOID, SIZE_T, ULONG, parse_address
)

class StealthEngine:
    """Low-footprint memory manipulator utilizing direct NTDLL invocations and adaptive polling."""

    def __init__(self, memory_engine):
        self.engine = memory_engine
        self.stealth_mode_enabled = True
        self.use_ephemeral_handles = True
        self.use_direct_nt = True
        self.jitter_min_ms = 40
        self.jitter_max_ms = 120
        self.smart_frozen_values: Dict[int, Dict[str, Any]] = {}
        self._smart_freeze_thread: Optional[threading.Thread] = None
        self._smart_freeze_running = False
        self._lock = threading.Lock()

    def _get_process_handle(self) -> Tuple[Optional[wintypes.HANDLE], bool]:
        """Returns (handle, is_ephemeral).

        If ephemeral handles are enabled, opens a fresh minimal-access handle that must be closed.
        """
        if not self.engine.pid:
            return None, False

        if not self.use_ephemeral_handles and self.engine.process_handle:
            return self.engine.process_handle, False

        access = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_LIMITED_INFORMATION
        h = OpenProcess(access, False, self.engine.pid)
        if not h:
            return self.engine.process_handle, False
        return h, True

    def _release_handle(self, handle: Optional[wintypes.HANDLE], is_ephemeral: bool):
        if is_ephemeral and handle:
            try:
                CloseHandle(handle)
            except Exception:
                pass

    def nt_read(self, address: int, size: int) -> Optional[bytes]:
        """Direct ntdll NtReadVirtualMemory with minimal syscall footprint."""
        handle, is_ephemeral = self._get_process_handle()
        if not handle:
            return None

        try:
            buffer = ctypes.create_string_buffer(size)
            bytes_read = SIZE_T(0)
            status = NtReadVirtualMemory(
                handle,
                PVOID(address),
                buffer,
                SIZE_T(size),
                ctypes.byref(bytes_read)
            )
            if status == STATUS_SUCCESS and bytes_read.value == size:
                return buffer.raw
            return None
        finally:
            self._release_handle(handle, is_ephemeral)

    def nt_write(self, address: int, data: bytes, restore_protection: bool = True) -> bool:
        """Direct ntdll NtWriteVirtualMemory with automatic page protection restoration."""
        handle, is_ephemeral = self._get_process_handle()
        if not handle:
            return False

        try:
            old_protect = ULONG(0)
            base_addr = PVOID(address)
            region_sz = SIZE_T(len(data))
            protection_changed = False

            if restore_protection:
                status = NtProtectVirtualMemory(
                    handle,
                    ctypes.byref(base_addr),
                    ctypes.byref(region_sz),
                    ULONG(PAGE_EXECUTE_READWRITE),
                    ctypes.byref(old_protect)
                )
                if status == STATUS_SUCCESS:
                    protection_changed = True

            buffer = (ctypes.c_char * len(data)).from_buffer_copy(data)
            bytes_written = SIZE_T(0)
            status = NtWriteVirtualMemory(
                handle,
                PVOID(address),
                buffer,
                SIZE_T(len(data)),
                ctypes.byref(bytes_written)
            )
            write_ok = (status == STATUS_SUCCESS and bytes_written.value == len(data))

            if protection_changed and restore_protection:
                base_addr = PVOID(address)
                region_sz = SIZE_T(len(data))
                temp_protect = ULONG(0)
                NtProtectVirtualMemory(
                    handle,
                    ctypes.byref(base_addr),
                    ctypes.byref(region_sz),
                    old_protect,
                    ctypes.byref(temp_protect)
                )

            return write_ok
        finally:
            self._release_handle(handle, is_ephemeral)

    def stealth_write(self, address: int, data_type: str, value: Any, restore_protection: bool = True) -> Dict[str, Any]:
        """Performs a low-footprint typed memory write with protection restoration."""
        try:
            size, fmt = self.engine._type_size_and_format(data_type)
            val_num = float(value) if ('float' in data_type.lower() or 'double' in data_type.lower()) else int(value)
            data = struct.pack(fmt, val_num)
        except Exception as e:
            return {"success": False, "error": f"Invalid type or value: {e}"}

        ok = self.nt_write(address, data, restore_protection=restore_protection)
        if ok:
            return {
                "success": True,
                "address": hex(address),
                "written_value": value,
                "method": "NtWriteVirtualMemory",
                "protection_restored": restore_protection
            }
        return {"success": False, "error": f"NtWriteVirtualMemory failed at {hex(address)}"}

    # -- Smart Adaptive Freezing (Event-Driven Write-on-Change + Jitter) ------

    def smart_freeze(self, address: int, data_type: str, value: Any, min_interval_ms: int = 50, max_interval_ms: int = 150) -> Dict[str, Any]:
        """Freezes an address with low footprint:

        - Only writes when the in-game value deviates from target.
        - Adds randomized sleep jitter across check cycles.
        """
        with self._lock:
            self.smart_frozen_values[address] = {
                "type": data_type,
                "target_value": value,
                "min_ms": min_interval_ms,
                "max_ms": max_interval_ms,
                "writes_count": 0,
                "checks_count": 0
            }
        self._start_smart_freeze_worker()
        return {
            "success": True,
            "address": hex(address),
            "mode": "smart_adaptive_freeze",
            "target_value": value,
            "jitter_range_ms": f"{min_interval_ms}-{max_interval_ms}ms"
        }

    def smart_unfreeze(self, address: int) -> Dict[str, Any]:
        with self._lock:
            if address in self.smart_frozen_values:
                del self.smart_frozen_values[address]
                return {"success": True, "address": hex(address), "smart_unfrozen": True}
        return {"success": False, "error": f"Address {hex(address)} not in smart freeze list"}

    def _start_smart_freeze_worker(self):
        if self._smart_freeze_running:
            return
        self._smart_freeze_running = True
        self._smart_freeze_thread = threading.Thread(target=self._smart_freeze_loop, daemon=True)
        self._smart_freeze_thread.start()

    def _smart_freeze_loop(self):
        while self._smart_freeze_running:
            with self._lock:
                items = list(self.smart_frozen_values.items())

            if not items:
                time.sleep(0.05)
                continue

            min_delay = 1.0
            max_delay = 1.0

            for addr, meta in items:
                try:
                    size, fmt = self.engine._type_size_and_format(meta["type"])
                    raw = self.nt_read(addr, size)
                    if raw:
                        cur_val = struct.unpack(fmt, raw)[0]
                        meta["checks_count"] += 1

                        target = meta["target_value"]
                        if 'float' in meta["type"].lower() or 'double' in meta["type"].lower():
                            needs_write = (abs(cur_val - float(target)) > 0.001)
                        else:
                            needs_write = (cur_val != int(target))

                        if needs_write:
                            self.stealth_write(addr, meta["type"], target, restore_protection=True)
                            meta["writes_count"] += 1
                except Exception:
                    pass

                min_delay = min(min_delay, meta["min_ms"] / 1000.0)
                max_delay = min(max_delay, meta["max_ms"] / 1000.0)

            # Jitter sleep occurs once per cycle across all addresses (prevents starvation)
            delay = random.uniform(min_delay, max_delay)
            time.sleep(delay)

    # -- Obfuscation Utilities ----------------------------------------------

    @staticmethod
    def xor_cipher(data: bytes, key: bytes) -> bytes:
        """Applies repeating-key XOR encryption/decryption."""
        key_len = len(key)
        return bytes([b ^ key[i % key_len] for i, b in enumerate(data)])

    @staticmethod
    def obfuscate_script(script_text: str, key_seed: Optional[int] = None) -> Dict[str, Any]:
        """Obfuscates a script using multi-byte XOR encryption and generates a self-decrypting stub."""
        if key_seed is None:
            key_seed = random.randint(1, 255)

        key = bytes([(key_seed * 7 + i * 13) % 256 for i in range(8)])
        raw_bytes = script_text.encode('utf-8')
        encrypted = StealthEngine.xor_cipher(raw_bytes, key)

        hex_bytes = ", ".join(str(b) for b in encrypted)
        key_bytes = ", ".join(str(k) for k in key)

        # Self-decrypting Lua stub with pure-Lua XOR fallback (no external bit library required)
        lua_stub = f"""
-- Self-Decrypting Obfuscated Lua Payload
local function bxor(a, b)
    local r, m = 0, 1
    while a > 0 or b > 0 do
        if (a % 2) ~= (b % 2) then r = r + m end
        a, b, m = math.floor(a / 2), math.floor(b / 2), m * 2
    end
    return r
end

local encrypted = {{{hex_bytes}}}
local key = {{{key_bytes}}}
local decrypted = {{}}
for i = 1, #encrypted do
    local k = key[((i - 1) % #key) + 1]
    decrypted[i] = string.char(bxor(encrypted[i], k))
end
local code = table.concat(decrypted)
local fn = loadstring and loadstring(code) or load(code)
if fn then return fn() end
"""
        return {
            "success": True,
            "original_length": len(raw_bytes),
            "encrypted_length": len(encrypted),
            "key_hex": key.hex(),
            "lua_self_decrypting_stub": lua_stub
        }
