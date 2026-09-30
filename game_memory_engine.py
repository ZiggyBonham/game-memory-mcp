"""Core game memory engine — process attachment, memory scanning, pointer
resolution, AOB pattern scanning, and value freezing."""
import math
import re
import struct
import threading
import time
from typing import Any, Dict, List, Optional, Tuple, Union

import psutil

from win32_api import (
    MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS,
    PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, PROCESS_VM_WRITE, WRITABLE_PROTECTIONS,
    CloseHandle, IsWow64Process, OpenProcess, ReadProcessMemory,
    VirtualQueryEx, WriteProcessMemory, ctypes, wintypes, parse_address
)

# ---- Data-type Registry (O(1) lookup) -------------------------------------
_TYPE_MAP: Dict[str, Tuple[int, str]] = {}
for _aliases, _sz, _fmt in [
    (('int', 'int32', 'i32'), 4, '<i'),
    (('uint', 'uint32', 'u32'), 4, '<I'),
    (('int64', 'i64', 'long'), 8, '<q'),
    (('uint64', 'u64', 'ulong'), 8, '<Q'),
    (('short', 'int16', 'i16'), 2, '<h'),
    (('ushort', 'uint16', 'u16'), 2, '<H'),
    (('byte', 'uint8', 'u8'), 1, '<B'),
    (('float', 'f32'), 4, '<f'),
    (('double', 'f64'), 8, '<d'),
]:
    for _a in _aliases:
        _TYPE_MAP[_a] = (_sz, _fmt)

_FLOAT_TYPES = frozenset(('float', 'f32', 'double', 'f64'))


def type_size_and_format(data_type: str) -> Tuple[int, str]:
    """Returns (byte_size, struct_format) for a given type name."""
    key = data_type.lower()
    if key in _TYPE_MAP:
        return _TYPE_MAP[key]
    raise ValueError(f"Unsupported data type: '{data_type}'")


def is_float_type(data_type: str) -> bool:
    return data_type.lower() in _FLOAT_TYPES


class ScanSession:
    """Holds state for an ongoing memory-value search."""
    __slots__ = ('data_type', 'matches', 'scan_count')

    def __init__(self, data_type: str):
        self.data_type = data_type
        self.matches: Dict[int, Any] = {}  # address -> last known value
        self.scan_count: int = 0


class GameMemoryEngine:
    """Win32 process memory reader/writer with scanning and freezing."""

    _CHUNK_SIZE = 2 * 1024 * 1024  # 2 MiB read chunks

    def __init__(self):
        self.pid: Optional[int] = None
        self.process_name: Optional[str] = None
        self.process_handle: Optional[wintypes.HANDLE] = None
        self.is_64bit: bool = True
        self.scans: Dict[str, ScanSession] = {}
        self.frozen_values: Dict[int, Dict[str, Any]] = {}
        self._freeze_thread: Optional[threading.Thread] = None
        self._freeze_running = False
        self._lock = threading.Lock()

    @staticmethod
    def _type_size_and_format(data_type: str) -> Tuple[int, str]:
        return type_size_and_format(data_type)

    # -- Process Management -------------------------------------------------

    def list_processes(self, filter_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists running processes matching an optional name filter."""
        results = []
        needle = (filter_name or '').lower()
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
            try:
                name = proc.info['name'] or ''
                if needle and needle not in name.lower():
                    continue
                results.append({
                    "pid": proc.info['pid'],
                    "name": name,
                    "exe": proc.info.get('exe', ''),
                    "username": proc.info.get('username', '')
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return results

    def attach(self, target: Any) -> Dict[str, Any]:
        """Attaches to process by PID (int/str) or executable name."""
        target_pid = None
        target_name = None

        if isinstance(target, int) or (isinstance(target, str) and target.isdigit()):
            target_pid = int(target)
            try:
                target_name = psutil.Process(target_pid).name()
            except Exception as e:
                return {"success": False, "error": f"Failed to find PID {target_pid}: {e}"}
        else:
            target_name = str(target)
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if (proc.info['name'] or '').lower() == target_name.lower():
                        target_pid = proc.info['pid']
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            if not target_pid:
                return {"success": False, "error": f"No process named '{target_name}' found."}

        # Clean up existing handle and freeze state to avoid cross-process pollution
        if self.process_handle:
            try:
                CloseHandle(self.process_handle)
            except Exception:
                pass
            self.process_handle = None

        with self._lock:
            self.frozen_values.clear()

        # Open process
        handle = OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
        if not handle:
            handle = OpenProcess(
                PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                False,
                target_pid
            )

        if not handle:
            err = ctypes.get_last_error()
            return {
                "success": False,
                "error": f"Failed to open process {target_pid} (Error code: {err}). Run with Administrator privileges."
            }

        self.pid = target_pid
        self.process_name = target_name
        self.process_handle = handle

        # Check architecture
        is_wow64 = wintypes.BOOL()
        if IsWow64Process(handle, ctypes.byref(is_wow64)):
            self.is_64bit = not bool(is_wow64.value)
        else:
            self.is_64bit = True

        self.scans.clear()
        self._start_freeze_worker()

        return {
            "success": True,
            "pid": self.pid,
            "name": self.process_name,
            "architecture": "x64" if self.is_64bit else "x86"
        }

    def list_modules(self) -> List[Dict[str, Any]]:
        """Lists loaded modules and their base addresses for the attached process."""
        if not self.pid or not self.process_handle:
            return []
        modules = []
        try:
            import pymem
            pm = pymem.Pymem()
            pm.open_process_from_id(self.pid)
            for mod in pm.list_modules():
                modules.append({
                    "name": mod.name,
                    "base_address": hex(mod.lpBaseOfDll),
                    "size": mod.SizeOfImage
                })
        except Exception:
            try:
                p = psutil.Process(self.pid)
                for m in p.memory_maps():
                    modules.append({
                        "name": m.path.rsplit('\\', 1)[-1] if m.path else "unknown",
                        "base_address": hex(m.addr),
                        "path": m.path
                    })
            except Exception:
                pass
        return modules

    def get_module_base(self, module_name: Optional[str] = None) -> Optional[int]:
        """Gets base address of the main executable or specific module."""
        name = (module_name or self.process_name or '').lower()
        for mod in self.list_modules():
            if mod["name"].lower() == name:
                return int(mod["base_address"], 16)
        return None

    # -- Raw Memory I/O -----------------------------------------------------

    def read_raw(self, address: int, size: int) -> Optional[bytes]:
        """Reads raw bytes from target process memory."""
        if not self.process_handle:
            return None
        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)
        res = ReadProcessMemory(
            self.process_handle,
            ctypes.c_void_p(address),
            buffer,
            size,
            ctypes.byref(bytes_read)
        )
        if res and bytes_read.value == size:
            return buffer.raw
        return None

    def write_raw(self, address: int, data: bytes) -> bool:
        """Writes raw bytes to target process memory."""
        if not self.process_handle:
            return False
        buffer = (ctypes.c_char * len(data)).from_buffer_copy(data)
        bytes_written = ctypes.c_size_t(0)
        res = WriteProcessMemory(
            self.process_handle,
            ctypes.c_void_p(address),
            buffer,
            len(data),
            ctypes.byref(bytes_written)
        )
        return bool(res and bytes_written.value == len(data))

    # -- Pointer Chains -----------------------------------------------------

    def resolve_pointer(self, base_address: int, offsets: List[int]) -> Optional[int]:
        """Traverses a pointer chain: base -> [ptr1] + off1 -> [ptr2] + off2 -> final."""
        current_addr = base_address
        ptr_size = 8 if self.is_64bit else 4
        ptr_format = '<Q' if self.is_64bit else '<I'

        for offset in offsets:
            raw = self.read_raw(current_addr, ptr_size)
            if not raw:
                return None
            val = struct.unpack(ptr_format, raw)[0]
            if val == 0:
                return None
            current_addr = val + offset
        return current_addr

    # -- Typed Memory Access ------------------------------------------------

    def read_memory(self, address: int, data_type: str, offsets: Optional[List[int]] = None) -> Dict[str, Any]:
        """Reads a typed value from an address (resolving optional pointer offsets)."""
        target_addr = address
        if offsets:
            resolved = self.resolve_pointer(address, offsets)
            if resolved is None:
                return {"success": False, "error": "Failed to resolve pointer chain"}
            target_addr = resolved

        if data_type.lower() == 'string':
            raw = self.read_raw(target_addr, 256)
            if not raw:
                return {"success": False, "error": "Failed to read memory"}
            null_pos = raw.find(b'\x00')
            if null_pos != -1:
                raw = raw[:null_pos]
            val_str = raw.decode('utf-8', errors='replace')
            return {"success": True, "address": hex(target_addr), "value": val_str, "type": "string"}

        try:
            size, fmt = type_size_and_format(data_type)
        except ValueError as e:
            return {"success": False, "error": str(e)}

        raw = self.read_raw(target_addr, size)
        if not raw:
            return {"success": False, "error": f"Failed to read {size} bytes at {hex(target_addr)}"}
        val = struct.unpack(fmt, raw)[0]
        return {"success": True, "address": hex(target_addr), "value": val, "type": data_type}

    def write_memory(self, address: int, data_type: str, value: Any, offsets: Optional[List[int]] = None) -> Dict[str, Any]:
        """Writes a typed value to an address (resolving optional pointer offsets)."""
        target_addr = address
        if offsets:
            resolved = self.resolve_pointer(address, offsets)
            if resolved is None:
                return {"success": False, "error": "Failed to resolve pointer chain"}
            target_addr = resolved

        if data_type.lower() == 'string':
            data = str(value).encode('utf-8') + b'\x00'
        else:
            try:
                size, fmt = type_size_and_format(data_type)
                val_num = float(value) if is_float_type(data_type) else int(value)
                data = struct.pack(fmt, val_num)
            except Exception as e:
                return {"success": False, "error": f"Invalid value or data type: {e}"}

        if self.write_raw(target_addr, data):
            return {"success": True, "address": hex(target_addr), "written_value": value}
        return {"success": False, "error": f"Failed to write to {hex(target_addr)}"}

    # -- Memory Scanning Engine ---------------------------------------------

    def first_scan(self, scan_id: str, data_type: str, target_value: Any, max_matches: int = 50000) -> Dict[str, Any]:
        """Performs initial memory scan across committed writable memory pages."""
        if not self.process_handle:
            return {"success": False, "error": "No process attached"}

        try:
            size, fmt = type_size_and_format(data_type)
            target = float(target_value) if is_float_type(data_type) else int(target_value)
            packed_target = struct.pack(fmt, target)
        except Exception as e:
            return {"success": False, "error": f"Invalid scan parameters: {e}"}

        session = ScanSession(data_type=data_type)
        mbi = MEMORY_BASIC_INFORMATION()
        current_addr = 0

        while VirtualQueryEx(self.process_handle, ctypes.c_void_p(current_addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            if mbi.RegionSize == 0:
                break

            if (mbi.State == MEM_COMMIT) and (mbi.Protect & WRITABLE_PROTECTIONS) and not (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)):
                region_size = mbi.RegionSize
                chunk_size = min(region_size, self._CHUNK_SIZE)
                offset = 0

                while offset < region_size:
                    to_read = min(chunk_size, region_size - offset)
                    base_chunk = mbi.BaseAddress + offset
                    data = self.read_raw(base_chunk, to_read)

                    if data:
                        pos = 0
                        while True:
                            pos = data.find(packed_target, pos)
                            if pos == -1:
                                break
                            if pos % size == 0:
                                match_addr = base_chunk + pos
                                session.matches[match_addr] = target
                                if len(session.matches) >= max_matches:
                                    break
                                pos += size
                            else:
                                pos += 1

                    if len(session.matches) >= max_matches:
                        break
                    offset += to_read

            if len(session.matches) >= max_matches:
                break
            current_addr = mbi.BaseAddress + mbi.RegionSize

        session.scan_count = 1
        self.scans[scan_id] = session

        sample = [hex(a) for a in list(session.matches.keys())[:20]]
        return {
            "success": True,
            "scan_id": scan_id,
            "total_matches": len(session.matches),
            "sample_addresses": sample,
            "hit_limit": len(session.matches) >= max_matches
        }

    def next_scan(self, scan_id: str, scan_type: str = "exact", target_value: Optional[Any] = None) -> Dict[str, Any]:
        """Filters previous scan matches."""
        if scan_id not in self.scans:
            return {"success": False, "error": f"Scan session '{scan_id}' not found"}

        session = self.scans[scan_id]
        size, fmt = type_size_and_format(session.data_type)
        is_float = is_float_type(session.data_type)

        target = None
        if target_value is not None:
            try:
                target = float(target_value) if is_float else int(target_value)
            except (ValueError, TypeError) as e:
                return {"success": False, "error": f"Invalid target_value: {e}"}

        new_matches: Dict[int, Any] = {}
        st = scan_type.lower()

        for addr, prev_val in session.matches.items():
            raw = self.read_raw(addr, size)
            if not raw:
                continue
            cur_val = struct.unpack(fmt, raw)[0]

            keep = False
            if st == "exact":
                keep = math.isclose(cur_val, target, abs_tol=1e-4) if is_float else (cur_val == target)
            elif st == "increased":
                if target is None:
                    keep = (cur_val > prev_val)
                else:
                    keep = math.isclose(cur_val, prev_val + target, abs_tol=1e-4) if is_float else (cur_val == prev_val + target)
            elif st == "decreased":
                if target is None:
                    keep = (cur_val < prev_val)
                else:
                    keep = math.isclose(cur_val, prev_val - target, abs_tol=1e-4) if is_float else (cur_val == prev_val - target)
            elif st == "changed":
                keep = not math.isclose(cur_val, prev_val, abs_tol=1e-4) if is_float else (cur_val != prev_val)
            elif st == "unchanged":
                keep = math.isclose(cur_val, prev_val, abs_tol=1e-4) if is_float else (cur_val == prev_val)

            if keep:
                new_matches[addr] = cur_val

        session.matches = new_matches
        session.scan_count += 1

        sample = [
            {"address": hex(a), "current_value": v}
            for a, v in list(session.matches.items())[:20]
        ]

        return {
            "success": True,
            "scan_id": scan_id,
            "total_matches": len(session.matches),
            "scan_count": session.scan_count,
            "sample_results": sample
        }

    # -- High-Performance AOB Pattern Scanner -------------------------------

    def pattern_scan(self, pattern: str, module_name: Optional[str] = None) -> Dict[str, Any]:
        """AOB pattern scan with wildcards ('??' or '?') using compiled regex for speed."""
        if not self.process_handle:
            return {"success": False, "error": "No process attached"}

        tokens = pattern.strip().split()
        if not tokens:
            return {"success": False, "error": "Empty pattern"}

        regex_parts = []
        has_wildcards = False
        try:
            for t in tokens:
                if t in ('?', '??'):
                    regex_parts.append(b'.')
                    has_wildcards = True
                else:
                    byte_val = int(t, 16)
                    regex_parts.append(re.escape(bytes([byte_val])))
        except ValueError as e:
            return {"success": False, "error": f"Invalid hex in pattern: {e}"}

        compiled_regex = re.compile(b''.join(regex_parts), re.DOTALL)

        if module_name:
            base_addr = self.get_module_base(module_name) or 0
            current_addr = base_addr
            max_scan_addr = base_addr + 0x20000000
        else:
            current_addr = 0
            max_scan_addr = 0x7FFFFFFF0000 if self.is_64bit else 0xFFFFFFFF
        mbi = MEMORY_BASIC_INFORMATION()
        matches = []

        while VirtualQueryEx(self.process_handle, ctypes.c_void_p(current_addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            if mbi.RegionSize == 0:
                break

            if (mbi.State == MEM_COMMIT) and not (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)):
                # Chunked reading to avoid MemoryError on huge regions
                region_size = mbi.RegionSize
                chunk_size = min(region_size, self._CHUNK_SIZE)
                offset = 0

                while offset < region_size:
                    to_read = min(chunk_size, region_size - offset)
                    data = self.read_raw(mbi.BaseAddress + offset, to_read)
                    if data:
                        for m in compiled_regex.finditer(data):
                            matches.append(hex(mbi.BaseAddress + offset + m.start()))
                            if len(matches) >= 50:
                                break
                    if len(matches) >= 50:
                        break
                    # Overlap slightly for boundary patterns
                    offset += max(1, to_read - len(tokens))

            if len(matches) >= 50 or current_addr > max_scan_addr:
                break
            current_addr = mbi.BaseAddress + mbi.RegionSize

        return {
            "success": True,
            "pattern": pattern,
            "matches_found": len(matches),
            "addresses": matches
        }

    # -- Value Freezing -----------------------------------------------------

    def freeze_value(self, address: int, data_type: str, value: Any, interval_ms: int = 50) -> Dict[str, Any]:
        """Freezes an address so its value is constantly rewritten."""
        with self._lock:
            self.frozen_values[address] = {
                "type": data_type,
                "value": value,
                "interval": max(10, interval_ms) / 1000.0,
                "last_written": 0.0
            }
        return {"success": True, "address": hex(address), "frozen_to": value}

    def unfreeze_value(self, address: int) -> Dict[str, Any]:
        with self._lock:
            if address in self.frozen_values:
                del self.frozen_values[address]
                return {"success": True, "address": hex(address), "unfrozen": True}
        return {"success": False, "error": f"Address {hex(address)} is not frozen"}

    def list_frozen(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                {"address": hex(addr), "type": meta["type"], "value": meta["value"]}
                for addr, meta in self.frozen_values.items()
            ]

    def _start_freeze_worker(self):
        if self._freeze_running:
            return
        self._freeze_running = True
        self._freeze_thread = threading.Thread(target=self._freeze_loop, daemon=True)
        self._freeze_thread.start()

    def _freeze_loop(self):
        while self._freeze_running:
            now = time.monotonic()
            with self._lock:
                items = list(self.frozen_values.items())

            if not items:
                time.sleep(0.05)
                continue

            for addr, meta in items:
                if now - meta.get("last_written", 0.0) >= meta["interval"]:
                    try:
                        self.write_memory(addr, meta["type"], meta["value"])
                        meta["last_written"] = now
                    except Exception:
                        pass

            time.sleep(0.01)
