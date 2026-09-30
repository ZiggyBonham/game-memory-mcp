import ctypes
from ctypes import wintypes
import struct
import threading
import time
from typing import Dict, List, Optional, Tuple, Any
import psutil

# Win32 Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100

class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong),
        ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", wintypes.DWORD),
        ("Alignment1", wintypes.DWORD),
        ("RegionSize", ctypes.c_ulonglong),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("Alignment2", wintypes.DWORD),
    ]

# Win32 API functions
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

OpenProcess = kernel32.OpenProcess
OpenProcess.restype = wintypes.HANDLE
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

CloseHandle = kernel32.CloseHandle
CloseHandle.restype = wintypes.BOOL
CloseHandle.argtypes = [wintypes.HANDLE]

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.restype = wintypes.BOOL
ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t)
]

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.restype = wintypes.BOOL
WriteProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.LPCVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t)
]

VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.restype = ctypes.c_size_t
VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION64),
    ctypes.c_size_t
]

IsWow64Process = kernel32.IsWow64Process
IsWow64Process.restype = wintypes.BOOL
IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]


class ScanSession:
    def __init__(self, data_type: str):
        self.data_type = data_type
        self.matches: Dict[int, Any] = {} # address -> last_val
        self.scan_count = 0


class GameMemoryEngine:
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

    def list_processes(self, filter_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists running processes matching an optional name filter."""
        results = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
            try:
                name = proc.info['name'] or ''
                if filter_name and filter_name.lower() not in name.lower():
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
        """Attaches to process by PID (int) or process name (str)."""
        target_pid = None
        target_name = None

        if isinstance(target, int) or (isinstance(target, str) and target.isdigit()):
            target_pid = int(target)
            try:
                p = psutil.Process(target_pid)
                target_name = p.name()
            except Exception as e:
                return {"success": False, "error": f"Failed to find PID {target_pid}: {e}"}
        else:
            target_name = str(target)
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'] and proc.info['name'].lower() == target_name.lower():
                        target_pid = proc.info['pid']
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            if not target_pid:
                return {"success": False, "error": f"No process named '{target_name}' found."}

        # Close existing handle if attached
        if self.process_handle:
            try:
                CloseHandle(self.process_handle)
            except Exception:
                pass
            self.process_handle = None

        # Open process
        handle = OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
        if not handle:
            # Fallback with less permissions if ALL_ACCESS denied
            handle = OpenProcess(
                PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                False,
                target_pid
            )

        if not handle:
            err = ctypes.get_last_error()
            return {
                "success": False,
                "error": f"Failed to open process {target_pid} (Error code: {err}). Run with Admin privileges if needed."
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
            # Fallback via psutil memory maps
            try:
                p = psutil.Process(self.pid)
                for m in p.memory_maps():
                    modules.append({
                        "name": m.path.split('\\')[-1] if m.path else "unknown",
                        "base_address": hex(m.addr),
                        "path": m.path
                    })
            except Exception:
                pass
        return modules

    def get_module_base(self, module_name: Optional[str] = None) -> Optional[int]:
        """Gets base address of the main executable or specific module."""
        if not module_name:
            module_name = self.process_name
        for mod in self.list_modules():
            if mod["name"].lower() == (module_name or '').lower():
                return int(mod["base_address"], 16)
        return None

    def _type_size_and_format(self, data_type: str) -> Tuple[int, str]:
        t = data_type.lower()
        if t in ('int', 'int32', 'i32'):
            return 4, '<i'
        elif t in ('uint', 'uint32', 'u32'):
            return 4, '<I'
        elif t in ('int64', 'i64', 'long'):
            return 8, '<q'
        elif t in ('uint64', 'u64', 'ulong'):
            return 8, '<Q'
        elif t in ('short', 'int16', 'i16'):
            return 2, '<h'
        elif t in ('ushort', 'uint16', 'u16'):
            return 2, '<H'
        elif t in ('byte', 'uint8', 'u8'):
            return 1, '<B'
        elif t in ('float', 'f32'):
            return 4, '<f'
        elif t in ('double', 'f64'):
            return 8, '<d'
        else:
            raise ValueError(f"Unsupported data type: {data_type}")

    def read_raw(self, address: int, size: int) -> Optional[bytes]:
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

    def resolve_pointer(self, base_address: int, offsets: List[int]) -> Optional[int]:
        """Traverses a pointer chain: base -> ptr1 + offset1 -> ptr2 + offset2 -> final address."""
        current_addr = base_address
        ptr_size = 8 if self.is_64bit else 4
        ptr_format = '<Q' if self.is_64bit else '<I'

        for i, offset in enumerate(offsets):
            raw = self.read_raw(current_addr, ptr_size)
            if not raw:
                return None
            val = struct.unpack(ptr_format, raw)[0]
            if val == 0:
                return None
            current_addr = val + offset
        return current_addr

    def read_memory(self, address: int, data_type: str, offsets: Optional[List[int]] = None) -> Dict[str, Any]:
        """Reads a typed value from an address (resolving optional pointer offsets)."""
        target_addr = address
        if offsets:
            resolved = self.resolve_pointer(address, offsets)
            if resolved is None:
                return {"success": False, "error": "Failed to resolve pointer chain"}
            target_addr = resolved

        if data_type.lower() == 'string':
            raw = self.read_raw(target_addr, 64)
            if not raw:
                return {"success": False, "error": "Failed to read memory"}
            null_pos = raw.find(b'\x00')
            if null_pos != -1:
                raw = raw[:null_pos]
            val_str = raw.decode('utf-8', errors='ignore')
            return {"success": True, "address": hex(target_addr), "value": val_str, "type": "string"}

        size, fmt = self._type_size_and_format(data_type)
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
            size, fmt = self._type_size_and_format(data_type)
            if 'float' in data_type.lower() or 'double' in data_type.lower():
                val_num = float(value)
            else:
                val_num = int(value)
            data = struct.pack(fmt, val_num)

        if self.write_raw(target_addr, data):
            return {"success": True, "address": hex(target_addr), "written_value": value}
        else:
            return {"success": False, "error": f"Failed to write to {hex(target_addr)}"}

    def first_scan(self, scan_id: str, data_type: str, target_value: Any, max_matches: int = 50000) -> Dict[str, Any]:
        """Performs initial memory scan across committed writable memory pages."""
        if not self.process_handle:
            return {"success": False, "error": "No process attached"}

        size, fmt = self._type_size_and_format(data_type)
        if 'float' in data_type.lower() or 'double' in data_type.lower():
            target = float(target_value)
        else:
            target = int(target_value)
        packed_target = struct.pack(fmt, target)

        session = ScanSession(data_type=data_type)
        mbi = MEMORY_BASIC_INFORMATION64()
        current_addr = 0
        total_scanned_bytes = 0

        # Writable memory protections
        valid_protects = PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY

        while VirtualQueryEx(self.process_handle, ctypes.c_void_p(current_addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            if (mbi.State == MEM_COMMIT) and (mbi.Protect & valid_protects) and not (mbi.Protect & PAGE_GUARD) and not (mbi.Protect & PAGE_NOACCESS):
                region_size = mbi.RegionSize
                # Read page in chunks (up to 2MB)
                chunk_size = min(region_size, 2 * 1024 * 1024)
                offset = 0
                while offset < region_size:
                    to_read = min(chunk_size, region_size - offset)
                    base_chunk = mbi.BaseAddress + offset
                    data = self.read_raw(base_chunk, to_read)
                    if data:
                        total_scanned_bytes += len(data)
                        # Scan through data
                        pos = 0
                        while True:
                            pos = data.find(packed_target, pos)
                            if pos == -1:
                                break
                            # Ensure alignment
                            if pos % size == 0:
                                match_addr = base_chunk + pos
                                session.matches[match_addr] = target
                                if len(session.matches) >= max_matches:
                                    break
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
        """
        Filters previous scan matches.
        scan_type options: 'exact', 'increased', 'decreased', 'changed', 'unchanged'
        """
        if scan_id not in self.scans:
            return {"success": False, "error": f"Scan session '{scan_id}' not found"}

        session = self.scans[scan_id]
        size, fmt = self._type_size_and_format(session.data_type)

        target = None
        if target_value is not None:
            if 'float' in session.data_type.lower() or 'double' in session.data_type.lower():
                target = float(target_value)
            else:
                target = int(target_value)

        new_matches: Dict[int, Any] = {}

        for addr, prev_val in session.matches.items():
            raw = self.read_raw(addr, size)
            if not raw:
                continue
            cur_val = struct.unpack(fmt, raw)[0]

            keep = False
            st = scan_type.lower()
            if st == "exact":
                keep = (cur_val == target)
            elif st == "increased":
                keep = (cur_val > prev_val) if target is None else (cur_val == prev_val + target)
            elif st == "decreased":
                keep = (cur_val < prev_val) if target is None else (cur_val == prev_val - target)
            elif st == "changed":
                keep = (cur_val != prev_val)
            elif st == "unchanged":
                keep = (cur_val == prev_val)

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

    def pattern_scan(self, pattern: str, module_name: Optional[str] = None) -> Dict[str, Any]:
        """
        AOB (Array of Bytes) pattern scan with wildcards ('??' or '?').
        Example pattern: '48 8B 05 ?? ?? ?? ?? 48 85 C0'
        """
        if not self.process_handle:
            return {"success": False, "error": "No process attached"}

        tokens = pattern.strip().split()
        byte_pattern = []
        mask = []
        for t in tokens:
            if t == '?' or t == '??':
                byte_pattern.append(0)
                mask.append(False)
            else:
                byte_pattern.append(int(t, 16))
                mask.append(True)

        pat_len = len(byte_pattern)
        pat_bytes = bytes(byte_pattern)

        # Determine scan range (module or whole memory)
        base_addr = self.get_module_base(module_name) or 0
        current_addr = base_addr
        mbi = MEMORY_BASIC_INFORMATION64()

        matches = []

        while VirtualQueryEx(self.process_handle, ctypes.c_void_p(current_addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            if (mbi.State == MEM_COMMIT) and not (mbi.Protect & PAGE_GUARD) and not (mbi.Protect & PAGE_NOACCESS):
                data = self.read_raw(mbi.BaseAddress, mbi.RegionSize)
                if data:
                    data_len = len(data)
                    for i in range(data_len - pat_len):
                        match = True
                        for j in range(pat_len):
                            if mask[j] and data[i + j] != pat_bytes[j]:
                                match = False
                                break
                        if match:
                            matches.append(hex(mbi.BaseAddress + i))
                            if len(matches) >= 50:
                                break
            if len(matches) >= 50 or (module_name and current_addr > base_addr + 0x20000000):
                break
            current_addr = mbi.BaseAddress + mbi.RegionSize

        return {
            "success": True,
            "pattern": pattern,
            "matches_found": len(matches),
            "addresses": matches
        }

    def freeze_value(self, address: int, data_type: str, value: Any, interval_ms: int = 50) -> Dict[str, Any]:
        """Freezes an address so its value is constantly rewritten."""
        with self._lock:
            self.frozen_values[address] = {
                "type": data_type,
                "value": value,
                "interval": max(10, interval_ms) / 1000.0
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
            with self._lock:
                items = list(self.frozen_values.items())
            for addr, meta in items:
                try:
                    self.write_memory(addr, meta["type"], meta["value"])
                except Exception:
                    pass
            time.sleep(0.05)
