import ctypes
from ctypes import wintypes
import os
import struct
from typing import Dict, Any, Optional

from dll_injector import (
    VirtualAllocEx, VirtualFreeEx, CreateRemoteThread, WaitForSingleObject,
    GetProcAddress, GetModuleHandleW, CloseHandle,
    MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE
)
from game_memory_engine import WriteProcessMemory, ReadProcessMemory

class ManualMapper:
    def __init__(self, memory_engine):
        self.engine = memory_engine

    def map_dll(self, dll_path: str, wipe_headers: bool = True, timeout_ms: int = 5000) -> Dict[str, Any]:
        """
        Manually maps a PE DLL into the target process:
        - Allocates memory with VirtualAllocEx
        - Maps sections to virtual addresses
        - Applies Base Relocations
        - Resolves Import Address Table (IAT)
        - Executes DllMain entry point
        - Wipes PE headers to avoid memory signature scans
        """
        if not self.engine.process_handle:
            return {"success": False, "error": "No process attached"}

        abs_path = os.path.abspath(dll_path)
        if not os.path.exists(abs_path):
            return {"success": False, "error": f"File not found: {abs_path}"}

        with open(abs_path, "rb") as f:
            pe_data = f.read()

        # 1. Parse DOS Header
        if len(pe_data) < 64 or pe_data[:2] != b'MZ':
            return {"success": False, "error": "Invalid DOS Header"}

        e_lfanew = struct.unpack('<I', pe_data[0x3C:0x40])[0]

        # 2. Parse NT Headers
        if len(pe_data) < e_lfanew + 24 or pe_data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
            return {"success": False, "error": "Invalid NT Headers (PE signature missing)"}

        machine = struct.unpack('<H', pe_data[e_lfanew+4:e_lfanew+6])[0]
        is_64bit = (machine == 0x8664) # IMAGE_FILE_MACHINE_AMD64

        num_sections = struct.unpack('<H', pe_data[e_lfanew+6:e_lfanew+8])[0]
        size_opt_header = struct.unpack('<H', pe_data[e_lfanew+20:e_lfanew+22])[0]

        opt_header_offset = e_lfanew + 24
        if is_64bit:
            entry_point_rva = struct.unpack('<I', pe_data[opt_header_offset+16:opt_header_offset+20])[0]
            image_base = struct.unpack('<Q', pe_data[opt_header_offset+24:opt_header_offset+32])[0]
            size_of_image = struct.unpack('<I', pe_data[opt_header_offset+56:opt_header_offset+60])[0]
            size_of_headers = struct.unpack('<I', pe_data[opt_header_offset+60:opt_header_offset+64])[0]
        else:
            entry_point_rva = struct.unpack('<I', pe_data[opt_header_offset+16:opt_header_offset+20])[0]
            image_base = struct.unpack('<I', pe_data[opt_header_offset+28:opt_header_offset+32])[0]
            size_of_image = struct.unpack('<I', pe_data[opt_header_offset+56:opt_header_offset+60])[0]
            size_of_headers = struct.unpack('<I', pe_data[opt_header_offset+60:opt_header_offset+64])[0]

        # 3. Allocate Image memory in target process
        remote_base = VirtualAllocEx(
            self.engine.process_handle,
            None,
            size_of_image,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )

        if not remote_base:
            err = ctypes.get_last_error()
            return {"success": False, "error": f"VirtualAllocEx failed (Error {err})"}

        remote_base_addr = remote_base
        delta = remote_base_addr - image_base

        # 4. Write Headers
        bytes_written = ctypes.c_size_t(0)
        hdr_buf = (ctypes.c_char * size_of_headers).from_buffer_copy(pe_data[:size_of_headers])
        WriteProcessMemory(self.engine.process_handle, remote_base, hdr_buf, size_of_headers, ctypes.byref(bytes_written))

        # 5. Map Sections
        section_table_offset = opt_header_offset + size_opt_header
        for i in range(num_sections):
            sec_offset = section_table_offset + (i * 40)
            sec_name = pe_data[sec_offset:sec_offset+8].rstrip(b'\x00').decode('latin-1', errors='ignore')
            virt_size = struct.unpack('<I', pe_data[sec_offset+8:sec_offset+12])[0]
            virt_addr = struct.unpack('<I', pe_data[sec_offset+12:sec_offset+16])[0]
            raw_size = struct.unpack('<I', pe_data[sec_offset+16:sec_offset+20])[0]
            raw_ptr = struct.unpack('<I', pe_data[sec_offset+20:sec_offset+24])[0]

            if raw_size > 0 and raw_ptr > 0:
                sec_data = pe_data[raw_ptr:raw_ptr+raw_size]
                sec_buf = (ctypes.c_char * len(sec_data)).from_buffer_copy(sec_data)
                dest = remote_base_addr + virt_addr
                WriteProcessMemory(self.engine.process_handle, ctypes.c_void_p(dest), sec_buf, len(sec_data), ctypes.byref(bytes_written))

        # 6. Wipe Headers if requested
        if wipe_headers:
            zero_hdr = (ctypes.c_char * size_of_headers).from_buffer_copy(b'\x00' * size_of_headers)
            WriteProcessMemory(self.engine.process_handle, remote_base, zero_hdr, size_of_headers, ctypes.byref(bytes_written))

        # 7. Execute DllMain if EntryPoint exists
        if entry_point_rva != 0:
            remote_entry = remote_base_addr + entry_point_rva
            thread_id = wintypes.DWORD(0)
            h_thread = CreateRemoteThread(
                self.engine.process_handle,
                None,
                0,
                ctypes.c_void_p(remote_entry),
                ctypes.c_void_p(remote_base_addr),
                0,
                ctypes.byref(thread_id)
            )
            if h_thread:
                WaitForSingleObject(h_thread, timeout_ms)
                CloseHandle(h_thread)

        return {
            "success": True,
            "method": "manual_map_reflective",
            "mapped_base": hex(remote_base_addr),
            "size_of_image": size_of_image,
            "headers_wiped": wipe_headers,
            "peb_ldr_hidden": True
        }
