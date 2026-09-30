"""Reflective Manual-Map DLL Injector for Windows (x64 / x86).

Performs in-memory PE loading:
- Section mapping (.text, .rdata, .data, etc.)
- Base Relocations (IMAGE_DIRECTORY_ENTRY_BASERELOC)
- Import Address Table (IAT) resolution (IMAGE_DIRECTORY_ENTRY_IMPORT)
- ABI-compliant DllMain execution (DLL_PROCESS_ATTACH) via tiny shellcode trampoline
- Optional PE header wiping to defeat signature scanning in memory
"""
import ctypes
from ctypes import wintypes
import os
import struct
from typing import Dict, Any, Optional

from win32_api import (
    kernel32,
    VirtualAllocEx, VirtualFreeEx, CreateRemoteThread, WaitForSingleObject,
    GetExitCodeThread, GetProcAddress, GetModuleHandleW, CloseHandle,
    WriteProcessMemory, ReadProcessMemory,
    MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, PAGE_EXECUTE_READWRITE
)

# PE Directory Constants
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5

IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGHLOW = 3
IMAGE_REL_BASED_DIR64 = 10

class ManualMapper:
    """Reflective PE loader that maps DLLs directly into process memory without LoadLibrary."""

    def __init__(self, memory_engine):
        self.engine = memory_engine

    def map_dll(self, dll_path: str, wipe_headers: bool = True, timeout_ms: int = 5000) -> Dict[str, Any]:
        """Manually maps a PE DLL into the target process."""
        if not self.engine.process_handle:
            return {"success": False, "error": "No process attached"}

        abs_path = os.path.abspath(dll_path)
        if not os.path.exists(abs_path):
            return {"success": False, "error": f"File not found: {abs_path}"}

        with open(abs_path, "rb") as f:
            pe_data = f.read()

        # 1. Parse DOS Header
        if len(pe_data) < 64 or pe_data[:2] != b'MZ':
            return {"success": False, "error": "Invalid DOS Header (missing MZ)"}

        e_lfanew = struct.unpack('<I', pe_data[0x3C:0x40])[0]

        # 2. Parse NT Headers
        if len(pe_data) < e_lfanew + 24 or pe_data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
            return {"success": False, "error": "Invalid NT Headers (missing PE)"}

        machine = struct.unpack('<H', pe_data[e_lfanew+4:e_lfanew+6])[0]
        is_64bit = (machine == 0x8664)

        if is_64bit != self.engine.is_64bit:
            return {
                "success": False,
                "error": f"Architecture mismatch: DLL is {'x64' if is_64bit else 'x86'}, target process is {'x64' if self.engine.is_64bit else 'x86'}"
            }

        num_sections = struct.unpack('<H', pe_data[e_lfanew+6:e_lfanew+8])[0]
        size_opt_header = struct.unpack('<H', pe_data[e_lfanew+20:e_lfanew+22])[0]
        opt_header_offset = e_lfanew + 24

        if is_64bit:
            entry_point_rva = struct.unpack('<I', pe_data[opt_header_offset+16:opt_header_offset+20])[0]
            image_base = struct.unpack('<Q', pe_data[opt_header_offset+24:opt_header_offset+32])[0]
            size_of_image = struct.unpack('<I', pe_data[opt_header_offset+56:opt_header_offset+60])[0]
            size_of_headers = struct.unpack('<I', pe_data[opt_header_offset+60:opt_header_offset+64])[0]
            data_dirs_offset = opt_header_offset + 112
        else:
            entry_point_rva = struct.unpack('<I', pe_data[opt_header_offset+16:opt_header_offset+20])[0]
            image_base = struct.unpack('<I', pe_data[opt_header_offset+28:opt_header_offset+32])[0]
            size_of_image = struct.unpack('<I', pe_data[opt_header_offset+56:opt_header_offset+60])[0]
            size_of_headers = struct.unpack('<I', pe_data[opt_header_offset+60:opt_header_offset+64])[0]
            data_dirs_offset = opt_header_offset + 96

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

        # Cast pointer to int
        remote_base_addr = remote_base if isinstance(remote_base, int) else (remote_base.value if hasattr(remote_base, 'value') else int(remote_base))
        delta = remote_base_addr - image_base

        try:
            # 4. Write Headers
            bytes_written = ctypes.c_size_t(0)
            hdr_buf = (ctypes.c_char * size_of_headers).from_buffer_copy(pe_data[:size_of_headers])
            WriteProcessMemory(self.engine.process_handle, ctypes.c_void_p(remote_base_addr), hdr_buf, size_of_headers, ctypes.byref(bytes_written))

            # 5. Map Sections
            section_table_offset = opt_header_offset + size_opt_header
            for i in range(num_sections):
                sec_offset = section_table_offset + (i * 40)
                virt_size = struct.unpack('<I', pe_data[sec_offset+8:sec_offset+12])[0]
                virt_addr = struct.unpack('<I', pe_data[sec_offset+12:sec_offset+16])[0]
                raw_size = struct.unpack('<I', pe_data[sec_offset+16:sec_offset+20])[0]
                raw_ptr = struct.unpack('<I', pe_data[sec_offset+20:sec_offset+24])[0]

                if raw_size > 0 and raw_ptr > 0:
                    sec_data = pe_data[raw_ptr:raw_ptr+raw_size]
                    sec_buf = (ctypes.c_char * len(sec_data)).from_buffer_copy(sec_data)
                    dest = remote_base_addr + virt_addr
                    WriteProcessMemory(self.engine.process_handle, ctypes.c_void_p(dest), sec_buf, len(sec_data), ctypes.byref(bytes_written))

            # 6. Apply Base Relocations if delta != 0
            if delta != 0 and len(pe_data) >= data_dirs_offset + (IMAGE_DIRECTORY_ENTRY_BASERELOC + 1) * 8:
                reloc_rva, reloc_size = struct.unpack('<II', pe_data[data_dirs_offset + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8:data_dirs_offset + (IMAGE_DIRECTORY_ENTRY_BASERELOC + 1) * 8])
                if reloc_rva and reloc_size:
                    curr_reloc_rva = reloc_rva
                    end_reloc_rva = reloc_rva + reloc_size

                    while curr_reloc_rva < end_reloc_rva:
                        raw_block_hdr = self.engine.read_raw(remote_base_addr + curr_reloc_rva, 8)
                        if not raw_block_hdr:
                            break
                        page_rva, block_size = struct.unpack('<II', raw_block_hdr)
                        if block_size <= 8:
                            break

                        entries_count = (block_size - 8) // 2
                        raw_entries = self.engine.read_raw(remote_base_addr + curr_reloc_rva + 8, entries_count * 2)
                        if raw_entries:
                            for e_idx in range(entries_count):
                                entry = struct.unpack('<H', raw_entries[e_idx*2:(e_idx+1)*2])[0]
                                rel_type = entry >> 12
                                rel_offset = entry & 0xFFF
                                patch_addr = remote_base_addr + page_rva + rel_offset

                                if is_64bit and rel_type == IMAGE_REL_BASED_DIR64:
                                    val_raw = self.engine.read_raw(patch_addr, 8)
                                    if val_raw:
                                        cur_val = struct.unpack('<Q', val_raw)[0]
                                        new_val = struct.pack('<Q', cur_val + delta)
                                        self.engine.write_raw(patch_addr, new_val)
                                elif not is_64bit and rel_type == IMAGE_REL_BASED_HIGHLOW:
                                    val_raw = self.engine.read_raw(patch_addr, 4)
                                    if val_raw:
                                        cur_val = struct.unpack('<I', val_raw)[0]
                                        new_val = struct.pack('<I', (cur_val + delta) & 0xFFFFFFFF)
                                        self.engine.write_raw(patch_addr, new_val)

                        curr_reloc_rva += block_size

            # 7. Resolve Import Address Table (IAT)
            if len(pe_data) >= data_dirs_offset + (IMAGE_DIRECTORY_ENTRY_IMPORT + 1) * 8:
                import_rva, import_size = struct.unpack('<II', pe_data[data_dirs_offset + IMAGE_DIRECTORY_ENTRY_IMPORT * 8:data_dirs_offset + (IMAGE_DIRECTORY_ENTRY_IMPORT + 1) * 8])
                if import_rva and import_size:
                    curr_desc_rva = import_rva
                    while True:
                        raw_desc = self.engine.read_raw(remote_base_addr + curr_desc_rva, 20)
                        if not raw_desc or raw_desc == b'\x00' * 20:
                            break

                        orig_first_thunk, _, _, name_rva, first_thunk = struct.unpack('<IIIII', raw_desc)
                        thunk_rva = orig_first_thunk if orig_first_thunk else first_thunk

                        # Read DLL name
                        raw_dll_name = self.engine.read_raw(remote_base_addr + name_rva, 64)
                        if raw_dll_name:
                            null_pos = raw_dll_name.find(b'\x00')
                            dll_name = raw_dll_name[:null_pos].decode('latin-1', errors='ignore')
                            h_mod = kernel32.LoadLibraryA(dll_name.encode('ascii'))

                            if h_mod:
                                ptr_sz = 8 if is_64bit else 4
                                thunk_idx = 0
                                while True:
                                    t_data = self.engine.read_raw(remote_base_addr + thunk_rva + (thunk_idx * ptr_sz), ptr_sz)
                                    if not t_data:
                                        break
                                    val = struct.unpack('<Q' if is_64bit else '<I', t_data)[0]
                                    if val == 0:
                                        break

                                    fn_addr = 0
                                    ordinal_mask = 0x8000000000000000 if is_64bit else 0x80000000
                                    if val & ordinal_mask:
                                        # Import by ordinal
                                        ordinal = val & 0xFFFF
                                        fn_addr = GetProcAddress(h_mod, ctypes.c_char_p(ordinal))
                                    else:
                                        # Import by name
                                        name_data = self.engine.read_raw(remote_base_addr + val + 2, 64)
                                        if name_data:
                                            fn_name = name_data[:name_data.find(b'\x00')]
                                            fn_addr = GetProcAddress(h_mod, fn_name)

                                    if fn_addr:
                                        dest_iat = remote_base_addr + first_thunk + (thunk_idx * ptr_sz)
                                        packed_fn = struct.pack('<Q' if is_64bit else '<I', fn_addr)
                                        self.engine.write_raw(dest_iat, packed_fn)

                                    thunk_idx += 1

                        curr_desc_rva += 20

            # 8. Wipe Headers if requested
            if wipe_headers:
                zero_hdr = (ctypes.c_char * size_of_headers).from_buffer_copy(b'\x00' * size_of_headers)
                WriteProcessMemory(self.engine.process_handle, ctypes.c_void_p(remote_base_addr), zero_hdr, size_of_headers, ctypes.byref(bytes_written))

            # 9. Execute DllMain with ABI-compliant Trampoline
            if entry_point_rva != 0:
                remote_entry = remote_base_addr + entry_point_rva

                if is_64bit:
                    # x64 Trampoline:
                    # sub rsp, 40       (48 83 EC 28)
                    # mov rcx, base     (48 B9 <8 bytes>)
                    # mov edx, 1        (BA 01 00 00 00)
                    # xor r8d, r8d      (45 31 C0)
                    # mov rax, entry    (48 B8 <8 bytes>)
                    # call rax          (FF D0)
                    # add rsp, 40       (48 83 C4 28)
                    # ret               (C3)
                    stub = (
                        b'\x48\x83\xEC\x28'
                        + b'\x48\xB9' + struct.pack('<Q', remote_base_addr)
                        + b'\xBA\x01\x00\x00\x00'
                        + b'\x45\x31\xC0'
                        + b'\x48\xB8' + struct.pack('<Q', remote_entry)
                        + b'\xFF\xD0'
                        + b'\x48\x83\xC4\x28'
                        + b'\xC3'
                    )
                else:
                    # x86 Trampoline:
                    # push 0 (lpReserved) (6A 00)
                    # push 1 (fdwReason)  (6A 01)
                    # push base           (68 <4 bytes>)
                    # mov eax, entry      (B8 <4 bytes>)
                    # call eax            (FF D0)
                    # ret                 (C3)
                    stub = (
                        b'\x6A\x00'
                        + b'\x6A\x01'
                        + b'\x68' + struct.pack('<I', remote_base_addr)
                        + b'\xB8' + struct.pack('<I', remote_entry)
                        + b'\xFF\xD0'
                        + b'\xC3'
                    )

                stub_mem = VirtualAllocEx(
                    self.engine.process_handle,
                    None,
                    len(stub),
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE
                )

                if stub_mem:
                    stub_mem_addr = stub_mem if isinstance(stub_mem, int) else (stub_mem.value if hasattr(stub_mem, 'value') else int(stub_mem))
                    stub_buf = (ctypes.c_char * len(stub)).from_buffer_copy(stub)
                    WriteProcessMemory(self.engine.process_handle, ctypes.c_void_p(stub_mem_addr), stub_buf, len(stub), ctypes.byref(bytes_written))

                    thread_id = wintypes.DWORD(0)
                    h_thread = CreateRemoteThread(
                        self.engine.process_handle,
                        None,
                        0,
                        ctypes.c_void_p(stub_mem_addr),
                        None,
                        0,
                        ctypes.byref(thread_id)
                    )

                    if h_thread:
                        WaitForSingleObject(h_thread, timeout_ms)
                        CloseHandle(h_thread)

                    VirtualFreeEx(self.engine.process_handle, ctypes.c_void_p(stub_mem_addr), 0, MEM_RELEASE)

            return {
                "success": True,
                "method": "manual_map_reflective",
                "mapped_base": hex(remote_base_addr),
                "size_of_image": size_of_image,
                "headers_wiped": wipe_headers,
                "peb_ldr_hidden": True,
                "relocations_applied": delta != 0,
                "iat_resolved": True
            }

        except Exception as e:
            VirtualFreeEx(self.engine.process_handle, ctypes.c_void_p(remote_base_addr), 0, MEM_RELEASE)
            return {"success": False, "error": f"Manual mapping exception: {e}"}
