"""Win32 DLL Injection via CreateRemoteThread + LoadLibraryW.

Includes architecture checks, handle cleanup, and thread exit code verification.
"""
import ctypes
from ctypes import wintypes
import os
import struct
from typing import Dict, Any

from win32_api import (
    kernel32,
    VirtualAllocEx, VirtualFreeEx, CreateRemoteThread, WaitForSingleObject,
    GetExitCodeThread, GetProcAddress, GetModuleHandleW, CloseHandle,
    WriteProcessMemory,
    MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, PAGE_READWRITE
)

def get_dll_architecture(dll_path: str) -> str:
    """Reads PE header of DLL to determine bitness ('x86' or 'x64')."""
    try:
        with open(dll_path, 'rb') as f:
            dos_hdr = f.read(64)
            if len(dos_hdr) < 64 or dos_hdr[:2] != b'MZ':
                return 'unknown'
            e_lfanew = struct.unpack('<I', dos_hdr[0x3C:0x40])[0]
            f.seek(e_lfanew)
            pe_sig = f.read(4)
            if pe_sig != b'PE\x00\x00':
                return 'unknown'
            machine = struct.unpack('<H', f.read(2))[0]
            if machine == 0x8664:
                return 'x64'
            elif machine == 0x014c:
                return 'x86'
            return 'unknown'
    except Exception:
        return 'unknown'

def inject_dll_to_process(process_handle: wintypes.HANDLE, dll_path: str, timeout_ms: int = 5000) -> Dict[str, Any]:
    """Injects a DLL into the target process using standard Win32 CreateRemoteThread and LoadLibraryW."""
    abs_dll_path = os.path.abspath(dll_path)
    if not os.path.exists(abs_dll_path):
        return {"success": False, "error": f"DLL not found at {abs_dll_path}"}

    dll_arch = get_dll_architecture(abs_dll_path)

    # Encode DLL path as wide string (UTF-16 with null terminator)
    dll_bytes = abs_dll_path.encode('utf-16le') + b'\x00\x00'
    dll_len = len(dll_bytes)

    # 1. Allocate memory in target process for the DLL path
    remote_mem = VirtualAllocEx(
        process_handle,
        None,
        dll_len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    )

    if not remote_mem:
        err = ctypes.get_last_error()
        return {"success": False, "error": f"VirtualAllocEx failed with code {err}"}

    try:
        # 2. Write the DLL path into target process memory
        bytes_written = ctypes.c_size_t(0)
        buffer = (ctypes.c_char * dll_len).from_buffer_copy(dll_bytes)
        write_res = WriteProcessMemory(
            process_handle,
            remote_mem,
            buffer,
            dll_len,
            ctypes.byref(bytes_written)
        )

        if not write_res or bytes_written.value != dll_len:
            err = ctypes.get_last_error()
            return {"success": False, "error": f"WriteProcessMemory failed with code {err}"}

        # 3. Get address of LoadLibraryW in kernel32
        h_kernel32 = GetModuleHandleW("kernel32.dll")
        load_library_w = GetProcAddress(h_kernel32, b"LoadLibraryW")
        if not load_library_w:
            return {"success": False, "error": "Could not locate LoadLibraryW in kernel32"}

        # 4. Create remote thread in target process
        thread_id = wintypes.DWORD(0)
        h_thread = CreateRemoteThread(
            process_handle,
            None,
            0,
            load_library_w,
            remote_mem,
            0,
            ctypes.byref(thread_id)
        )

        if not h_thread:
            err = ctypes.get_last_error()
            return {"success": False, "error": f"CreateRemoteThread failed with code {err}"}

        # 5. Wait for injection thread
        wait_res = WaitForSingleObject(h_thread, timeout_ms)
        exit_code = wintypes.DWORD(0)
        GetExitCodeThread(h_thread, ctypes.byref(exit_code))
        CloseHandle(h_thread)

        if wait_res != 0:
            return {
                "success": False,
                "error": f"Thread timed out or failed (wait result: {wait_res})"
            }

        # If LoadLibraryW returns 0, the DLL failed to load
        if exit_code.value == 0:
            return {
                "success": False,
                "error": "LoadLibraryW returned NULL in remote process. Check DLL dependencies or bitness mismatch."
            }

        return {
            "success": True,
            "dll_path": abs_dll_path,
            "dll_architecture": dll_arch,
            "remote_module_handle": hex(exit_code.value),
            "message": "DLL injected and loaded successfully."
        }

    finally:
        VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE)
