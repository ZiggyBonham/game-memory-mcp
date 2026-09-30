import ctypes
from ctypes import wintypes
import os
from typing import Dict, Any

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.restype = wintypes.LPVOID
VirtualAllocEx.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    ctypes.c_size_t,
    wintypes.DWORD,
    wintypes.DWORD
]

VirtualFreeEx = kernel32.VirtualFreeEx
VirtualFreeEx.restype = wintypes.BOOL
VirtualFreeEx.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    ctypes.c_size_t,
    wintypes.DWORD
]

CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.restype = wintypes.HANDLE
CreateRemoteThread.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    ctypes.c_size_t,
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.LPDWORD
]

WaitForSingleObject = kernel32.WaitForSingleObject
WaitForSingleObject.restype = wintypes.DWORD
WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]

GetProcAddress = kernel32.GetProcAddress
GetProcAddress.restype = wintypes.LPVOID
GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]

GetModuleHandleW = kernel32.GetModuleHandleW
GetModuleHandleW.restype = wintypes.HMODULE
GetModuleHandleW.argtypes = [wintypes.LPCWSTR]

CloseHandle = kernel32.CloseHandle
CloseHandle.restype = wintypes.BOOL
CloseHandle.argtypes = [wintypes.HANDLE]

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
INFINITE = 0xFFFFFFFF


def inject_dll_to_process(process_handle: wintypes.HANDLE, dll_path: str, timeout_ms: int = 5000) -> Dict[str, Any]:
    """
    Injects a DLL into the target process using standard Win32 CreateRemoteThread and LoadLibraryW.
    """
    abs_dll_path = os.path.abspath(dll_path)
    if not os.path.exists(abs_dll_path):
        return {"success": False, "error": f"DLL not found at {abs_dll_path}"}

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
        from game_memory_engine import WriteProcessMemory
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
            return {"success": False, "error": "Could not locate LoadLibraryW"}

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

        # 5. Wait for injection to complete
        WaitForSingleObject(h_thread, timeout_ms)
        CloseHandle(h_thread)

        return {
            "success": True,
            "dll_path": abs_dll_path,
            "message": "DLL injected successfully."
        }

    finally:
        # Free allocated path memory
        VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE)
