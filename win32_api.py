"""Centralized Win32 API definitions, structures, constants, and utilities.

All Win32 constants, structures, function signatures, and address parsing
utilities are defined here to ensure high performance and zero duplication.
"""
import ctypes
from ctypes import wintypes
import sys
from typing import Optional, Union

# ---------------------------------------------------------------------------
# DLL Handles
# ---------------------------------------------------------------------------
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll.dll', use_last_error=True)

# ---------------------------------------------------------------------------
# Process Access Rights
# ---------------------------------------------------------------------------
PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# ---------------------------------------------------------------------------
# Memory State & Allocation Constants
# ---------------------------------------------------------------------------
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000
MEM_RELEASE = 0x8000

# ---------------------------------------------------------------------------
# Page Protection Constants
# ---------------------------------------------------------------------------
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100

WRITABLE_PROTECTIONS = (
    PAGE_READWRITE | PAGE_EXECUTE_READWRITE
    | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY
)

INFINITE = 0xFFFFFFFF

# ---------------------------------------------------------------------------
# Structures
# ---------------------------------------------------------------------------
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

class MEMORY_BASIC_INFORMATION32(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wintypes.DWORD),
        ("AllocationBase", wintypes.DWORD),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", wintypes.DWORD),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

# Default structure matching Python pointer width
IS_64BIT_PYTHON = (sys.maxsize > 2**32)
MEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION64 if IS_64BIT_PYTHON else MEMORY_BASIC_INFORMATION32

# ---------------------------------------------------------------------------
# NT Native Types
# ---------------------------------------------------------------------------
NTSTATUS = ctypes.c_long
PVOID = ctypes.c_void_p
SIZE_T = ctypes.c_size_t
PSIZE_T = ctypes.POINTER(ctypes.c_size_t)
ULONG = wintypes.ULONG
PULONG = ctypes.POINTER(wintypes.ULONG)
STATUS_SUCCESS = 0x00000000

# ---------------------------------------------------------------------------
# kernel32 functions
# ---------------------------------------------------------------------------
OpenProcess = kernel32.OpenProcess
OpenProcess.restype = wintypes.HANDLE
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

CloseHandle = kernel32.CloseHandle
CloseHandle.restype = wintypes.BOOL
CloseHandle.argtypes = [wintypes.HANDLE]

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.restype = wintypes.BOOL
ReadProcessMemory.argtypes = [
    wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.restype = wintypes.BOOL
WriteProcessMemory.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]

VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.restype = ctypes.c_size_t
VirtualQueryEx.argtypes = [
    wintypes.HANDLE, wintypes.LPCVOID,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t,
]

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.restype = wintypes.LPVOID
VirtualAllocEx.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
    wintypes.DWORD, wintypes.DWORD,
]

VirtualFreeEx = kernel32.VirtualFreeEx
VirtualFreeEx.restype = wintypes.BOOL
VirtualFreeEx.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD,
]

VirtualProtectEx = kernel32.VirtualProtectEx
VirtualProtectEx.restype = wintypes.BOOL
VirtualProtectEx.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
]

IsWow64Process = kernel32.IsWow64Process
IsWow64Process.restype = wintypes.BOOL
IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]

CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.restype = wintypes.HANDLE
CreateRemoteThread.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
    wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD,
]

WaitForSingleObject = kernel32.WaitForSingleObject
WaitForSingleObject.restype = wintypes.DWORD
WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]

GetExitCodeThread = kernel32.GetExitCodeThread
GetExitCodeThread.restype = wintypes.BOOL
GetExitCodeThread.argtypes = [wintypes.HANDLE, wintypes.LPDWORD]

GetProcAddress = kernel32.GetProcAddress
GetProcAddress.restype = wintypes.LPVOID
GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]

GetModuleHandleW = kernel32.GetModuleHandleW
GetModuleHandleW.restype = wintypes.HMODULE
GetModuleHandleW.argtypes = [wintypes.LPCWSTR]

# ---------------------------------------------------------------------------
# ntdll functions
# ---------------------------------------------------------------------------
NtReadVirtualMemory = ntdll.NtReadVirtualMemory
NtReadVirtualMemory.restype = NTSTATUS
NtReadVirtualMemory.argtypes = [
    wintypes.HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T,
]

NtWriteVirtualMemory = ntdll.NtWriteVirtualMemory
NtWriteVirtualMemory.restype = NTSTATUS
NtWriteVirtualMemory.argtypes = [
    wintypes.HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T,
]

NtProtectVirtualMemory = ntdll.NtProtectVirtualMemory
NtProtectVirtualMemory.restype = NTSTATUS
NtProtectVirtualMemory.argtypes = [
    wintypes.HANDLE, ctypes.POINTER(PVOID), PSIZE_T, ULONG, PULONG,
]

NtAllocateVirtualMemory = ntdll.NtAllocateVirtualMemory
NtAllocateVirtualMemory.restype = NTSTATUS
NtAllocateVirtualMemory.argtypes = [
    wintypes.HANDLE, ctypes.POINTER(PVOID), ctypes.c_size_t,
    PSIZE_T, ULONG, ULONG,
]

NtFreeVirtualMemory = ntdll.NtFreeVirtualMemory
NtFreeVirtualMemory.restype = NTSTATUS
NtFreeVirtualMemory.argtypes = [
    wintypes.HANDLE, ctypes.POINTER(PVOID), PSIZE_T, ULONG,
]

# ---------------------------------------------------------------------------
# Address Parsing Utility
# ---------------------------------------------------------------------------
def parse_address(addr: Union[int, str]) -> int:
    """Robustly parses an address from int, hex string, or CE-style hex string.

    Supports:
    - 0x7FF71234, 0X1234
    - 1400A100, 00405000 (raw hex without prefix)
    - 12345678 (numeric hex or decimal)
    """
    if isinstance(addr, int):
        return addr
    s = str(addr).strip()
    if s.startswith(('0x', '0X')):
        return int(s, 16)
    # Check if string contains hex characters a-f or A-F
    if any(c in 'abcdefABCDEF' for c in s):
        return int(s, 16)
    # If 8 or 16 chars with leading zeros or standard pointer length, prefer hex
    if len(s) in (8, 16) or s.startswith('0'):
        try:
            return int(s, 16)
        except ValueError:
            pass
    # Try as integer (could be decimal), then fallback to hex
    try:
        return int(s)
    except ValueError:
        return int(s, 16)
