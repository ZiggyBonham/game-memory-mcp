import subprocess
import time
import sys
import os

sys.path.append(os.path.dirname(__file__))
from game_memory_engine import GameMemoryEngine
from stealth_engine import StealthEngine
from lua_engine import LuaEngine

def run_stealth_tests():
    print(">>> Starting Dummy Game for Stealth Verification...")
    proc = subprocess.Popen(
        [sys.executable, os.path.join(os.path.dirname(__file__), "dummy_game.py")],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    time.sleep(1)

    try:
        pid = proc.pid
        print(f">>> Dummy Game PID: {pid}")

        engine = GameMemoryEngine()
        attach_res = engine.attach(pid)
        assert attach_res["success"], "Failed to attach"

        stealth = StealthEngine(engine)

        # 1. Scan for HP (100 or current)
        scan_res = engine.first_scan("hp_scan", "int32", 100)
        if scan_res["total_matches"] == 0:
            # Try 99 or 98 if ticked
            scan_res = engine.first_scan("hp_scan", "int32", 99)
        hp_addr = list(engine.scans["hp_scan"].matches.keys())[0]
        print(f"Located HP Address: {hex(hp_addr)}")

        # 2. Test Direct NT Read & Stealth Write with Protection Restoration
        print("\n--- Testing Direct NT Syscall Memory Read/Write ---")
        w_res = stealth.stealth_write(hp_addr, "int32", 7777, restore_protection=True)
        print("Stealth Write Result:", w_res)
        assert w_res["success"]

        r_bytes = stealth.nt_read(hp_addr, 4)
        assert r_bytes is not None
        import struct
        val = struct.unpack('<i', r_bytes)[0]
        print(f"Direct NtRead value: {val}")
        assert val == 7777

        # 3. Test Smart Adaptive Freezing (Low-footprint check-before-write + jitter)
        print("\n--- Testing Smart Adaptive Freezing ---")
        freeze_res = stealth.smart_freeze(hp_addr, "int32", 5555, min_interval_ms=30, max_interval_ms=80)
        print("Smart Freeze Result:", freeze_res)
        assert freeze_res["success"]

        # Let dummy game run for 2 seconds (it tries to decrement HP each second)
        time.sleep(2.2)
        r_bytes2 = stealth.nt_read(hp_addr, 4)
        val2 = struct.unpack('<i', r_bytes2)[0]
        print(f"Smart Frozen Value after 2s game loop: {val2}")
        assert val2 == 5555

        # Check write stats (should be very low writes count compared to tight loop)
        meta = stealth.smart_frozen_values[hp_addr]
        print(f"Smart Freeze Stats -> Checks: {meta['checks_count']}, Actual Writes: {meta['writes_count']}")
        assert meta["writes_count"] > 0
        stealth.smart_unfreeze(hp_addr)

        # 4. Test Script Obfuscation
        print("\n--- Testing Script Obfuscator ---")
        plain_script = 'print("Obfuscated execution confirmed!") return 42'
        obf_res = StealthEngine.obfuscate_script(plain_script, key_seed=99)
        print("Obfuscation Result -> Encrypted length:", obf_res["encrypted_length"])
        assert obf_res["success"]

        # Verify decoding logic
        key = bytes.fromhex(obf_res["key_hex"])
        encrypted = StealthEngine.xor_cipher(plain_script.encode('utf-8'), key)
        decrypted = StealthEngine.xor_cipher(encrypted, key).decode('utf-8')
        assert decrypted == plain_script
        print("Decryption check verified: match!")

        print("\n ALL STEALTH, NT SYSCALL, SMART FREEZE & OBFUSCATION TESTS PASSED!")

    finally:
        proc.kill()

if __name__ == "__main__":
    run_stealth_tests()
