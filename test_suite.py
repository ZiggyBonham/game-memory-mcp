import subprocess
import time
import sys
import os

sys.path.append(os.path.dirname(__file__))
from game_memory_engine import GameMemoryEngine

def run_tests():
    print(">>> Starting Dummy Game...")
    proc = subprocess.Popen(
        [sys.executable, os.path.join(os.path.dirname(__file__), "dummy_game.py")],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    time.sleep(1) # wait for startup

    try:
        pid = proc.pid
        print(f">>> Dummy Game started with PID: {pid}")

        engine = GameMemoryEngine()

        # 1. Test Attach
        attach_res = engine.attach(pid)
        print("Attach Result:", attach_res)
        assert attach_res["success"], "Failed to attach"

        # 2. Test First Scan for Gold (777)
        print(">>> Scanning for Gold (777)...")
        scan_res = engine.first_scan("gold_scan", "int32", 777)
        print(f"Scan found {scan_res['total_matches']} candidate addresses.")
        assert scan_res["total_matches"] > 0, "No matches found for 777"

        # 3. Test Direct Memory Write & Read
        target_addr = list(engine.scans["gold_scan"].matches.keys())[0]
        print(f">>> Writing 999999 to candidate address {hex(target_addr)}...")
        w_res = engine.write_memory(target_addr, "int32", 999999)
        print("Write Result:", w_res)
        assert w_res["success"], "Failed to write memory"

        r_res = engine.read_memory(target_addr, "int32")
        print("Read Result:", r_res)
        assert r_res["value"] == 999999, f"Read value mismatch: {r_res['value']}"

        # 4. Test Freeze Value
        print(f">>> Freezing candidate address to 500000...")
        f_res = engine.freeze_value(target_addr, "int32", 500000)
        print("Freeze Result:", f_res)
        assert f_res["success"], "Failed to freeze value"

        time.sleep(0.3)
        r_frozen = engine.read_memory(target_addr, "int32")
        print(f"Frozen Read Verification: {r_frozen['value']}")
        assert r_frozen["value"] == 500000, "Frozen value not maintained"

        # 5. Test Unfreeze
        u_res = engine.unfreeze_value(target_addr)
        print("Unfreeze Result:", u_res)
        assert u_res["success"], "Failed to unfreeze"

        print("\n ALL GAME MEMORY ENGINE TESTS PASSED SUCCESSFULLY!")

    finally:
        proc.kill()

if __name__ == "__main__":
    run_tests()
