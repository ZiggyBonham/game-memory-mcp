import subprocess
import time
import sys
import os

sys.path.append(os.path.dirname(__file__))
from win32_api import parse_address
from game_memory_engine import GameMemoryEngine
from cheat_table import CheatTableParser

def test_optimizations():
    print("--- 1. Testing parse_address utility ---")
    assert parse_address("0x7FF71234") == 0x7FF71234
    assert parse_address("0X100") == 0x100
    assert parse_address("1400A100") == 0x1400A100 # raw hex without 0x
    assert parse_address("00405000") == 0x00405000 # CE style with leading zeros
    assert parse_address(12345) == 12345
    print("parse_address: ALL PASSED")

    print("\n--- 2. Testing Dummy Game with Regex Pattern Scan & Float Scanning ---")
    proc = subprocess.Popen(
        [sys.executable, os.path.join(os.path.dirname(__file__), "dummy_game.py")],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    time.sleep(1)

    try:
        engine = GameMemoryEngine()
        res = engine.attach(proc.pid)
        assert res["success"]

        # Float scanning
        scan_res = engine.first_scan("mana_scan", "float", 50.5)
        print("Float scan for Mana (50.5):", scan_res)
        assert scan_res["total_matches"] > 0
        mana_addr = list(engine.scans["mana_scan"].matches.keys())[0]

        # Next scan with float matching
        next_res = engine.next_scan("mana_scan", "exact", 50.5)
        print("Next scan exact float:", next_res)
        assert next_res["total_matches"] > 0

        # High-speed Regex AOB Pattern Scanning
        print("\n--- 3. Testing High-Speed AOB Pattern Scan ---")
        # Read 8 bytes from mana_addr to construct a pattern
        raw_bytes = engine.read_raw(mana_addr, 8)
        assert raw_bytes is not None
        pattern = " ".join(f"{b:02X}" for b in raw_bytes[:4]) + " ?? ??"
        print(f"Scanning pattern with wildcards: {pattern}")
        pat_res = engine.pattern_scan(pattern)
        print("Pattern scan results:", pat_res)
        assert pat_res["success"]
        assert pat_res["matches_found"] > 0
        assert hex(mana_addr) in pat_res["addresses"]

        print("\n ALL OPTIMIZATION TESTS PASSED SUCCESSFULLY!")

    finally:
        proc.kill()

if __name__ == "__main__":
    test_optimizations()
