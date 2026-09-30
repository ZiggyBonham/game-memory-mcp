import subprocess
import time
import sys
import os

sys.path.append(os.path.dirname(__file__))
from game_memory_engine import GameMemoryEngine
from cheat_table import CheatTableParser
from lua_engine import LuaEngine

def run_extended_tests():
    print(">>> Starting Dummy Game...")
    proc = subprocess.Popen(
        [sys.executable, os.path.join(os.path.dirname(__file__), "dummy_game.py")],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    time.sleep(1)

    try:
        pid = proc.pid
        print(f">>> Dummy Game running with PID: {pid}")

        engine = GameMemoryEngine()
        attach_res = engine.attach(pid)
        assert attach_res["success"], "Failed to attach"

        # 1. Scan to locate the dynamic gold address for testing
        scan_res = engine.first_scan("gold_scan", "int32", 777)
        assert scan_res["total_matches"] > 0
        gold_addr = list(engine.scans["gold_scan"].matches.keys())[0]
        gold_hex = hex(gold_addr)
        print(f"Located Gold Address: {gold_hex}")

        # 2. Test Lua Engine
        print("\n--- Testing Lua Script Execution ---")
        lua = LuaEngine(engine)
        lua_script = f"""
        print("Hello from Lua Engine!")
        local val = readInteger("{gold_hex}")
        print("Lua read gold:", val)
        writeInteger("{gold_hex}", 888888)
        local new_val = readInteger("{gold_hex}")
        print("Lua new gold:", new_val)
        return new_val
        """
        lua_res = lua.execute_script(lua_script)
        print("Lua Execution Result:", lua_res)
        assert lua_res["success"], f"Lua script failed: {lua_res.get('error')}"
        assert lua_res["result"] == "888888"

        # 3. Test Cheat Table (.CT) Parser & Runner
        print("\n--- Testing Cheat Table (.CT) Engine ---")
        sample_ct = f"""<?xml version="1.0" encoding="utf-8"?>
<CheatTable CheatEngineTableVersion="45">
  <CheatEntries>
    <CheatEntry>
      <ID>1</ID>
      <Description>"Player Gold"</Description>
      <VariableType>4 Bytes</VariableType>
      <Address>{gold_hex}</Address>
    </CheatEntry>
  </CheatEntries>
</CheatTable>"""

        ct_parser = CheatTableParser(engine)
        ct_res = ct_parser.parse_ct("test_table", sample_ct)
        print("Parsed CT Result:", ct_res)
        assert ct_res["success"], "Failed to parse CT"

        entries = ct_parser.list_entries("test_table")
        print("CT Entries:", entries)
        assert len(entries) == 1
        assert entries[0]["current_value"] == 888888

        # Modify value via CT
        set_res = ct_parser.set_entry_value("test_table", "1", 1234567)
        print("Set Entry Value Result:", set_res)
        assert set_res["success"]

        # Verify read back
        verify_val = engine.read_memory(gold_addr, "int32")
        print(f"Verified memory after CT edit: {verify_val['value']}")
        assert verify_val["value"] == 1234567

        print("\n ALL EXTENDED FEATURES (LUA & CHEAT TABLES) VERIFIED SUCCESSFULLY!")

    finally:
        proc.kill()

if __name__ == "__main__":
    run_extended_tests()
