import ctypes
import os
import sys
import time

# Create C-types memory variables so they have fixed memory addresses
hp_var = ctypes.c_int(100)
gold_var = ctypes.c_int(777)
mana_var = ctypes.c_float(50.5)

hp_addr = ctypes.addressof(hp_var)
gold_addr = ctypes.addressof(gold_var)
mana_addr = ctypes.addressof(mana_var)

print("=" * 50)
print("DUMMY GAME PROCESS RUNNING")
print(f"PID: {os.getpid()}")
print(f"HP Address: {hex(hp_addr)} (Current HP: {hp_var.value})")
print(f"Gold Address: {hex(gold_addr)} (Current Gold: {gold_var.value})")
print(f"Mana Address: {hex(mana_addr)} (Current Mana: {mana_var.value})")
print("=" * 50)
sys.stdout.flush()

try:
    while True:
        time.sleep(1)
        # Simulate damage if not frozen
        if hp_var.value > 0 and hp_var.value != 99999:
            hp_var.value -= 1
        print(f"[Game Loop] HP: {hp_var.value} | Gold: {gold_var.value} | Mana: {mana_var.value:.1f}")
        sys.stdout.flush()
except KeyboardInterrupt:
    print("Dummy game stopped.")
