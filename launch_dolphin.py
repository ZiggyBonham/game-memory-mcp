"""Launcher for Open Interpreter with Dolphin 3 and the Game Memory Suite.

Routes requests through Ollama's OpenAI-compatible API endpoint to bypass
Open Interpreter's internal Ollama tag-matching bug, and preloads the game memory tools.
"""
import sys
import os

# Add game-memory server directory to Python path
SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
if SERVER_DIR not in sys.path:
    sys.path.insert(0, SERVER_DIR)

from interpreter import interpreter

def main():
    print("=" * 60)
    print("  Initializing Open Interpreter with Dolphin 3 (Ollama)")
    print("  Game Memory Editing Suite: Ready")
    print("=" * 60)

    # Configure Open Interpreter to connect via Ollama's OpenAI-compatible endpoint
    interpreter.llm.model = "openai/dolphin3:latest"
    interpreter.llm.api_base = "http://localhost:11434/v1"
    interpreter.llm.api_key = "ollama"  # placeholder key required by OpenAI client
    interpreter.llm.temperature = 0.2
    interpreter.llm.context_window = 8192

    # Give Dolphin 3 full awareness of your game memory tools
    interpreter.system_message += f"""
You have direct programmatic access to a Game Memory Editing suite located at:
{SERVER_DIR}

When asked to inspect, scan, modify, or freeze game memory:
1. Import the necessary engines:
   import sys
   sys.path.insert(0, r"{SERVER_DIR}")
   from game_memory_engine import GameMemoryEngine
   from stealth_engine import StealthEngine
   from cheat_table import CheatTableParser
   from lua_engine import LuaEngine

2. Example Usage:
   engine = GameMemoryEngine()
   engine.attach("game.exe")
   engine.first_scan("hp_scan", "int32", 100)
   engine.write_memory(addr, "int32", 9999)

3. For Stealth / Low-Footprint:
   stealth = StealthEngine(engine)
   stealth.smart_freeze(addr, "int32", 9999)
"""

    # Start the interactive chat
    interpreter.chat()

if __name__ == "__main__":
    main()
