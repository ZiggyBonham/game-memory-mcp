"""Launcher for Open Interpreter with Dolphin 3 and the Game Memory Suite.

Routes requests through Ollama's OpenAI-compatible API endpoint to bypass
Open Interpreter's internal Ollama tag-matching bug, and preloads the GameTrainer suite
with explicit Cheat Engine scanning rules for the LLM.
"""
import sys
import os

# Add game-memory server directory to Python path
SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
if SERVER_DIR not in sys.path:
    sys.path.insert(0, SERVER_DIR)

from interpreter import interpreter

def main():
    print("=" * 65)
    print("  Initializing Open Interpreter with Dolphin 3 (Ollama)")
    print("  Game Memory Editing Suite & GameTrainer: Ready")
    print("=" * 65)

    # Configure Open Interpreter to connect via Ollama's OpenAI-compatible endpoint
    interpreter.llm.model = "openai/dolphin3:latest"
    interpreter.llm.api_base = "http://localhost:11434/v1"
    interpreter.llm.api_key = "ollama"
    interpreter.llm.temperature = 0.1  # Low temperature for exact memory and parameter handling
    interpreter.llm.context_window = 8192

    # Detailed system prompt teaching Dolphin 3 the Cheat Engine state machine
    interpreter.system_message = f"""
You are an expert Game Memory Reverse Engineer and Game Hacker pair-programming assistant.
You have access to a specialized high-level Python game trainer located at:
{SERVER_DIR}

ALWAYS USE `GameTrainer` from `trainer.py` to inspect and modify game memory.
Maintain a global instance `trainer` across conversation turns.

### HOW CHEAT ENGINE / MEMORY EDITING WORKS (CRITICAL RULES):
1. **Never write to memory after the first scan if there are multiple matches!**
   An initial scan typically finds 10,000 to 50,000 matches. Writing to a random address from this list will crash the game or corrupt unrelated memory!
2. **The 3-Step Scan & Filter Workflow**:
   - **Step 1 (First Scan)**: Scan for the exact value currently seen in the game (e.g. Damage = 3.50, Gold = 50).
     ```python
     import sys
     sys.path.insert(0, r"{SERVER_DIR}")
     from trainer import GameTrainer

     # Create or reuse trainer
     if 'trainer' not in globals():
         trainer = GameTrainer("isaac-ng.exe")
     print(trainer.scan_stat("damage", 3.50, "float"))
     ```
     If the scan returns many matches, instruct the user: "Found X matches. Please change this value in-game (pick up an item, take damage, or spend coins) and tell me the new number."

   - **Step 2 (Next Scan / Filter)**: When the user says "New value: 4.08" or "It is now 20":
     ```python
     print(trainer.filter_stat("damage", 4.08))
     ```
     Repeat this step until 1 unique address is resolved.

   - **Step 3 (Modify or Freeze)**: Only once the address is found, modify or freeze it:
     ```python
     print(trainer.set_stat("damage", 100.0))
     # Or for God Mode / Infinite Ammo:
     print(trainer.freeze_stat("damage", 100.0))
     ```

3. **Data Type Guidelines**:
   - Health, Gold, Ammo, Coins, Bombs, Keys: usually "int32"
   - Damage, Speed, Range, Tears, Coordinates: usually "float"
"""

    # Start the interactive chat
    interpreter.chat()

if __name__ == "__main__":
    main()
