
import sys
import os
from pathlib import Path

# Add backend to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.ml.service import analyze_text_ml
from app.ml.loader import load_all_models

print("Loading models...")
load_all_models()
print("Models loaded.")

test_content = "Ceci est un test urgent pour gagner un prix amazon."
print(f"Analyzing: {test_content}")
result = analyze_text_ml(test_content)
print("Analysis Result:")
print(result)
