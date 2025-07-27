#!/usr/bin/env python3
"""
Test en direct du Repository Guardian
Démontre comment le Guardian bloque le code problématique
"""

import os
import sys

def test_vulnerable_code():
    """Code intentionnellement vulnérable pour tester le Guardian"""
    
    print("🧪 Test 1: Command Injection")
    try:
        # ❌ GUARDIAN DEVRAIT BLOQUER: os.system avec user input
        target = input("Enter target: ")
        os.system(f"nmap {target}")  # Vulnérable!
    except Exception as e:
        print(f"✅ Guardian blocked: {e}")
    
    print("\n🧪 Test 2: Hardcoded Secrets")
    # ❌ GUARDIAN DEVRAIT BLOQUER: API key en dur
    API_KEY = "HTB{this_is_a_flag_12345}"  # Secret!
    AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # AWS Key!
    
    print("\n🧪 Test 3: Path Traversal")
    # ❌ GUARDIAN DEVRAIT BLOQUER: Path traversal
    user_file = input("File to read: ")
    with open(f"/etc/{user_file}", 'r') as f:  # Dangereux!
        content = f.read()
    
    print("\n🧪 Test 4: SQL Injection")
    # ❌ GUARDIAN DEVRAIT BLOQUER: SQL injection
    user_id = input("User ID: ")
    query = f"SELECT * FROM users WHERE id = {user_id}"  # Injectable!
    
    print("\n🧪 Test 5: Eval Usage")
    # ❌ GUARDIAN DEVRAIT BLOQUER: eval() dangereux
    user_code = input("Enter expression: ")
    result = eval(user_code)  # Code execution!

def test_good_practices():
    """Code qui suit les bonnes pratiques"""
    
    print("\n✅ Code Sécurisé:")
    
    # ✅ Utilisation correcte de subprocess
    import subprocess
    import shlex
    from pathlib import Path
    
    # Input validation
    from src.utils.validators import InputValidator
    validator = InputValidator()
    
    target = "127.0.0.1"
    if validator.validate_ip(target):
        # Safe subprocess usage
        cmd = ["nmap", "-sV", target]
        result = subprocess.run(cmd, capture_output=True, text=True)
    
    # ✅ Secrets depuis environnement
    api_key = os.environ.get("CYBA_API_KEY")
    
    # ✅ Path validation
    safe_path = Path("/tmp/cyba-inspector") / "results.txt"
    if safe_path.exists() and safe_path.is_file():
        with open(safe_path, 'r') as f:
            content = f.read()

if __name__ == "__main__":
    print("🛡️ Repository Guardian Live Test\n")
    
    print("⚠️  ATTENTION: Ce code contient des vulnérabilités intentionnelles")
    print("Le Guardian devrait bloquer ce commit!\n")
    
    # Ces tests ne devraient jamais passer en production
    # Le Guardian doit les détecter et bloquer
    
    test_vulnerable_code()
    test_good_practices()