# 🛡️ Repository Guardian Security Report

## ❌ BLOCKED - 7 Security Violations Found


### 📄 test_guardian_live.py

**🚨 Critical Issues:**
- Line 17: command_injection - `os.system(`
- Line 38: command_injection - `eval(`
- Line 40: command_injection - `eval(`
- Line 23: hardcoded_secrets - `API_KEY = "HTB{this_is_a_flag_12345}"`
- Line 23: hardcoded_secrets - `HTB{this_is_a_flag_12345}`
- Line 24: hardcoded_secrets - `AKIAIOSFODNN7EXAMPLE`
- Line 35: sql_injection - `f"SELECT * FROM users WHERE id = {`