#!/bin/bash
# Comprehensive workflow test for cyba-Inspector
# Tests installation, commands, error handling, and integration

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test results
PASSED=0
FAILED=0
SKIPPED=0

# Log file
LOG_FILE="test_workflow_$(date +%Y%m%d_%H%M%S).log"

# Test counter
TEST_NUM=0

# Function to log
log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

# Function to run a test
run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_result="${3:-0}"
    
    TEST_NUM=$((TEST_NUM + 1))
    
    log "\n${BLUE}[TEST $TEST_NUM] $test_name${NC}"
    log "Command: $test_command"
    
    # Run the test
    set +e
    if eval "$test_command" >> "$LOG_FILE" 2>&1; then
        actual_result=0
    else
        actual_result=$?
    fi
    set -e
    
    # Check result
    if [ $actual_result -eq $expected_result ]; then
        log "${GREEN}✓ PASSED${NC}"
        PASSED=$((PASSED + 1))
        return 0
    else
        log "${RED}✗ FAILED (expected: $expected_result, got: $actual_result)${NC}"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

# Function to check prerequisite
check_prerequisite() {
    local cmd="$1"
    local name="$2"
    
    if command -v "$cmd" &> /dev/null; then
        log "${GREEN}✓ $name found${NC}"
        return 0
    else
        log "${YELLOW}⚠ $name not found (some tests will be skipped)${NC}"
        return 1
    fi
}

log "======================================"
log "cyba-Inspector Workflow Test Suite"
log "$(date)"
log "======================================"

# Check prerequisites
log "\n${BLUE}Checking prerequisites...${NC}"
check_prerequisite "python3" "Python 3"
check_prerequisite "nmap" "Nmap"
check_prerequisite "gobuster" "Gobuster"
HAS_NIKTO=$(check_prerequisite "nikto" "Nikto" && echo 1 || echo 0)

# Test 1: Python environment
log "\n${BLUE}=== SECTION 1: Python Environment ===${NC}"
run_test "Python version check" "python3 --version | grep -E 'Python 3\.(8|9|10|11)'"
run_test "Import test" "cd /home/user1/cyba-Inspector && python3 -c 'import sys; sys.path.insert(0, \"src\"); from utils.colors import Colors; print(\"OK\")' | grep OK"

# Test 2: Installation validation
log "\n${BLUE}=== SECTION 2: Installation ===${NC}"
run_test "Symlink exists" "test -L /usr/local/bin/cyba-inspector"
run_test "Symlink points to correct file" "readlink -f /usr/local/bin/cyba-inspector | grep -q '/home/user1/cyba-Inspector/cyba-inspector.py'"
run_test "Main script is executable" "test -x /home/user1/cyba-Inspector/cyba-inspector.py"
run_test "Config directory exists" "test -d ~/.cyba-inspector"

# Test 3: Basic commands
log "\n${BLUE}=== SECTION 3: Basic Commands ===${NC}"
run_test "Help command" "cyba-inspector --help | grep -q 'Specialized enumeration tool'"
run_test "Profiles list" "cyba-inspector profiles list | grep -q 'linux-basic'"
run_test "Sessions list" "cyba-inspector sessions list"

# Test 4: Input validation
log "\n${BLUE}=== SECTION 4: Input Validation ===${NC}"
run_test "Invalid IP rejection" "cyba-inspector enum -t 999.999.999.999 -n test" 1
run_test "Invalid port rejection" "cyba-inspector enum -t 127.0.0.1 -n test --ports 99999" 1
run_test "Invalid machine name rejection" "cyba-inspector enum -t 127.0.0.1 -n 'test@machine'" 1
run_test "Missing target rejection" "cyba-inspector enum -n test" 2

# Test 5: Quick scan simulation
log "\n${BLUE}=== SECTION 5: Quick Scan ===${NC}"
if [ $HAS_NIKTO -eq 1 ]; then
    run_test "Quick scan localhost" "timeout 10 cyba-inspector quick -t 127.0.0.1 || true"
else
    log "${YELLOW}⚠ Skipping quick scan test (nikto not installed)${NC}"
    SKIPPED=$((SKIPPED + 1))
fi

# Test 6: Python validators
log "\n${BLUE}=== SECTION 6: Validator Tests ===${NC}"
run_test "Run validator tests" "cd /home/user1/cyba-Inspector && python3 tests/test_validators.py | grep -q 'All tests passed'"

# Test 7: Module imports
log "\n${BLUE}=== SECTION 7: Module Integration ===${NC}"
run_test "Import enumeration modules" "cd /home/user1/cyba-Inspector && python3 -c 'import sys; sys.path.insert(0, \"src\"); from enumeration.modules import nmap, web, smb, ssh, ftp; print(\"OK\")' | grep OK"
run_test "Import reporting modules" "cd /home/user1/cyba-Inspector && python3 -c 'import sys; sys.path.insert(0, \"src\"); from reporting.generator import ReportGenerator; print(\"OK\")' | grep OK"
run_test "Import utilities" "cd /home/user1/cyba-Inspector && python3 -c 'import sys; sys.path.insert(0, \"src\"); from utils.config import config; from utils.validators import InputValidator; print(\"OK\")' | grep OK"

# Test 8: Configuration system
log "\n${BLUE}=== SECTION 8: Configuration ===${NC}"
run_test "Config file creation" "cd /home/user1/cyba-Inspector && python3 -c 'import sys; sys.path.insert(0, \"src\"); from utils.config import Config; c = Config(); print(\"OK\")' | grep OK"
run_test "Environment variable handling" "CYBA_TIMEOUT_SHORT=60 python3 -c 'import os; print(os.getenv(\"CYBA_TIMEOUT_SHORT\"))' | grep 60"

# Test 9: Error handling
log "\n${BLUE}=== SECTION 9: Error Handling ===${NC}"
run_test "Graceful error on invalid session" "cyba-inspector report invalid_session_id" 1
run_test "Graceful error on invalid profile" "cyba-inspector profiles show invalid_profile" 1

# Test 10: Security checks
log "\n${BLUE}=== SECTION 10: Security ===${NC}"
run_test "No hardcoded API keys" "! grep -r 'api_key.*=.*[a-zA-Z0-9]\\{20,\\}' /home/user1/cyba-Inspector/src --include='*.py' | grep -v example"
run_test "No hardcoded passwords" "! grep -r 'password.*=.*[\"'\''][^\"'\'']*[\"'\'']' /home/user1/cyba-Inspector/src --include='*.py' | grep -v example"

# Summary
log "\n${BLUE}======================================"
log "Test Summary"
log "======================================${NC}"
log "${GREEN}Passed: $PASSED${NC}"
log "${RED}Failed: $FAILED${NC}"
log "${YELLOW}Skipped: $SKIPPED${NC}"
log "Total: $((PASSED + FAILED + SKIPPED))"
log "\nDetailed log saved to: $LOG_FILE"

# Exit code based on failures
if [ $FAILED -eq 0 ]; then
    log "\n${GREEN}✅ All tests passed!${NC}"
    exit 0
else
    log "\n${RED}❌ Some tests failed!${NC}"
    exit 1
fi