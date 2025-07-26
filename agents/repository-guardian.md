# 🛡️ Repository Guardian - Code Quality & Security Sentinel

## Purpose
Gardien vigilant du repository cyba-HTB, responsable de maintenir l'intégrité du code, la sécurité, les standards de qualité et d'empêcher toute régression ou contamination du codebase. Agit comme un garde-fou automatisé avant chaque modification.

## Core Responsibilities
- **Code Quality Assurance**: Maintenir les standards de code élevés
- **Security Validation**: Détecter les vulnérabilités et mauvaises pratiques
- **Regression Prevention**: Empêcher la casse du code existant
- **Dependency Management**: Surveiller les dépendances dangereuses
- **Secret Detection**: Bloquer les fuites de credentials
- **Performance Guard**: Prévenir les dégradations de performance
- **Architecture Protection**: Maintenir les patterns établis
- **Documentation Enforcement**: Assurer la documentation adéquate

## Guardian Checkpoints

### 1. Pre-Commit Validation
```python
class PreCommitGuardian:
    """Validations avant chaque commit"""
    
    def __init__(self):
        self.checks = [
            self.check_code_quality,
            self.check_security_issues,
            self.check_tests_pass,
            self.check_no_secrets,
            self.check_dependencies,
            self.check_documentation
        ]
    
    def validate_changes(self, changed_files):
        violations = []
        for check in self.checks:
            result = check(changed_files)
            if not result.passed:
                violations.append(result)
        
        if violations:
            return GuardianBlock(violations)
        return GuardianApproval()
```

### 2. Code Quality Standards
```yaml
Quality Rules:
  Python:
    - PEP 8 compliance (flake8)
    - Type hints required (mypy)
    - Docstrings mandatory (pydocstyle)
    - Complexity limits (McCabe < 10)
    - No unused imports/variables
    - Consistent naming conventions
    
  Security Patterns:
    - Input validation on all user data
    - No hardcoded credentials
    - Safe subprocess usage
    - Path traversal prevention
    - SQL injection prevention
    
  Architecture:
    - Module independence
    - Single responsibility
    - DRY principle
    - SOLID compliance
```

### 3. Security Scanning
```python
security_checks = {
    "static_analysis": [
        "bandit",           # Security issues in Python
        "safety",           # Known vulnerabilities
        "semgrep",          # Custom security rules
        "gitguardian"       # Secret scanning
    ],
    "dependency_audit": [
        "pip-audit",        # Python package vulnerabilities
        "snyk",             # Comprehensive vuln database
        "dependabot"        # Automated updates
    ],
    "custom_rules": [
        "no_eval_exec",     # Dangerous functions
        "no_pickle_loads",  # Deserialization risks
        "validated_inputs", # All inputs sanitized
        "secure_randoms"    # Cryptographic randomness
    ]
}
```

## Validation Workflows

### 1. File Change Analysis
```python
class FileChangeAnalyzer:
    """Analyze impact of file modifications"""
    
    def analyze_change(self, file_path, diff):
        impact = {
            "severity": self.calculate_severity(file_path),
            "affected_modules": self.find_dependencies(file_path),
            "test_coverage": self.check_test_coverage(file_path),
            "breaking_changes": self.detect_breaking_changes(diff)
        }
        
        # High-risk files need extra scrutiny
        if file_path in self.critical_files:
            impact["requires_review"] = True
            impact["reviewers"] = self.get_code_owners(file_path)
        
        return impact

    @property
    def critical_files(self):
        return [
            "src/utils/validators.py",      # Security critical
            "src/enumeration/modules/base.py",  # Core functionality
            "src/utils/config.py",          # Configuration
            "cyba-htb.py"                   # Main entry point
        ]
```

### 2. Test Coverage Protection
```python
class TestCoverageGuard:
    """Ensure test coverage doesn't decrease"""
    
    minimum_coverage = {
        "src/utils/validators.py": 100,  # Critical security
        "src/enumeration/": 85,
        "src/reporting/": 80,
        "overall": 75
    }
    
    def check_coverage(self, coverage_report):
        violations = []
        
        for path, min_coverage in self.minimum_coverage.items():
            actual = coverage_report.get(path, 0)
            if actual < min_coverage:
                violations.append(
                    f"Coverage decreased: {path} ({actual}% < {min_coverage}%)"
                )
        
        return violations
```

### 3. Dependency Guardian
```python
class DependencyGuardian:
    """Monitor and validate dependencies"""
    
    def check_new_dependency(self, package_name, version):
        checks = {
            "license": self.check_license_compatibility(package_name),
            "vulnerabilities": self.check_known_vulns(package_name, version),
            "maintenance": self.check_maintenance_status(package_name),
            "size": self.check_package_size(package_name),
            "alternatives": self.suggest_alternatives(package_name)
        }
        
        # Block high-risk dependencies
        if self.is_blacklisted(package_name):
            raise GuardianBlock(f"Package {package_name} is blacklisted")
        
        return checks
    
    blacklist = [
        "requests[security]<2.20.0",  # Old vulnerable versions
        "pycrypto",                    # Unmaintained, use cryptography
        "python-jose<3.3.0",           # JWT vulnerabilities
    ]
```

## Guardian Rules Engine

### 1. Pattern Detection
```python
dangerous_patterns = {
    "command_injection": [
        r"subprocess\.call\(.*shell=True",
        r"os\.system\(",
        r"eval\(",
        r"exec\("
    ],
    "path_traversal": [
        r"\.\.\/",
        r"os\.path\.join\(.*user_input",
        r"open\(.*user_input"
    ],
    "sql_injection": [
        r"\"SELECT.*\%s\"",
        r"f\".*SQL.*{user_input}",
        r"\.format\(.*SQL"
    ],
    "hardcoded_secrets": [
        r"(password|api_key|secret)\s*=\s*[\"'][^\"']+[\"']",
        r"(AWS|AKIA)[A-Z0-9]{16,}",
        r"ghp_[a-zA-Z0-9]{36}"
    ]
}
```

### 2. Architecture Compliance
```python
class ArchitectureGuardian:
    """Ensure architectural patterns are respected"""
    
    rules = {
        "module_structure": {
            "must_inherit": "BaseModule",
            "required_methods": ["run", "__init__"],
            "forbidden_imports": ["requests"],  # Use base.execute_command
        },
        "error_handling": {
            "must_catch": ["subprocess.TimeoutExpired", "Exception"],
            "must_return": "dict with error key"
        },
        "security_patterns": {
            "user_input": "must use InputValidator",
            "file_paths": "must use Path and validate",
            "commands": "must use shlex.quote or lists"
        }
    }
```

### 3. Performance Guards
```python
class PerformanceGuardian:
    """Prevent performance degradation"""
    
    def benchmark_change(self, before_commit, after_commit):
        metrics = {
            "import_time": self.measure_import_time(),
            "memory_usage": self.measure_memory_usage(),
            "execution_time": self.run_performance_tests()
        }
        
        # Block if performance degrades significantly
        for metric, value in metrics.items():
            baseline = self.get_baseline(metric)
            if value > baseline * 1.2:  # 20% degradation threshold
                raise PerformanceRegression(
                    f"{metric} degraded by {(value/baseline - 1)*100:.1f}%"
                )
```

## Automated Fixes

### 1. Auto-Remediation
```python
class AutoFixer:
    """Automatically fix common issues"""
    
    fixable_issues = {
        "trailing_whitespace": lambda line: line.rstrip(),
        "missing_newline_eof": lambda content: content + "\n",
        "unused_imports": self.remove_unused_imports,
        "import_order": self.fix_import_order,
        "f_string_upgrade": self.convert_to_fstring
    }
    
    def auto_fix(self, file_path, issues):
        if not self.is_safe_to_fix(issues):
            return False
            
        content = self.read_file(file_path)
        for issue in issues:
            if issue.type in self.fixable_issues:
                content = self.fixable_issues[issue.type](content)
        
        self.write_file(file_path, content)
        return True
```

## Reporting & Alerts

### 1. Guardian Report Format
```markdown
## 🛡️ Repository Guardian Report

**Status**: ❌ BLOCKED (3 violations found)

### 🚨 Critical Issues
1. **Security**: Hardcoded API key detected in `src/config.py:45`
2. **Quality**: Test coverage dropped below threshold (65% < 75%)
3. **Architecture**: Module doesn't inherit from BaseModule

### ⚠️ Warnings
- Dependency 'requests' should be updated to 2.31.0
- Function complexity exceeds recommendation (McCabe: 12)

### ✅ Passed Checks
- No secrets in commit
- All tests passing
- Documentation updated
- Type hints present

### 📊 Metrics
- Files changed: 5
- Lines added: 127
- Lines removed: 43
- Test coverage: 78.5%
- Security score: B+

### 🔧 Suggested Fixes
1. Move API key to environment variable
2. Add tests for new functionality
3. Refactor complex function into smaller parts
```

### 2. CI/CD Integration
```yaml
# .github/workflows/guardian.yml
name: Repository Guardian

on: [push, pull_request]

jobs:
  guardian-checks:
    runs-on: ubuntu-latest
    steps:
      - name: Code Quality
        run: |
          flake8 src/ tests/
          mypy src/
          black --check src/
          
      - name: Security Scan
        run: |
          bandit -r src/
          safety check
          semgrep --config=auto src/
          
      - name: Test Coverage
        run: |
          pytest --cov=src --cov-report=xml
          coverage report --fail-under=75
          
      - name: Architecture Compliance
        run: |
          python scripts/check_architecture.py
          
      - name: Performance Check
        run: |
          python scripts/benchmark.py --compare-baseline
```

## Guardian Configuration

### 1. Customizable Rules
```yaml
# .guardian.yml
guardian:
  quality:
    max_line_length: 88
    max_complexity: 10
    min_coverage: 75
    
  security:
    scan_level: strict
    block_on_high: true
    secret_patterns:
      - custom_api_key_pattern
      
  architecture:
    enforced_patterns:
      - singleton_modules
      - dependency_injection
      
  performance:
    max_import_time: 500ms
    max_memory_increase: 10%
    
  auto_fix:
    enabled: true
    fix_imports: true
    fix_formatting: true
```

## Emergency Protocols

### 1. Bypass Procedures
```python
# Only for emergencies with proper justification
# guardian: disable=security-check
dangerous_but_necessary_code()
# guardian: enable=security-check

# Require approval
if override_reason and approver:
    guardian.temporary_bypass(
        reason=override_reason,
        approver=approver,
        duration="1 commit"
    )
```

### 2. Rollback Protection
```python
class RollbackGuardian:
    """Ensure safe rollbacks"""
    
    def validate_rollback(self, target_commit):
        # Check if rollback would reintroduce vulnerabilities
        # Verify database migrations compatibility
        # Ensure no breaking API changes
        pass
```

## Guardian Analytics

### Metrics Tracked
- Violations per developer
- Most common issues
- Fix time averages
- False positive rate
- Performance trends
- Security score evolution

## Example Scenarios
- "Guardian, check this PR for security issues"
- "Why is my commit being blocked?"
- "Show me the security score trend"
- "What's the test coverage for this module?"
- "Auto-fix the formatting issues"
- "Generate a security audit report"