#!/usr/bin/env python3
"""
Repository Guardian - Analyse statique de sécurité
Vérifie le code pour détecter les vulnérabilités
"""

import ast
import re
import sys
from pathlib import Path
from typing import List, Dict, Tuple

class SecurityGuardian:
    def __init__(self):
        self.violations = []
        self.warnings = []
        
        # Patterns de sécurité à détecter
        self.dangerous_patterns = {
            'command_injection': [
                r'os\.system\s*\(',
                r'subprocess\.call\s*\(.*shell\s*=\s*True',
                r'eval\s*\(',
                r'exec\s*\('
            ],
            'hardcoded_secrets': [
                r'(password|api_key|secret|token)\s*=\s*["\'][^"\']+["\']',
                r'HTB\{[^}]+\}',
                r'(AWS|AKIA)[A-Z0-9]{16,}',
                r'sk-[a-zA-Z0-9]{48}',
                r'ghp_[a-zA-Z0-9]{36}'
            ],
            'path_traversal': [
                r'\.\./',
                r'open\s*\([^,)]*\+[^,)]*\)',
                r'Path\s*\([^)]*\+[^)]*\)'
            ],
            'sql_injection': [
                r'["\']SELECT.*%s["\']',
                r'f["\'].*SELECT.*\{',
                r'\.format\(.*SELECT'
            ]
        }
        
    def check_file(self, filepath: Path) -> Tuple[List[Dict], List[Dict]]:
        """Analyse un fichier Python pour détecter les problèmes de sécurité"""
        self.violations = []
        self.warnings = []
        
        try:
            content = filepath.read_text()
            
            # Check patterns dangereux
            for category, patterns in self.dangerous_patterns.items():
                for pattern in patterns:
                    matches = list(re.finditer(pattern, content, re.IGNORECASE))
                    for match in matches:
                        line_no = content[:match.start()].count('\n') + 1
                        self.violations.append({
                            'file': str(filepath),
                            'line': line_no,
                            'category': category,
                            'pattern': pattern,
                            'code': match.group(0)
                        })
            
            # Analyse AST pour des checks plus avancés
            try:
                tree = ast.parse(content)
                self.visit_ast(tree, filepath)
            except SyntaxError:
                self.warnings.append({
                    'file': str(filepath),
                    'message': 'Syntax error - cannot parse AST'
                })
                
        except Exception as e:
            self.warnings.append({
                'file': str(filepath),
                'message': f'Error reading file: {e}'
            })
            
        return self.violations, self.warnings
    
    def visit_ast(self, tree, filepath):
        """Analyse AST pour détecter des patterns complexes"""
        for node in ast.walk(tree):
            # Détection d'imports dangereux
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in ['pickle', 'marshal']:
                        self.warnings.append({
                            'file': str(filepath),
                            'line': node.lineno,
                            'message': f'Dangerous import: {alias.name}'
                        })
    
    def generate_report(self, files_checked: List[Path]) -> str:
        """Génère un rapport détaillé"""
        report = ["# 🛡️ Repository Guardian Security Report\n"]
        
        total_violations = sum(len(v) for v, _ in [self.check_file(f) for f in files_checked])
        
        if total_violations > 0:
            report.append(f"## ❌ BLOCKED - {total_violations} Security Violations Found\n")
        else:
            report.append("## ✅ PASSED - No Security Issues Found\n")
        
        for filepath in files_checked:
            violations, warnings = self.check_file(filepath)
            
            if violations or warnings:
                report.append(f"\n### 📄 {filepath.name}")
                
                if violations:
                    report.append("\n**🚨 Critical Issues:**")
                    for v in violations:
                        report.append(f"- Line {v['line']}: {v['category']} - `{v['code']}`")
                
                if warnings:
                    report.append("\n**⚠️ Warnings:**")
                    for w in warnings:
                        report.append(f"- {w.get('line', 'N/A')}: {w['message']}")
        
        return "\n".join(report)

def main():
    """Point d'entrée principal"""
    if len(sys.argv) < 2:
        print("Usage: python guardian_check.py <file_or_directory>")
        sys.exit(1)
    
    target = Path(sys.argv[1])
    guardian = SecurityGuardian()
    
    if target.is_file():
        files_to_check = [target]
    elif target.is_dir():
        files_to_check = list(target.rglob("*.py"))
    else:
        print(f"Error: {target} not found")
        sys.exit(1)
    
    print("🛡️ Repository Guardian - Security Analysis\n")
    
    total_violations = 0
    for filepath in files_to_check:
        violations, warnings = guardian.check_file(filepath)
        if violations:
            print(f"\n❌ {filepath}:")
            for v in violations:
                print(f"   Line {v['line']}: {v['category']} - {v['code']}")
            total_violations += len(violations)
    
    if total_violations > 0:
        print(f"\n🚨 Total violations: {total_violations}")
        print("⛔ Commit would be BLOCKED by Guardian")
        
        # Générer rapport complet
        report = guardian.generate_report(files_to_check)
        report_path = Path("guardian_report.md")
        report_path.write_text(report)
        print(f"\n📊 Full report saved to: {report_path}")
        
        sys.exit(1)
    else:
        print("\n✅ All checks passed! Code is clean.")
        sys.exit(0)

if __name__ == "__main__":
    main()